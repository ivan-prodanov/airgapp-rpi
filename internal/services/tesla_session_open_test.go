package services

// Open's ordering guarantees, with the BLE radio replaced by an injected acquire.
//
// The behaviour pinned here is "newest open wins, and nobody hangs". On
// 2026-11-07 a phone Open that arrived while another open was mid-scan had
// nothing registered to preempt, then blocked on the adapter lock with no way to
// give up: nine POSTs took 29s or more that day, the worst 1m51s.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type openResult struct {
	sess *BLESession
	err  error
}

func openAsync(s *BLESessionService, ctx context.Context, owner int64) <-chan openResult {
	ch := make(chan openResult, 1)
	go func() {
		sess, err := s.Open(ctx, "VIN", owner)
		ch <- openResult{sess, err}
	}()
	return ch
}

func await(t *testing.T, ch <-chan openResult, what string) openResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return", what)
		return openResult{}
	}
}

func newOpenTestService(acquire func(ctx context.Context, vin string) (bleConn, func(), error)) *BLESessionService {
	s := NewBLESessionService(nil)
	s.acquire = acquire
	return s
}

func TestOpenPreemptsARegisteredSession(t *testing.T) {
	var released atomic.Int32
	s := newOpenTestService(func(ctx context.Context, vin string) (bleConn, func(), error) {
		return newFakeBLEConn(), func() { released.Add(1) }, nil
	})

	first, err := s.Open(context.Background(), "VIN", 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Open(context.Background(), "VIN", 1)
	if err != nil {
		t.Fatal(err)
	}

	if released.Load() != 1 {
		t.Fatalf("released = %d, want 1", released.Load())
	}
	if _, err := s.get(first.ID); !errors.Is(err, ErrBLESessionNotFound) {
		t.Fatalf("first session still registered: %v", err)
	}
	if id, _ := s.CurrentSession(); id != second.ID {
		t.Fatalf("current session = %q, want the newest %q", id, second.ID)
	}
}

// A newer Open must not wait out an older one that is still scanning.
func TestNewerOpenCancelsOneStillAcquiring(t *testing.T) {
	var calls atomic.Int32
	s := newOpenTestService(func(ctx context.Context, vin string) (bleConn, func(), error) {
		if calls.Add(1) == 1 {
			<-ctx.Done() // a scan that is not going to find the car any time soon
			return nil, nil, ctx.Err()
		}
		return newFakeBLEConn(), func() {}, nil
	})

	first := openAsync(s, context.Background(), 1)
	waitFor(t, 2*time.Second, "the first open to start", func() bool { return calls.Load() == 1 })

	second, err := s.Open(context.Background(), "VIN", 1)
	if err != nil {
		t.Fatalf("newest open must win: %v", err)
	}

	if r := await(t, first, "the superseded open"); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("superseded open err = %v, want context.Canceled", r.err)
	}
	if id, _ := s.CurrentSession(); id != second.ID {
		t.Fatalf("current session = %q, want %q", id, second.ID)
	}
}

// The other half of that race: the older open has already got the radio when the
// newer one arrives. If it registered anyway, the newer open would have nothing
// to preempt yet and would wait behind a session nobody wants.
func TestOpenSupersededAfterAcquiringReleasesInsteadOfRegistering(t *testing.T) {
	var lock bleLock
	var calls atomic.Int32
	firstHolds := make(chan struct{})
	firstMayFinish := make(chan struct{})
	s := newOpenTestService(func(ctx context.Context, vin string) (bleConn, func(), error) {
		if err := lock.Lock(ctx); err != nil {
			return nil, nil, err
		}
		if calls.Add(1) == 1 {
			close(firstHolds)
			<-firstMayFinish // the connect completes regardless of ctx
		}
		return newFakeBLEConn(), lock.Unlock, nil
	})

	first := openAsync(s, context.Background(), 1)
	<-firstHolds
	second := openAsync(s, context.Background(), 1)
	time.Sleep(20 * time.Millisecond) // let the second open reach the lock
	close(firstMayFinish)

	if r := await(t, first, "the superseded open"); !errors.Is(r.err, ErrBLEOpenSuperseded) {
		t.Fatalf("superseded open err = %v, want ErrBLEOpenSuperseded", r.err)
	}
	r := await(t, second, "the newest open")
	if r.err != nil {
		t.Fatalf("newest open: %v", r.err)
	}
	if id, _ := s.CurrentSession(); id != r.sess.ID {
		t.Fatalf("current session = %q, want %q", id, r.sess.ID)
	}
}

// Something unregistered holds the adapter (enrolment does): Open cannot preempt
// it, so the caller's deadline has to be able to end the wait.
func TestOpenWaitingOnTheAdapterEndsWithItsContext(t *testing.T) {
	var lock bleLock
	if err := lock.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	s := newOpenTestService(func(ctx context.Context, vin string) (bleConn, func(), error) {
		if err := lock.Lock(ctx); err != nil {
			return nil, nil, err
		}
		return newFakeBLEConn(), lock.Unlock, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	r := await(t, openAsync(s, ctx, 1), "the open")

	if !errors.Is(r.err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", r.err)
	}
}

func TestCloseForTokenClosesThatTokensSession(t *testing.T) {
	var released atomic.Int32
	s := newOpenTestService(func(ctx context.Context, vin string) (bleConn, func(), error) {
		return newFakeBLEConn(), func() { released.Add(1) }, nil
	})
	sess, err := s.Open(context.Background(), "VIN", 7)
	if err != nil {
		t.Fatal(err)
	}
	_, ch, err := s.Subscribe(sess.ID)
	if err != nil {
		t.Fatal(err)
	}

	if n := s.CloseForToken(7); n != 1 {
		t.Fatalf("closed = %d, want 1", n)
	}

	if released.Load() != 1 {
		t.Fatalf("released = %d, want 1 — the radio must be free", released.Load())
	}
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("unexpected frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the event stream must end with the session")
	}
}

func TestCloseForTokenLeavesOtherTokensAlone(t *testing.T) {
	s := newOpenTestService(func(ctx context.Context, vin string) (bleConn, func(), error) {
		return newFakeBLEConn(), func() {}, nil
	})
	sess, err := s.Open(context.Background(), "VIN", 7)
	if err != nil {
		t.Fatal(err)
	}

	if n := s.CloseForToken(8); n != 0 {
		t.Fatalf("closed = %d, want 0", n)
	}
	if n := s.CloseForToken(0); n != 0 {
		t.Fatalf("closed = %d for no token, want 0", n)
	}
	if id, _ := s.CurrentSession(); id != sess.ID {
		t.Fatalf("session was closed by another token's removal")
	}
}

// Removed while its open is still in flight: it must not come back to life as a
// session that outlives the token.
func TestCloseForTokenCancelsItsOpenInFlight(t *testing.T) {
	var started atomic.Bool
	s := newOpenTestService(func(ctx context.Context, vin string) (bleConn, func(), error) {
		started.Store(true)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})

	opening := openAsync(s, context.Background(), 7)
	waitFor(t, 2*time.Second, "the open to start", started.Load)

	s.CloseForToken(7)

	if r := await(t, opening, "the open"); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", r.err)
	}
}

func TestCloseForTokenLeavesAnotherTokensOpenInFlight(t *testing.T) {
	var started atomic.Bool
	finish := make(chan struct{})
	s := newOpenTestService(func(ctx context.Context, vin string) (bleConn, func(), error) {
		started.Store(true)
		select {
		case <-finish:
			return newFakeBLEConn(), func() {}, nil
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	})

	opening := openAsync(s, context.Background(), 7)
	waitFor(t, 2*time.Second, "the open to start", started.Load)

	s.CloseForToken(8)
	close(finish)

	if r := await(t, opening, "the open"); r.err != nil {
		t.Fatalf("another token's removal must not affect this open: %v", r.err)
	}
}

func TestBLELockWaiterGivesUpWithItsContext(t *testing.T) {
	var lock bleLock
	if err := lock.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := lock.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}

	lock.Unlock()
	if err := lock.Lock(context.Background()); err != nil {
		t.Fatalf("a waiter that gave up must not have taken the lock: %v", err)
	}
}

func TestBLELockAlreadyCancelledContextDoesNotAcquire(t *testing.T) {
	var lock bleLock
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := lock.Lock(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if err := lock.Lock(context.Background()); err != nil {
		t.Fatalf("the lock must still be free: %v", err)
	}
}

func TestBLELockSerialises(t *testing.T) {
	var lock bleLock
	var inside, overlaps atomic.Int32
	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			if err := lock.Lock(context.Background()); err != nil {
				t.Error(err)
				return
			}
			if inside.Add(1) != 1 {
				overlaps.Add(1)
			}
			time.Sleep(time.Millisecond)
			inside.Add(-1)
			lock.Unlock()
		}()
	}
	for range 8 {
		<-done
	}
	if overlaps.Load() != 0 {
		t.Fatalf("%d overlapping holders", overlaps.Load())
	}
}
