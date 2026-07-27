package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
	"google.golang.org/protobuf/proto"
)

type fakeSessionSource struct {
	mu      sync.Mutex
	id      string
	ch      chan []byte
	openErr error
	subErr  error
	opens   int
	subbed  int
	unsubbd int
}

func (f *fakeSessionSource) CurrentSession() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.id == "" {
		return "", false
	}
	return f.id, true
}

func (f *fakeSessionSource) Open(ctx context.Context, vin string) (*BLESession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	if f.openErr != nil {
		return nil, f.openErr
	}
	f.id = "fake-session"
	return &BLESession{ID: f.id, VIN: vin}, nil
}

func (f *fakeSessionSource) Subscribe(id string) (int, <-chan []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.subErr != nil {
		return 0, nil, f.subErr
	}
	if id != f.id {
		return 0, nil, ErrBLESessionNotFound
	}
	f.subbed++
	f.ch = make(chan []byte, 8)
	return 1, f.ch, nil
}

func (f *fakeSessionSource) Unsubscribe(id string, subID int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unsubbd++
}

func (f *fakeSessionSource) counts() (opens, subbed, unsubbd int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens, f.subbed, f.unsubbd
}

// frames hands the test the channel the service is pumping, so a test can feed
// it real frames and close it to simulate the link dropping.
func (f *fakeSessionSource) frames() chan []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ch
}

// activityFrame is a car-initiated VCSEC frame that is NOT a status — the shape
// of the ~1 Hz approach challenge. It carries no lock state, only an activity
// lease.
func activityFrame(t *testing.T) []byte {
	t.Helper()
	inner, err := proto.Marshal(&vcsec.FromVCSECMessage{
		SubMessage: &vcsec.FromVCSECMessage_CommandStatus{
			CommandStatus: &vcsec.CommandStatus{},
		},
	})
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	outer, err := proto.Marshal(&universal.RoutableMessage{
		FromDestination: &universal.Destination{
			SubDestination: &universal.Destination_Domain{Domain: universal.Domain_DOMAIN_VEHICLE_SECURITY},
		},
		Payload: &universal.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: inner},
	})
	if err != nil {
		t.Fatalf("marshal outer: %v", err)
	}
	return outer
}

func lockedEmptyFrame(t *testing.T) []byte {
	t.Helper()
	return statusFrame(t,
		vcsec.VehicleLockState_E_VEHICLELOCKSTATE_LOCKED,
		vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT)
}

// waitFor polls cond until it holds or the deadline passes. Must be called from
// the test goroutine (it calls t.Fatalf).
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", d, what)
}

// mustReturnWithin fails instead of hanging the whole suite when a lifecycle
// call regresses into a block.
func mustReturnWithin(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s blocked for %v", what, d)
	}
}

// recorder collects enforcer calls from whichever goroutine settled.
type recorder struct {
	mu    sync.Mutex
	calls []bool
}

func (r *recorder) fn(up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, up)
}

func (r *recorder) snapshot() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.calls...)
}

func (r *recorder) last() (bool, bool) {
	c := r.snapshot()
	if len(c) == 0 {
		return false, false
	}
	return c[len(c)-1], true
}

// Ingest is the seam the goroutine uses, so the state machine is testable
// without running the supervisor at all.
func TestIngestLockedAndEmptyWantsAPDown(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	s.Ingest(lockedEmptyFrame(t), now)
	st := s.Status()
	if !st.HaveStatus || !st.Locked || st.Present {
		t.Fatalf("status = %+v", st)
	}
	if st.APShouldBeUp {
		t.Error("locked + empty must want the AP down")
	}
}

// An undecodable frame must be INERT — not merely "leaves a fail-open service
// fail-open", which an empty Ingest would also satisfy. Establish a down
// verdict first, then prove the garbage neither flips it nor re-fires the
// actuator.
func TestIngestGarbageLeavesTheVerdictUntouched(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	var rec recorder
	s.SetEnforcer(rec.fn)
	s.Ingest(lockedEmptyFrame(t), now)
	if s.Status().APShouldBeUp {
		t.Fatal("precondition: locked + empty should want the AP down")
	}
	before := len(rec.snapshot())

	s.Ingest([]byte{0xde, 0xad, 0xbe, 0xef}, now.Add(time.Second))

	if s.Status().APShouldBeUp {
		t.Error("an undecodable frame must not move the verdict")
	}
	if got := len(rec.snapshot()); got != before {
		t.Errorf("enforcer calls = %d, want %d — garbage must not re-fire the actuator", got, before)
	}
}

func TestEnforcerCalledOnlyOnTransition(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	var rec recorder
	// Installing the enforcer asserts the CURRENT verdict immediately (the
	// gate is empty, so: up). That is the first call.
	s.SetEnforcer(rec.fn)

	locked := lockedEmptyFrame(t)
	s.Ingest(locked, now)
	s.Ingest(locked, now.Add(time.Second)) // same verdict — must not re-fire
	s.Ingest(statusFrame(t,
		vcsec.VehicleLockState_E_VEHICLELOCKSTATE_UNLOCKED,
		vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT), now.Add(2*time.Second))

	calls := rec.snapshot()
	want := []bool{true, false, true}
	if len(calls) != len(want) {
		t.Fatalf("enforcer calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("enforcer calls = %v, want %v", calls, want)
		}
	}
}

// The actuator shells out to systemctl. If it ever ran with mu held it would
// block every Status() and Ingest() for the duration — and an enforcer that
// reads back the state it is enforcing would deadlock outright. This enforcer
// calls Status(), which takes mu (NOT applyMu), so it pins exactly that
// property: a refactor that settles-and-applies under mu hangs here.
func TestEnforcerRunsWithoutTheStateLockHeld(t *testing.T) {
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	now := time.Unix(1700000000, 0)
	mustReturnWithin(t, 2*time.Second, "settle with a Status()-calling enforcer", func() {
		s.SetEnforcer(func(up bool) { _ = s.Status() }) // fires once, immediately
		s.Ingest(lockedEmptyFrame(t), now)              // flips the verdict, fires again
	})
}

func TestNilEnforcerIsSafe(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	// No SetEnforcer — this is Phase 1. Must not panic.
	s.Ingest(lockedEmptyFrame(t), now)
}

func TestReportExternalDrivesTheSameState(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	s.ReportExternal(true, false, now)
	if s.Status().APShouldBeUp {
		t.Fatal("an external locked+empty report must want the AP down")
	}
}

// Losing the session must fail OPEN, discarding the stale verdict — and it must
// do so through the REAL teardown wiring (channel close → pump exit → deferred
// reset), not by calling the unexported reset directly.
func TestSessionLossFailsOpen(t *testing.T) {
	f := &fakeSessionSource{}
	s := NewLockWatchService(f, "VIN0")
	// Long enough that the supervisor's re-attach cannot race the assertions.
	s.retryDelay = 5 * time.Second
	s.Start()
	defer s.Stop()

	waitFor(t, 2*time.Second, "the first subscription", func() bool {
		_, subbed, _ := f.counts()
		return subbed >= 1
	})
	ch := f.frames()
	ch <- lockedEmptyFrame(t)
	waitFor(t, 2*time.Second, "the down verdict", func() bool { return !s.Status().APShouldBeUp })

	close(ch) // the link drops

	waitFor(t, 2*time.Second, "fail-open after the link drops", func() bool {
		st := s.Status()
		return st.SessionID == "" && st.APShouldBeUp
	})
	if _, _, unsubbd := f.counts(); unsubbd < 1 {
		t.Error("tearing down the pump must unsubscribe")
	}
}

// The supervisor opens a session when none exists, and subscribes to it.
func TestSupervisorOpensAndSubscribes(t *testing.T) {
	f := &fakeSessionSource{}
	s := NewLockWatchService(f, "VIN0")
	s.retryDelay = 5 * time.Millisecond
	s.Start()
	defer s.Stop()

	waitFor(t, 2*time.Second, "the supervisor to open + subscribe", func() bool {
		opens, subbed, _ := f.counts()
		return opens >= 1 && subbed >= 1
	})
}

// The structural constraint the whole design rests on: when a session is
// already live the watcher ATTACHES to it and never opens one of its own.
// Open preempts, so a watcher-owned session would force-close every phone
// session and spend its life reconnecting.
func TestSupervisorNeverOwnsASession(t *testing.T) {
	f := &fakeSessionSource{id: "phone-session"}
	s := NewLockWatchService(f, "VIN0")
	s.retryDelay = 5 * time.Millisecond
	s.Start()
	defer s.Stop()

	waitFor(t, 2*time.Second, "the watcher to attach", func() bool {
		_, subbed, _ := f.counts()
		return subbed >= 1
	})
	if opens, _, _ := f.counts(); opens != 0 {
		t.Fatalf("opens = %d, want 0 — the watcher must never open its own session", opens)
	}
}

// Finding 2: the Open/Subscribe early returns must fail open too. The stale
// verdict here came from ReportExternal (the phone's re-sync path, another
// goroutine entirely), so "only a successful subscribe could have set a down
// verdict" is not a defence — a car asleep enough to fail Open is exactly when
// a stranded "down" leaves it with no link at all.
func TestAttachFailureFailsOpen(t *testing.T) {
	for name, f := range map[string]*fakeSessionSource{
		"open fails":      {openErr: errors.New("scan timeout")},
		"subscribe fails": {subErr: errors.New("session gone")},
	} {
		t.Run(name, func(t *testing.T) {
			s := NewLockWatchService(f, "VIN0")
			s.retryDelay = 5 * time.Millisecond
			s.ReportExternal(true, false, time.Now())
			if s.Status().APShouldBeUp {
				t.Fatal("precondition: the external report should want the AP down")
			}

			s.Start()
			defer s.Stop()

			waitFor(t, 2*time.Second, "the failed attach to fail open", func() bool {
				return s.Status().APShouldBeUp
			})
		})
	}
}

// Finding 4: the verdict is time-dependent (ActivityLease), so a car that goes
// silent after an approach must be re-settled by the clock. Without the ticker
// the actuator stays on the stale "up" forever while Status() reports "down".
func TestExpiredActivityLeaseSettlesWithoutANewFrame(t *testing.T) {
	f := &fakeSessionSource{}
	s := NewLockWatchService(f, "VIN0")
	s.retryDelay = time.Hour // the attach succeeds; keep the retry loop out of it
	s.settleTick = 5 * time.Millisecond
	var rec recorder
	s.SetEnforcer(rec.fn)

	// Backdate both signals so the lease is already expired in real time.
	past := time.Now().Add(-2 * ActivityLease)
	s.Ingest(lockedEmptyFrame(t), past) // locked + empty → down
	s.Ingest(activityFrame(t), past)    // someone at the car → lease → up

	if up, ok := rec.last(); !ok || !up {
		t.Fatalf("precondition: the activity lease should have raised the AP, calls = %v", rec.snapshot())
	}
	if s.Status().APShouldBeUp {
		t.Fatal("precondition: with the lease expired the predicate should already read down")
	}

	s.Start() // starts the re-settle ticker
	defer s.Stop()

	waitFor(t, 2*time.Second, "the expired lease to settle down on its own", func() bool {
		up, ok := rec.last()
		return ok && !up
	})
}

// Finding 3: Start/Stop must survive being called in any order, any number of
// times. Stop before Start used to block forever (nothing ever closed done) and
// a second Start used to panic on a double close.
func TestStartStopLifecycleIsRobust(t *testing.T) {
	t.Run("stop without start returns", func(t *testing.T) {
		s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
		mustReturnWithin(t, 2*time.Second, "Stop() before Start()", func() {
			s.Stop()
			s.Stop()  // idempotent
			s.Start() // startOnce is spent; must not launch a supervisor
			s.Stop()
		})
	})

	t.Run("double start and double stop", func(t *testing.T) {
		f := &fakeSessionSource{}
		s := NewLockWatchService(f, "VIN0")
		s.retryDelay = 5 * time.Millisecond
		s.Start()
		s.Start() // must not launch a second supervisor or double-close done
		waitFor(t, 2*time.Second, "the supervisor to attach", func() bool {
			_, subbed, _ := f.counts()
			return subbed >= 1
		})
		mustReturnWithin(t, 2*time.Second, "Stop()", func() {
			s.Stop()
			s.Stop()
		})
	})
}
