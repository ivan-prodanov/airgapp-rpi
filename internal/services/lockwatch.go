package services

// lockwatch — the CONCURRENT half of lock-gated WiFi. Keeps a subscription to
// the live BLE session's unsolicited fan-out, folds each frame through the pure
// lockgate predicate, and calls the enforcer when the verdict FLIPS.
//
// It deliberately does not own a session. BLESessionService.Open preempts, so a
// watcher-owned session would be force-closed by every phone Open; instead the
// supervisor attaches to whatever session is live and opens one only when there
// is none.
//
// Every failure path here fails OPEN. Losing the link, an unknown session, a
// closed channel — all of them discard the accumulated verdict and go back to
// "AP up", because being wrong must cost traffic, never connectivity.

import (
	"context"
	"log"
	"sync"
	"time"
)

// sessionSource is the slice of BLESessionService lockwatch needs.
// *BLESessionService satisfies it structurally; tests substitute a fake.
type sessionSource interface {
	CurrentSession() (string, bool)
	Open(ctx context.Context, vin string) (*BLESession, error)
	Subscribe(id string) (int, <-chan []byte, error)
	Unsubscribe(id string, subID int)
}

// LockWatchStatus is the read-only snapshot the UI and API render.
type LockWatchStatus struct {
	HaveStatus   bool      `json:"have_status"`
	Locked       bool      `json:"locked"`
	Present      bool      `json:"present"`
	APShouldBeUp bool      `json:"ap_should_be_up"`
	LastSignal   time.Time `json:"last_signal"`
	SessionID    string    `json:"session_id"`
}

type LockWatchService struct {
	src sessionSource
	vin string

	mu         sync.Mutex
	gate       GateState
	lastSignal time.Time
	sessionID  string
	enforcer   func(up bool)
	lastWanted *bool // nil until the first verdict, so the first one always fires

	retryDelay time.Duration
	stop       chan struct{}
	stopOnce   sync.Once
	done       chan struct{}
}

func NewLockWatchService(src sessionSource, vin string) *LockWatchService {
	return &LockWatchService{
		src:        src,
		vin:        vin,
		retryDelay: 10 * time.Second,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// SetEnforcer installs the AP actuator. Phase 1 never calls this, which is what
// makes Phase 1 structurally incapable of taking the radio down.
func (s *LockWatchService) SetEnforcer(fn func(up bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enforcer = fn
}

func (s *LockWatchService) Status() LockWatchStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return LockWatchStatus{
		HaveStatus:   s.gate.HaveStatus,
		Locked:       s.gate.Locked,
		Present:      s.gate.Present,
		APShouldBeUp: s.gate.APShouldBeUp(time.Now()),
		LastSignal:   s.lastSignal,
		SessionID:    s.sessionID,
	}
}

// Ingest folds one frame into the verdict and fires the enforcer on a flip.
func (s *LockWatchService) Ingest(frame []byte, now time.Time) {
	sig := DecodeLockSignal(frame)
	if sig.Kind == SignalNone {
		return
	}
	s.mu.Lock()
	s.gate = s.gate.Apply(sig, now)
	s.lastSignal = now
	fn, want := s.settleLocked(now)
	s.mu.Unlock()
	if fn != nil {
		fn(want)
	}
}

// ReportExternal is the phone's re-sync path: the app holds the keys, so it can
// poll GET_STATUS and tell us the authoritative answer. Same state, same flip
// logic — it just did not arrive over BLE.
func (s *LockWatchService) ReportExternal(locked, present bool, now time.Time) {
	s.mu.Lock()
	s.gate = s.gate.Apply(LockSignal{Kind: SignalStatus, Locked: locked, Present: present}, now)
	s.lastSignal = now
	fn, want := s.settleLocked(now)
	s.mu.Unlock()
	if fn != nil {
		fn(want)
	}
}

// noteSessionLost throws away the accumulated verdict. A stale lock state is
// exactly the thing that could hold the AP down while someone drives off, so
// losing the link resets to "we know nothing", which fails open.
func (s *LockWatchService) noteSessionLost() {
	s.mu.Lock()
	s.gate = GateState{}
	s.sessionID = ""
	fn, want := s.settleLocked(time.Now())
	s.mu.Unlock()
	if fn != nil {
		fn(want)
	}
}

// settleLocked computes the verdict and reports whether it changed. Caller must
// hold s.mu; it returns the enforcer rather than calling it so the actuator
// never runs under the lock.
func (s *LockWatchService) settleLocked(now time.Time) (func(bool), bool) {
	want := s.gate.APShouldBeUp(now)
	if s.lastWanted != nil && *s.lastWanted == want {
		return nil, want
	}
	s.lastWanted = &want
	log.Printf("[LOCKWATCH] verdict: ap_up=%v (have_status=%v locked=%v present=%v)",
		want, s.gate.HaveStatus, s.gate.Locked, s.gate.Present)
	return s.enforcer, want
}

func (s *LockWatchService) Start() { go s.supervise() }

func (s *LockWatchService) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
}

// supervise keeps exactly one subscription alive for the process lifetime.
func (s *LockWatchService) supervise() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		s.attachAndPump()
		select {
		case <-s.stop:
			return
		case <-time.After(s.retryDelay):
		}
	}
}

// attachAndPump subscribes to the live session (opening one if none exists) and
// consumes frames until the channel closes. Returns on any failure; the caller
// retries after retryDelay.
func (s *LockWatchService) attachAndPump() {
	id, ok := s.src.CurrentSession()
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		sess, err := s.src.Open(ctx, s.vin)
		cancel()
		if err != nil {
			log.Printf("[LOCKWATCH] open session: %v", err)
			return
		}
		id = sess.ID
	}

	subID, ch, err := s.src.Subscribe(id)
	if err != nil {
		log.Printf("[LOCKWATCH] subscribe %s: %v", id, err)
		return
	}
	defer s.src.Unsubscribe(id, subID)
	defer s.noteSessionLost()

	s.mu.Lock()
	s.sessionID = id
	s.mu.Unlock()
	log.Printf("[LOCKWATCH] attached to session %s", id)

	for {
		select {
		case <-s.stop:
			return
		case frame, open := <-ch:
			if !open {
				log.Printf("[LOCKWATCH] session %s closed", id)
				return
			}
			s.Ingest(frame, time.Now())
		}
	}
}
