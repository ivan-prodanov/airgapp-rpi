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
	// openTimes records the wall-clock instant of each Open call, in call
	// order. Backoff tests read this (via openTimestamps) to observe the GAP
	// between consecutive attach attempts, rather than reaching into any
	// LockWatchService internals — this is purely a test fixture.
	openTimes []time.Time
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
	f.openTimes = append(f.openTimes, time.Now())
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

// openTimestamps returns a snapshot of every Open call's timestamp so far,
// in call order.
func (f *fakeSessionSource) openTimestamps() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.openTimes...)
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

// Round 2 Finding A: settle writes lastWanted whether or not an enforcer is
// installed — it has no idea fn was nil, it just records what it decided. So
// a settle that ran with a nil enforcer still "spends" lastWanted, and a
// later SetEnforcer that just compares against it can find the verdict
// unchanged and skip the call — installing an actuator that is told nothing.
// This is the reviewer's probe, made permanent: assert on the recorded calls,
// not merely on the absence of a panic.
func TestSetEnforcerAfterAPriorSettleStillAsserts(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")

	// This settle runs against a nil enforcer (Phase 1) and burns lastWanted.
	s.Ingest(lockedEmptyFrame(t), now) // locked + empty -> down
	if s.Status().APShouldBeUp {
		t.Fatal("precondition: locked + empty should want the AP down")
	}

	var rec recorder
	s.SetEnforcer(rec.fn)

	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("enforcer calls after SetEnforcer = %v, want exactly one call", calls)
	}
	if calls[0] != false {
		t.Fatalf("enforcer called with %v, want false — it must be told the CURRENT verdict (down), not skipped because a nil-enforcer settle already recorded it", calls[0])
	}
}

// Companion case: SetEnforcer before any settle has ever run (lastWanted is
// still its construction-time nil) must also assert the current verdict —
// this was never broken, but belongs alongside the prior-settle case so the
// two together pin SetEnforcer's contract regardless of history.
func TestSetEnforcerBeforeAnySettleAsserts(t *testing.T) {
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	var rec recorder
	s.SetEnforcer(rec.fn)

	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("enforcer calls after SetEnforcer = %v, want exactly one call", calls)
	}
	if calls[0] != true {
		t.Fatalf("enforcer called with %v, want true — the gate is empty, so the current verdict is up", calls[0])
	}
}

// Round 2 Finding A, minor: replacing an already-installed enforcer must tell
// the NEW one the current verdict too, not silently inherit the fact that its
// predecessor was already told.
func TestSetEnforcerReplacingAnInstalledEnforcerAssertsToTheNewOne(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")

	var first recorder
	s.SetEnforcer(first.fn) // gate empty -> up; first gets called with true

	s.Ingest(lockedEmptyFrame(t), now) // flips to down; first gets called with false

	var second recorder
	s.SetEnforcer(second.fn)

	calls := second.snapshot()
	if len(calls) != 1 || calls[0] != false {
		t.Fatalf("second enforcer calls = %v, want exactly one call with false (current verdict)", calls)
	}
}

// Round 2 Finding B: round 1's headline fix was serialising decide-and-apply
// under applyMu so the LAST enforcer call always matches the final state,
// regardless of goroutine interleaving. This is a property test, not an
// attempt to reproduce one exact interleaving — it hammers the mutators
// concurrently, quiesces for real (WaitGroup, not a sleep), and checks the
// invariant. Post-fix this is deterministic: every mutator routes through
// settle, and applyMu totally orders decide-and-apply, so the temporally-last
// settle call necessarily reads the gate as it stands after every goroutine
// has finished (each goroutine's own mutation always precedes its own settle
// call, synchronously, so no mutation can occur after the last settle without
// that same goroutine's settle then being the new last one — a contradiction).
// Pre-fix (decide under mu, release mu, THEN call fn) two settles can compute
// their verdicts and then invoke the actuator in the opposite order, so this
// fails probabilistically — the correct behaviour for a negative control.
//
// Status frames / ReportExternal only — no activity signals — so
// APShouldBeUp never depends on ActivityLease here and the assertion cannot
// be perturbed by a lease expiring mid-test.
func TestConcurrentMutatorsLastEnforcerCallMatchesFinalState(t *testing.T) {
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	var rec recorder
	s.SetEnforcer(rec.fn)

	const n = 200
	var wg sync.WaitGroup
	wg.Add(3 * n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s.ReportExternal(true, false, time.Now()) // locked + empty -> down
		}()
		go func() {
			defer wg.Done()
			s.ReportExternal(false, false, time.Now()) // unlocked -> up
		}()
		go func() {
			defer wg.Done()
			s.noteSessionLost() // gate reset -> up (fail open)
		}()
	}
	wg.Wait() // real quiescence: every mutator has returned, not a sleep

	want := s.Status().APShouldBeUp
	got, ok := rec.last()
	if !ok {
		t.Fatal("enforcer was never called")
	}
	if got != want {
		t.Fatalf("last enforcer call = %v, want %v (Status().APShouldBeUp) — the last actuator call must always match the final state", got, want)
	}
}

// The finding this pins: a watcher retrying at a FIXED cadence while the car
// is unreachable would, every retryDelay, race a phone Open against
// attachAndPump's Open — which reaches AcquireBLEForVIN's ctx-blind bleMu.Lock()
// (internal/services/tesla.go) and can hold it through a full teslaScanTimeout
// scan before a still-registering session can be preempted
// (BLESessionService.preemptExisting, internal/services/tesla_session.go).
// The fix is exponential backoff on consecutive attachAndPump failures, so a
// permanently-unreachable car is retried less and less often rather than
// forever at the same short cadence. This test proves the delay GROWS across
// consecutive failures — not merely that retries happen — by observing the
// real gaps between Open call timestamps, without exposing any backoff state
// on LockWatchService itself.
func TestSuperviseBacksOffOnConsecutiveFailures(t *testing.T) {
	f := &fakeSessionSource{openErr: errors.New("scan timeout")}
	s := NewLockWatchService(f, "VIN0")
	s.retryDelay = 40 * time.Millisecond
	s.Start()
	defer s.Stop()

	const wantAttempts = 5
	waitFor(t, 5*time.Second, "enough failed attach attempts to observe backoff", func() bool {
		return len(f.openTimestamps()) >= wantAttempts
	})

	times := f.openTimestamps()
	if len(times) < wantAttempts {
		t.Fatalf("got %d attempts, want at least %d", len(times), wantAttempts)
	}
	times = times[:wantAttempts]

	// gaps[i] is the wait that preceded attempt i+1 — i.e. the backoff delay
	// supervise computed after attempt i failed.
	gaps := make([]time.Duration, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i].Sub(times[i-1]))
	}

	// Each gap must be clearly larger than the one before it. True doubling
	// (the implemented behaviour) clears a 1.5x bar with room to spare; a
	// regression back to a flat retryDelay (ratio ~1.0) fails it outright.
	// Tolerant of scheduler jitter, not tolerant of "not growing".
	for i := 1; i < len(gaps); i++ {
		min := gaps[i-1] * 3 / 2
		if gaps[i] <= min {
			t.Fatalf("gaps = %v — gap[%d]=%v is not clearly larger than gap[%d]=%v; backoff does not appear to be growing", gaps, i, gaps[i], i-1, gaps[i-1])
		}
	}
}

// Companion to the backoff-growth test: a background observer's exponential
// backoff must never make shutdown sluggish. Once several consecutive
// failures have grown the retry delay well past retryDelay, Stop() must still
// return promptly — the select on s.stop in supervise's retry-wait (and the
// one at the top of its loop) must win over an in-flight multi-second
// time.After, exactly as it already does for the un-backed-off delay.
func TestStopReturnsPromptlyDuringABackedOffSleep(t *testing.T) {
	f := &fakeSessionSource{openErr: errors.New("scan timeout")}
	s := NewLockWatchService(f, "VIN0")
	s.retryDelay = 50 * time.Millisecond
	s.Start()

	// Let enough consecutive failures accumulate that the pending backoff
	// sleep is comfortably longer (by 2026-07-27's doubling: 50ms * 2^5 =
	// 1.6s+ by the 6th attempt) than the prompt-return bound checked below —
	// so this genuinely exercises interrupting a BACKED-OFF sleep, not just
	// the base retryDelay.
	waitFor(t, 5*time.Second, "the backoff to grow past a comfortably long bound", func() bool {
		return len(f.openTimestamps()) >= 6
	})

	mustReturnWithin(t, 300*time.Millisecond, "Stop() during a backed-off sleep", func() {
		s.Stop()
	})
}
