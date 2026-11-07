package services

// lockwatch — the CONCURRENT half of lock-gated WiFi. Keeps a subscription to
// the live BLE session's unsolicited fan-out, folds each frame through the pure
// lockgate predicate, and calls the enforcer when the verdict FLIPS.
//
// It only ever observes. The supervisor attaches to whatever session is live and,
// when there is none, waits. It must not open one or keep one alive:
//
//   - Opening takes the adapter. It used to open a session 10s after any other
//     closed, and a phone Open arriving during that scan had nothing to preempt, so
//     it queued behind a session nobody asked for. All nine phone opens that took
//     29s or more on 2026-11-07 started 1-4s before one of these, up to 1m51s.
//   - Keeping a session alive would defeat the reaper for a phone that has gone away.
//
// Every failure path here fails OPEN. Losing the link, an unknown session, a
// closed channel — all of them discard the accumulated verdict and go back to
// "AP up", because being wrong must cost traffic, never connectivity.

import (
	"log"
	"sync"
	"time"
)

// sessionSource is the slice of BLESessionService lockwatch needs.
// *BLESessionService satisfies it structurally; tests substitute a fake. It has no
// Open and nothing that refreshes a session's idle clock, which is what makes the
// watcher structurally incapable of competing with the phone for the radio.
type sessionSource interface {
	CurrentSession() (string, bool)
	Subscribe(id string) (int, <-chan []byte, error)
	Unsubscribe(id string, subID int)
}

// LockWatchStatus is the read-only snapshot the UI and API render.
//
// AttachedSince and FramesSeen describe the CURRENT attachment only, and exist
// because "attached" on its own is not a diagnosis. "Attached / Last signal:
// never" is the same string whether the link came up two seconds ago and the
// car simply has not spoken yet, or the link came up nine hours ago and has
// been dead for most of them. AttachedSince + FramesSeen separate those: the
// first case reads "Attached 2s · 0 frames", the second "Attached 9h · 0
// frames", and only the second is alarming. Both are cleared by
// noteSessionLost along with the rest of the attachment's state.
type LockWatchStatus struct {
	HaveStatus    bool      `json:"have_status"`
	Locked        bool      `json:"locked"`
	Present       bool      `json:"present"`
	APShouldBeUp  bool      `json:"ap_should_be_up"`
	LastSignal    time.Time `json:"last_signal"`
	SessionID     string    `json:"session_id"`
	AttachedSince time.Time `json:"attached_since"`
	FramesSeen    int       `json:"frames_seen"`
}

// defaultSettleTick is how often the verdict is recomputed with no new signal.
// APShouldBeUp is time-dependent (ActivityLease), so a lease that expires while
// the car is silent has to be noticed by a clock, not by a frame — otherwise a
// passer-by leaves the AP up forever. Well under the 3-minute lease.
const defaultSettleTick = 30 * time.Second

// maxRetryBackoff caps supervise's exponential backoff after consecutive attach
// failures. Having no session to attach to is not a failure and does not back off.
const maxRetryBackoff = 5 * time.Minute

// maxFramesDescribed caps the per-frame diagnostic per attachment. Enough for a
// representative sample of what the car actually sends a keyless listener,
// without turning journalctl into a packet log.
const maxFramesDescribed = 8

type LockWatchService struct {
	src sessionSource

	// LOCK ORDERING: applyMu THEN mu, never the reverse. applyMu serialises
	// decide-and-apply (see settle) and is the only lock held across the
	// enforcer call; mu guards the state below and is always taken inside
	// applyMu and released before the actuator runs. Inverting this deadlocks.
	applyMu sync.Mutex
	// lastWanted is guarded by applyMu ONLY — it lives entirely inside the
	// apply path so it can never disagree with the last call the actuator got.
	// nil until the first verdict, so the first one always fires.
	lastWanted *bool

	mu         sync.Mutex
	gate       GateState
	lastSignal time.Time
	sessionID  string
	enforcer   func(up bool)
	// attachedSince and framesSeen describe the CURRENT attachment: set when
	// Subscribe succeeds, cleared by noteSessionLost. Reported by Status so
	// "Attached" can be told apart from "attached ages ago and probably dead".
	attachedSince time.Time
	framesSeen    int
	// framesStatus / framesActivity break framesSeen down by what
	// DecodeLockSignal made of each frame. Without this split, "15 frames
	// seen, have_status=false" is ambiguous between "the car spoke and none
	// of it was a VehicleStatus" and "the car spoke and we could not parse
	// it" — and those point opposite ways: the first says the design's
	// premise is wrong, the second says our decoder is. Undecodable is
	// framesSeen - framesStatus - framesActivity.
	framesStatus   int
	framesActivity int
	// framesDescribed rate-limits the per-frame diagnostic below to the first
	// few of each attachment. The car sent 38 undecodable frames in 43
	// minutes, so a handful is a representative sample, not a sacrifice.
	framesDescribed int
	// sawStatus latches the first VehicleStatus of the process. That
	// transition is the single most important event of the observation run
	// and is otherwise invisible: settle only logs when the AP VERDICT
	// changes, so an unlock (verdict stays up) or a lock while presence
	// reads UNKNOWN (also stays up) would flip have_status silently.
	sawStatus bool

	// retryDelay and settleTick are read by the goroutines Start launches WITHOUT
	// holding a lock. That is safe only because they are written once, at
	// construction, and (in tests) before Start — never after.
	retryDelay time.Duration
	settleTick time.Duration

	stop      chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

func NewLockWatchService(src sessionSource) *LockWatchService {
	return &LockWatchService{
		src:        src,
		retryDelay: 10 * time.Second,
		settleTick: defaultSettleTick,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// SetEnforcer installs the AP actuator. Phase 1 never calls this, which is what
// makes Phase 1 structurally incapable of taking the radio down.
//
// Installing an actuator immediately asserts the CURRENT verdict rather than
// waiting for an unrelated event: after a restart that previously left the
// radio down, nothing else would ever raise it — the gate starts empty, so its
// verdict is "up", and without this settle no flip would occur to say so.
//
// That assertion must not be short-circuited by settle's own dedup. A settle
// that ran earlier with NO enforcer installed (Phase 1, or the gap before this
// call) still writes lastWanted — settle has no idea whether fn was nil, it
// just records what it decided. If we called settle here without first
// clearing lastWanted, and the verdict happens to match what that nil-enforcer
// settle already recorded, settle finds "nothing changed" and returns without
// ever calling the actuator we just installed — exactly the case this
// paragraph promises to prevent. So: clear lastWanted to nil (in its own
// applyMu section — settle takes applyMu itself, so we cannot hold it across
// the call) before settling, which forces the assertion regardless of what any
// earlier, enforcer-less settle believed. This also covers replacing an
// already-installed enforcer: the new one gets told the current verdict too,
// rather than inheriting a call made to its predecessor.
//
// The enforcer runs on whichever goroutine settled — the supervisor, the
// re-settle ticker, or an API caller's Ingest/ReportExternal — with applyMu
// held. So an enforcer that calls Stop() self-deadlocks (Stop waits for those
// goroutines), and one that calls SetEnforcer or Ingest re-enters applyMu.
// Keep it to shelling out at the radio.
func (s *LockWatchService) SetEnforcer(fn func(up bool)) {
	s.mu.Lock()
	s.enforcer = fn
	s.mu.Unlock()

	s.applyMu.Lock()
	s.lastWanted = nil
	s.applyMu.Unlock()

	s.settle(time.Now())
}

func (s *LockWatchService) Status() LockWatchStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return LockWatchStatus{
		HaveStatus:    s.gate.HaveStatus,
		Locked:        s.gate.Locked,
		Present:       s.gate.Present,
		APShouldBeUp:  s.gate.APShouldBeUp(time.Now()),
		LastSignal:    s.lastSignal,
		SessionID:     s.sessionID,
		AttachedSince: s.attachedSince,
		FramesSeen:    s.framesSeen,
	}
}

// Ingest folds one frame into the verdict and fires the enforcer on a flip.
func (s *LockWatchService) Ingest(frame []byte, now time.Time) {
	sig := DecodeLockSignal(frame)

	// Classify BEFORE the SignalNone early return — an undecodable frame is
	// evidence too, and counting only the ones we understood is what made the
	// first run's "15 frames seen" unreadable.
	s.mu.Lock()
	firstStatus := false
	switch sig.Kind {
	case SignalStatus:
		s.framesStatus++
		if !s.sawStatus {
			s.sawStatus = true
			firstStatus = true
		}
	case SignalActivity:
		s.framesActivity++
	}
	describe := ""
	if sig.Kind == SignalNone && s.framesDescribed < maxFramesDescribed {
		s.framesDescribed++
		describe = DescribeFrame(frame)
	}
	s.mu.Unlock()

	if describe != "" {
		log.Printf("[LOCKWATCH] undecodable frame: %s", describe)
	}

	if firstStatus {
		// Deliberately loud and unconditional: this is the answer to "does the
		// car push state to us at all", and nothing else in the log reports it.
		log.Printf("[LOCKWATCH] *** FIRST VehicleStatus decoded *** locked=%v present=%v",
			sig.Locked, sig.Present)
	}
	if sig.Kind == SignalStatus {
		// Status pushes are rare (zero in the first 95 minutes on-car), so
		// logging each one costs nothing and shows whether they arrive on an
		// idle link or only in the seconds after a fresh attach.
		log.Printf("[LOCKWATCH] status push: locked=%v present=%v", sig.Locked, sig.Present)
	}

	if sig.Kind == SignalNone {
		return
	}
	s.mu.Lock()
	s.gate = s.gate.Apply(sig, now)
	s.lastSignal = now
	s.mu.Unlock()
	s.settle(now)
}

// ReportExternal is the phone's re-sync path: the app holds the keys, so it can
// poll GET_STATUS and tell us the authoritative answer. Same state, same flip
// logic — it just did not arrive over BLE.
func (s *LockWatchService) ReportExternal(locked, present bool, now time.Time) {
	s.mu.Lock()
	s.gate = s.gate.Apply(LockSignal{Kind: SignalStatus, Locked: locked, Present: present}, now)
	s.lastSignal = now
	s.mu.Unlock()
	s.settle(now)
}

// noteSessionLost throws away the accumulated verdict. A stale lock state is
// exactly the thing that could hold the AP down while someone drives off, so
// losing the link resets to "we know nothing", which fails open.
//
// lastSignal goes with it. It is the timestamp OF the state being discarded,
// so keeping it made the dashboard self-contradictory: "Unknown / Unknown /
// Should be UP / 4s ago" reads as a car that just told us something we somehow
// know nothing about. Zeroing it renders "never", which is the truth — we have
// heard nothing since we still had a link.
//
// attachedSince and framesSeen go with it for the same reason: they describe
// an attachment that no longer exists, and leaving them set would let the
// dashboard report an age and a frame count for a link that is gone.
func (s *LockWatchService) noteSessionLost() {
	s.mu.Lock()
	s.gate = GateState{}
	s.sessionID = ""
	s.lastSignal = time.Time{}
	s.attachedSince = time.Time{}
	s.framesSeen = 0
	s.framesStatus = 0
	s.framesActivity = 0
	s.framesDescribed = 0
	s.mu.Unlock()
	s.settle(time.Now())
}

// settle resolves the current verdict and applies it if it changed.
//
// applyMu serialises DECISION AND APPLICATION together. Computing the verdict
// under mu and then calling the enforcer after unlocking is not enough: two
// goroutines can each compute a verdict, both unlock, and then invoke the
// actuator in the opposite order, leaving the radio in a state that contradicts
// the gate — and since lastWanted then matches that stale call, nothing ever
// corrects it. Holding applyMu across the whole read-decide-apply sequence
// makes the last call always the one derived from the latest state.
//
// mu is taken INSIDE applyMu and released before the enforcer runs, so
// Status() stays responsive even while the actuator is running — it only ever
// waits on mu, never on applyMu.
//
// Ingest and ReportExternal are NOT so lucky: they call settle synchronously,
// so they block for the full duration of the actuator call whenever they are
// the ones who settle. That is deliberate, not an oversight — it is the exact
// mechanism that makes "the last call always matches the latest state" true.
// Releasing applyMu before calling fn (so a caller could return early) would
// reopen the round-1 hole: two settles could then invoke the actuator in the
// opposite order of their decisions. Do not read this as a note to fix later.
//
// Operational consequence: while the actuator runs, whichever goroutine is
// blocked in settle cannot do anything else — including, concretely, the
// frame-pump goroutine in attachAndPump, which cannot drain the session's
// unsolicited fan-out channel until its Ingest call returns. That channel is
// bounded (internal/services/tesla_session.go, subscribe's buffer cap 8) and
// drops frames once full rather than blocking the pump upstream. So the
// actuator's running time is not free: it must stay well inside that 8-frame
// headroom, or a slow systemctl call starts costing lock/presence pushes, not
// just latency.
func (s *LockWatchService) settle(now time.Time) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	s.mu.Lock()
	want := s.gate.APShouldBeUp(now)
	fn := s.enforcer
	haveStatus, locked, present := s.gate.HaveStatus, s.gate.Locked, s.gate.Present
	s.mu.Unlock()

	if s.lastWanted != nil && *s.lastWanted == want {
		return
	}
	s.lastWanted = &want
	log.Printf("[LOCKWATCH] verdict: ap_up=%v (have_status=%v locked=%v present=%v)",
		want, haveStatus, locked, present)
	if fn != nil {
		fn(want)
	}
}

// Start launches the supervisor and the re-settle ticker. Idempotent: a second
// Start (or a Start after Stop) is a no-op rather than a second pair of
// goroutines racing to close done.
func (s *LockWatchService) Start() {
	s.startOnce.Do(func() {
		s.wg.Add(2)
		go func() { defer s.wg.Done(); s.supervise() }()
		go func() { defer s.wg.Done(); s.resettleLoop() }()
		// done closes once BOTH goroutines are gone, so Stop returning means
		// neither supervise's frame pump nor resettleLoop's ticker can still be
		// mid-enforcer-call. That is ALL it means: an external caller of
		// Ingest, ReportExternal, or SetEnforcer runs on its own goroutine,
		// outside this WaitGroup, and can still be inside the actuator when
		// Stop returns.
		go func() { s.wg.Wait(); close(s.done) }()
	})
}

// Stop halts the supervisor and the re-settle ticker and waits for both to
// exit.
//
// It can itself actuate the radio. attachAndPump's deferred noteSessionLost
// runs as supervise unwinds, which settles with the gate reset to empty; if
// the verdict just before shutdown was "down", that is a flip, and the
// enforcer fires with true before Stop returns — the WaitGroup Start built
// guarantees supervise does not exit until its deferred settle has completed.
// This is intentional: a stopping process must not leave the radio down with
// no one left to raise it. But it means Stop can shell out to the actuator,
// not just close channels, so callers should not assume Stop is cheap or
// that it never blocks on external I/O.
func (s *LockWatchService) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
	// If Start never ran, nothing will ever close done — claim startOnce so
	// supervise can no longer be launched, and close done ourselves.
	s.startOnce.Do(func() { close(s.done) })
	<-s.done
}

// resettleLoop re-evaluates the verdict on a timer. The predicate is
// time-dependent (ActivityLease expiry), so without this the verdict only ever
// moves when a frame arrives — a car that goes silent after an approach keeps
// the AP up forever, and Status() reports a verdict the actuator was never
// told. Deliberately its own goroutine: supervise spends most of its life
// blocked in attachAndPump's frame loop and could not tick from there.
func (s *LockWatchService) resettleLoop() {
	t := time.NewTicker(s.settleTick)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-t.C:
			s.settle(now)
		}
	}
}

// supervise keeps exactly one subscription alive for the process lifetime.
//
// It looks for a session every retryDelay. The delay backs off exponentially on
// consecutive attach failures (capped at maxRetryBackoff) and resets the moment an
// attempt does not fail. The look itself is only a map lookup, so an idle Pi costs
// nothing and a new phone session is picked up within retryDelay.
//
// delay is a plain local variable, not a struct field: it belongs entirely to
// this goroutine, so it needs no lock and can never be read inconsistently.
func (s *LockWatchService) supervise() {
	delay := s.retryDelay
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		if s.attachAndPump() {
			delay = s.retryDelay
		} else {
			delay *= 2
			if delay > maxRetryBackoff {
				delay = maxRetryBackoff
			}
		}
		select {
		case <-s.stop:
			return
		case <-time.After(delay):
		}
	}
}

// attachAndPump subscribes to the live session, if there is one, and consumes
// frames until the channel closes.
//
// The bool result reports whether the attempt was free of failure, which is all
// supervise needs to decide whether to reset or grow its retry delay: true when
// there was nothing to attach to, and true once Subscribe has succeeded however
// the pump then ends (Stop, the channel closing). False only if Subscribe failed.
func (s *LockWatchService) attachAndPump() (ok bool) {
	// FIRST STATEMENT, deliberately: every exit from this function — no session,
	// Subscribe failing, the channel closing, Stop — must leave the gate empty and
	// therefore the AP up. Registering it only after a successful Subscribe would
	// make fail-open depend on an argument about which paths can have set a down
	// verdict, and that argument is false: ReportExternal is exported and drives
	// the gate down from another goroutine entirely. A car with no session on it
	// is exactly when a stale "down" would strand it with no link.
	defer s.noteSessionLost()

	id, live := s.src.CurrentSession()
	if !live {
		return true
	}

	subID, ch, err := s.src.Subscribe(id)
	if err != nil {
		log.Printf("[LOCKWATCH] subscribe %s: %v", id, err)
		return
	}
	defer s.src.Unsubscribe(id, subID)

	// Subscribe succeeded: this attempt counts as a success no matter how the pump
	// below eventually exits (Stop, the channel closing) — set it now, once, rather
	// than at every exit point below.
	ok = true

	attachedAt := time.Now()
	s.mu.Lock()
	s.sessionID = id
	s.attachedSince = attachedAt
	s.framesSeen = 0
	s.framesStatus = 0
	s.framesActivity = 0
	s.framesDescribed = 0
	s.mu.Unlock()
	log.Printf("[LOCKWATCH] attached to session %s", id)

	// Log the attachment's frame count on the way out. This is the deployment's
	// primary evidence, not decoration: if pushes cluster right after each
	// attach and then stop, "the car only answers a fresh GATT connect" and
	// "the car pushes on an idle link" are distinguishable in journalctl
	// without instrumenting anything else. Registered AFTER the deferred
	// noteSessionLost, so it runs BEFORE it — noteSessionLost zeroes exactly
	// the counters being reported.
	defer func() {
		s.mu.Lock()
		n, st, act := s.framesSeen, s.framesStatus, s.framesActivity
		s.mu.Unlock()
		log.Printf("[LOCKWATCH] detached from session %s after %v — %d frames: %d status, %d activity, %d undecodable",
			id, time.Since(attachedAt).Truncate(time.Second), n, st, act, n-st-act)
	}()

	for {
		select {
		case <-s.stop:
			return
		case frame, open := <-ch:
			if !open {
				log.Printf("[LOCKWATCH] session %s closed", id)
				return
			}
			now := time.Now()
			s.mu.Lock()
			s.framesSeen++
			s.mu.Unlock()
			s.Ingest(frame, now)
		}
	}
}
