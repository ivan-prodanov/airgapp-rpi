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
	Touch(id string)
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

// defaultSettleTick is how often the verdict is recomputed with no new signal.
// APShouldBeUp is time-dependent (ActivityLease), so a lease that expires while
// the car is silent has to be noticed by a clock, not by a frame — otherwise a
// passer-by leaves the AP up forever. Well under the 3-minute lease.
const defaultSettleTick = 30 * time.Second

// maxRetryBackoff caps supervise's exponential backoff after consecutive
// attachAndPump failures. It is a bound on how much of the BLE adapter's time
// a background observer may consume: no matter how long the car stays
// unreachable, the watcher's own retries settle down to at most one attempt
// every maxRetryBackoff, rather than hammering the adapter (and blocking the
// phone's command path behind it — see supervise) at a fixed short cadence
// forever.
const maxRetryBackoff = 5 * time.Minute

// defaultKeepaliveTick is how often attachAndPump refreshes the session's idle
// clock when no frames are arriving.
//
// BLESessionService's reaper closes a session bleSessionTTL (5 min) after its
// last touch, and until this existed the ONLY thing that touched was Exchange —
// which the watcher never calls. So a healthy, silent car got its watcher
// session reaped every five minutes forever: ~278 open/reap cycles a day, a
// verdict that could never be older than the TTL, and a fresh
// Open → AcquireBLEForVIN (ctx-blind bleMu, held across a BLE scan, before the
// session is registered where preemptExisting could reach it) blocking the
// phone's command path on that same cadence. Worse for the observe-only phase
// this watcher exists to serve: VCSEC commonly pushes a status right after a
// connect, so a push arriving every ~5 min would look identical whether the
// car pushes on an idle link or only ever answers a fresh GATT connect — the
// exact question being measured.
//
// 60s is comfortably under bleSessionTTL: several ticks are missed before the
// reaper could fire, so one descheduled tick is not a lost session, while the
// touch itself is a mutex and a clock read.
const defaultKeepaliveTick = 60 * time.Second

type LockWatchService struct {
	src sessionSource
	vin string

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

	// retryDelay, settleTick and keepaliveTick are read by the goroutines Start
	// launches WITHOUT holding a lock. That is safe only because they are
	// written once, at construction, and (in tests) before Start — never after.
	retryDelay    time.Duration
	settleTick    time.Duration
	keepaliveTick time.Duration

	stop      chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

func NewLockWatchService(src sessionSource, vin string) *LockWatchService {
	return &LockWatchService{
		src:           src,
		vin:           vin,
		retryDelay:    10 * time.Second,
		settleTick:    defaultSettleTick,
		keepaliveTick: defaultKeepaliveTick,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
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
func (s *LockWatchService) noteSessionLost() {
	s.mu.Lock()
	s.gate = GateState{}
	s.sessionID = ""
	s.lastSignal = time.Time{}
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
// The retry delay backs off exponentially on consecutive attachAndPump
// failures (capped at maxRetryBackoff), and resets to the base s.retryDelay
// the moment an attempt succeeds. This is mitigation for a ctx-blind lock
// upstream, not a fix for it: attachAndPump's Open path reaches
// TeslaService.AcquireBLEForVIN, which takes bleMu with a plain blocking
// Lock() that ignores ctx (internal/services/tesla.go, AcquireBLEForVIN) and
// holds it through a BLE scan bounded by teslaScanTimeout (15s). A concurrent
// phone-driven Open cannot preempt a session still mid-scan —
// BLESessionService.preemptExisting (internal/services/tesla_session.go) only
// preempts sessions already registered in its map — so it blocks behind us
// for that whole scan instead. At a flat retry cadence, a car that stays
// unreachable would repeat that stall roughly every retryDelay forever, on
// top of whatever the phone is trying to do. Backing off bounds how often a
// background observer can do that to the phone's command path; it does not
// touch bleMu or session registration (see BLESessionService.Open's comment
// about the same ctx-blind mutex causing 5-minute on-car outages) — actually
// fixing the lock is out of scope here because it touches the car's command
// path.
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

// attachAndPump subscribes to the live session (opening one if none exists)
// and consumes frames until the channel closes. Returns on any failure; the
// caller (supervise) retries after a delay that grows on repeated failure.
//
// The bool result reports whether this attempt achieved anything: true once
// Subscribe has succeeded, regardless of how the pump subsequently ends
// (Stop, the channel closing) — false for both early-return failure paths
// (Open failed, Subscribe failed). supervise uses this alone to decide
// whether to reset or grow its retry delay.
func (s *LockWatchService) attachAndPump() (subscribed bool) {
	// FIRST STATEMENT, deliberately: every exit from this function — Open
	// failing, Subscribe failing, the channel closing, Stop — must leave the
	// gate empty and therefore the AP up. Registering it only after a
	// successful Subscribe would make fail-open depend on an argument about
	// which paths can have set a down verdict, and that argument is false:
	// ReportExternal is exported and drives the gate down from another
	// goroutine entirely. A car asleep enough to fail Open is exactly when a
	// stale "down" would strand it with no link.
	defer s.noteSessionLost()

	id, ok := s.src.CurrentSession()
	if !ok {
		// Bound the open on Stop as well as the timeout, so shutdown is not
		// hostage to a 30s dial. This bounds only the ctx-AWARE part of the
		// path: Open → AcquireBLEForVIN takes bleMu with a plain Lock() that
		// ignores ctx (internal/services/tesla.go), so Stop can still be
		// delayed by that mutex. Cancelling here is the best a caller can do.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		stopped := make(chan struct{})
		go func() {
			select {
			case <-s.stop:
				cancel()
			case <-stopped:
			}
		}()
		sess, err := s.src.Open(ctx, s.vin)
		close(stopped)
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

	// Subscribe succeeded: this attempt counts as achieving something no
	// matter how the pump below eventually exits (Stop, the channel
	// closing) — set it now, once, rather than at every exit point below.
	subscribed = true

	s.mu.Lock()
	s.sessionID = id
	s.mu.Unlock()
	log.Printf("[LOCKWATCH] attached to session %s", id)

	// Keepalive. The session's idle clock is otherwise only refreshed by
	// Exchange, which is the phone's path, not ours — see defaultKeepaliveTick
	// for why an un-touched watcher session is reaped every bleSessionTTL and
	// why that ruins both the link and the measurement. Touching on each frame
	// covers a talkative car; the ticker covers a silent one.
	//
	// Holding the session indefinitely is the intent, not a leak: a phone Open
	// preempts us (newest wins), whereupon this pump's channel closes and
	// supervise re-attaches to the PHONE's session rather than opening a
	// competing one. There is deliberately no "polite release" — preemption
	// already is one.
	//
	// The ticker shares this select with the frame receive and s.stop, so a
	// keepalive can never delay shutdown by more than the touch itself.
	ka := time.NewTicker(s.keepaliveTick)
	defer ka.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ka.C:
			s.src.Touch(id)
		case frame, open := <-ch:
			if !open {
				log.Printf("[LOCKWATCH] session %s closed", id)
				return
			}
			// Before Ingest, not after: Ingest blocks for the whole enforcer
			// call when it settles, and the point of touching is the clock.
			s.src.Touch(id)
			s.Ingest(frame, time.Now())
		}
	}
}
