package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
)

type fakeSessionSource struct {
	mu      sync.Mutex
	id      string
	ch      chan []byte
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
	f.id = "fake-session"
	return &BLESession{ID: f.id, VIN: vin}, nil
}

func (f *fakeSessionSource) Subscribe(id string) (int, <-chan []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

// Ingest is the seam the goroutine uses, so the state machine is testable
// without running the supervisor at all.
func TestIngestLockedAndEmptyWantsAPDown(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	s.Ingest(statusFrame(t,
		vcsec.VehicleLockState_E_VEHICLELOCKSTATE_LOCKED,
		vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT), now)
	st := s.Status()
	if !st.HaveStatus || !st.Locked || st.Present {
		t.Fatalf("status = %+v", st)
	}
	if st.APShouldBeUp {
		t.Error("locked + empty must want the AP down")
	}
}

func TestIngestGarbageLeavesFailOpen(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	s.Ingest([]byte{0xde, 0xad, 0xbe, 0xef}, now)
	if !s.Status().APShouldBeUp {
		t.Fatal("an undecodable frame must leave the AP up")
	}
}

func TestEnforcerCalledOnlyOnTransition(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	var mu sync.Mutex
	var calls []bool
	s.SetEnforcer(func(up bool) { mu.Lock(); calls = append(calls, up); mu.Unlock() })

	locked := statusFrame(t,
		vcsec.VehicleLockState_E_VEHICLELOCKSTATE_LOCKED,
		vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT)
	s.Ingest(locked, now)
	s.Ingest(locked, now.Add(time.Second)) // same verdict — must not re-fire
	s.Ingest(statusFrame(t,
		vcsec.VehicleLockState_E_VEHICLELOCKSTATE_UNLOCKED,
		vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT), now.Add(2*time.Second))

	mu.Lock()
	defer mu.Unlock()
	want := []bool{false, true}
	if len(calls) != len(want) {
		t.Fatalf("enforcer calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("enforcer calls = %v, want %v", calls, want)
		}
	}
}

func TestNilEnforcerIsSafe(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	// No SetEnforcer — this is Phase 1. Must not panic.
	s.Ingest(statusFrame(t,
		vcsec.VehicleLockState_E_VEHICLELOCKSTATE_LOCKED,
		vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT), now)
}

func TestReportExternalDrivesTheSameState(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	s.ReportExternal(true, false, now)
	if s.Status().APShouldBeUp {
		t.Fatal("an external locked+empty report must want the AP down")
	}
}

// Losing the session must fail OPEN, discarding the stale verdict.
func TestSessionLossFailsOpen(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := NewLockWatchService(&fakeSessionSource{}, "VIN0")
	s.Ingest(statusFrame(t,
		vcsec.VehicleLockState_E_VEHICLELOCKSTATE_LOCKED,
		vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT), now)
	if s.Status().APShouldBeUp {
		t.Fatal("precondition: should be down")
	}
	s.noteSessionLost()
	if !s.Status().APShouldBeUp {
		t.Fatal("after losing the BLE link the AP must fail open")
	}
}

// The supervisor opens a session when none exists, and subscribes to it.
func TestSupervisorOpensAndSubscribes(t *testing.T) {
	f := &fakeSessionSource{}
	s := NewLockWatchService(f, "VIN0")
	s.retryDelay = 5 * time.Millisecond
	s.Start()
	defer s.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		ok := f.opens >= 1 && f.subbed >= 1
		f.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("supervisor never opened + subscribed to a session")
}
