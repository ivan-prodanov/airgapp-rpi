package services

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
)

// statusFrame builds the exact wire shape of an unsolicited VCSEC status
// push: a RoutableMessage FROM domain 2, with NO requestUuid (that would
// make it a solicited reply) and NO signature data (that would make it
// sealed), carrying a plaintext FromVCSECMessage.VehicleStatus.
func statusFrame(t *testing.T, lock vcsec.VehicleLockState_E, pres vcsec.UserPresence_E) []byte {
	t.Helper()
	inner, err := proto.Marshal(&vcsec.FromVCSECMessage{
		SubMessage: &vcsec.FromVCSECMessage_VehicleStatus{
			VehicleStatus: &vcsec.VehicleStatus{
				VehicleLockState: lock,
				UserPresence:     pres,
			},
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

func TestDecodeLockSignalStatus(t *testing.T) {
	f := statusFrame(t, vcsec.VehicleLockState_E_VEHICLELOCKSTATE_LOCKED,
		vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT)
	got := DecodeLockSignal(f)
	if got.Kind != SignalStatus {
		t.Fatalf("Kind = %v, want SignalStatus", got.Kind)
	}
	if !got.Locked || got.Present {
		t.Fatalf("got %+v, want Locked=true Present=false", got)
	}
}

func TestDecodeLockSignalGarbageIsNone(t *testing.T) {
	for name, frame := range map[string][]byte{
		"empty":  {},
		"random": {0xff, 0xff, 0xff, 0xff},
	} {
		if got := DecodeLockSignal(frame); got.Kind != SignalNone {
			t.Errorf("%s: Kind = %v, want SignalNone", name, got.Kind)
		}
	}
}

// A VCSEC frame that is NOT a VehicleStatus (e.g. the ~1 Hz passive-entry
// challenge the car emits on approach) is car ACTIVITY: someone is at the
// car. It must bring the AP up even though it carries no lock state.
func TestDecodeLockSignalNonStatusVcsecIsActivity(t *testing.T) {
	inner, err := proto.Marshal(&vcsec.FromVCSECMessage{
		SubMessage: &vcsec.FromVCSECMessage_CommandStatus{
			CommandStatus: &vcsec.CommandStatus{},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	outer, err := proto.Marshal(&universal.RoutableMessage{
		FromDestination: &universal.Destination{
			SubDestination: &universal.Destination_Domain{Domain: universal.Domain_DOMAIN_VEHICLE_SECURITY},
		},
		Payload: &universal.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: inner},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := DecodeLockSignal(outer); got.Kind != SignalActivity {
		t.Fatalf("Kind = %v, want SignalActivity", got.Kind)
	}
}

// THE predicate. Exhaustive over lock × presence. Only ONE cell is "down".
func TestAPShouldBeUp(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cases := []struct {
		name   string
		locked bool
		presnt bool
		wantUp bool
	}{
		{"locked and empty — the only down case", true, false, false},
		{"locked but someone inside (driving)", true, true, true},
		{"unlocked and empty", false, false, true},
		{"unlocked and occupied", false, true, true},
	}
	for _, c := range cases {
		g := GateState{HaveStatus: true, Locked: c.locked, Present: c.presnt}
		if got := g.APShouldBeUp(now); got != c.wantUp {
			t.Errorf("%s: APShouldBeUp = %v, want %v", c.name, got, c.wantUp)
		}
	}
}

// Fail-open: before any status has ever been seen, the AP is UP.
func TestAPShouldBeUpWithoutStatusFailsOpen(t *testing.T) {
	now := time.Unix(1700000000, 0)
	if !(GateState{}).APShouldBeUp(now) {
		t.Fatal("zero GateState must fail open (AP up)")
	}
}

// An activity frame overrides a locked-and-empty status for the lease
// duration, then expires back to the status verdict.
func TestActivityLeaseOverridesThenExpires(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := GateState{HaveStatus: true, Locked: true, Present: false}
	if g.APShouldBeUp(now) {
		t.Fatal("precondition: locked+empty should be down")
	}
	g = g.Apply(LockSignal{Kind: SignalActivity}, now)
	if !g.APShouldBeUp(now.Add(ActivityLease - time.Second)) {
		t.Error("within lease: AP must be up")
	}
	if g.APShouldBeUp(now.Add(ActivityLease + time.Second)) {
		t.Error("after lease: AP must fall back to the status verdict (down)")
	}
}

// A SignalNone frame must not disturb accumulated state.
func TestApplyNoneIsInert(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := GateState{HaveStatus: true, Locked: true, Present: false}
	if got := g.Apply(LockSignal{Kind: SignalNone}, now); got != g {
		t.Fatalf("SignalNone changed state: %+v -> %+v", g, got)
	}
}
