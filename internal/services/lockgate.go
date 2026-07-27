package services

// lockgate — the PURE half of lock-gated WiFi. Decodes the car's plaintext
// unsolicited VCSEC pushes into a lock/presence verdict and answers one
// question: should the WiFi AP be up?
//
// Pure by construction — no goroutines, no I/O, no clock reads (callers pass
// `now`). That is what makes the predicate cheap to test exhaustively, and the
// predicate is the part that must not be wrong: getting it backwards takes the
// car's network away while someone is driving it.
//
// Why we can read these frames at all without keys: an unsolicited VCSEC push
// has no request to bind a GCM tag to, so the car sends it in the CLEAR. See
// mobile's src/ble/vcsecPush.ts, which does exactly this in TypeScript.

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
	"google.golang.org/protobuf/proto"
)

// ActivityLease is how long a non-status VCSEC frame holds the AP up. The car
// emits challenge frames at ~1 Hz on approach (see the passive-entry research),
// several seconds before an unlock lands — that head start is what hides the
// WiFi re-association delay. The lease exists so a passer-by who triggers those
// frames and then walks away does not leave the AP up forever: absent any newer
// signal it expires back to whatever the last real status said.
const ActivityLease = 3 * time.Minute

type SignalKind int

const (
	// SignalNone — not a readable car-initiated VCSEC frame. Inert.
	SignalNone SignalKind = iota
	// SignalStatus — a VehicleStatus push. Carries lock + presence.
	SignalStatus
	// SignalActivity — a car-initiated VCSEC frame that is not a status.
	// Carries no lock state, but proves something is happening at the car.
	SignalActivity
)

// LockSignal is one frame's contribution. Locked/Present are meaningful only
// when Kind == SignalStatus.
type LockSignal struct {
	Kind    SignalKind
	Locked  bool
	Present bool
}

// DecodeLockSignal classifies one frame off the session pump's unsolicited
// fan-out. Never panics and never errors — anything unreadable is SignalNone,
// because "we could not parse it" must never be able to influence the AP.
func DecodeLockSignal(frame []byte) LockSignal {
	var rm universal.RoutableMessage
	if err := proto.Unmarshal(frame, &rm); err != nil {
		return LockSignal{Kind: SignalNone}
	}
	// Must be FROM the vehicle-security domain.
	if rm.GetFromDestination().GetDomain() != universal.Domain_DOMAIN_VEHICLE_SECURITY {
		return LockSignal{Kind: SignalNone}
	}
	// Best-effort filter, not a guarantee: a non-empty requestUuid means this
	// is a reply to somebody's request (an Exchange caller's bytes, not ours
	// to read), so we drop it. But the vendored library's own docs note VCSEC
	// typically leaves request_uuid EMPTY in its replies (memory constraints),
	// so a solicited-but-unencrypted VCSEC reply can slip past this check.
	// That is harmless here: the car's own lock/presence values in a
	// VehicleStatus are accurate regardless of who asked for them, so reading
	// one that arrived as someone else's plaintext reply does not corrupt the
	// verdict — this filter just catches what it can.
	if len(rm.GetRequestUuid()) > 0 {
		return LockSignal{Kind: SignalNone}
	}
	// Signed/sealed response data means encrypted — we hold no keys.
	if rm.GetSignatureData().GetAES_GCM_ResponseData() != nil {
		return LockSignal{Kind: SignalNone}
	}
	payload := rm.GetProtobufMessageAsBytes()
	if len(payload) == 0 {
		return LockSignal{Kind: SignalNone}
	}
	var fv vcsec.FromVCSECMessage
	if err := proto.Unmarshal(payload, &fv); err != nil {
		return LockSignal{Kind: SignalNone}
	}
	vs := fv.GetVehicleStatus()
	if vs == nil {
		// Car-initiated VCSEC traffic that is not a status: approach
		// challenges, command acks, presence beacons. No lock state, but it
		// means something is going on at the car.
		return LockSignal{Kind: SignalActivity}
	}
	return LockSignal{
		Kind:   SignalStatus,
		Locked: vs.GetVehicleLockState() == vcsec.VehicleLockState_E_VEHICLELOCKSTATE_LOCKED,
		// UserPresence_E is THREE-valued: UNKNOWN, NOT_PRESENT, PRESENT. Test
		// against NOT_PRESENT, not PRESENT — `Present` means "not confirmed
		// absent", so UNKNOWN counts as present and fails open. Testing
		// `== PRESENT` would collapse UNKNOWN into "nobody there" and take the
		// AP down on a locked car whose presence sensor said nothing, which is
		// the exact case the fail-open constraint names.
		Present: vs.GetUserPresence() != vcsec.UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT,
	}
}

// GateState is the accumulated verdict. The zero value means "we have never
// heard from the car", which fails open.
type GateState struct {
	HaveStatus    bool
	Locked        bool
	Present       bool
	ActivityUntil time.Time
}

// Apply folds one signal into the state.
func (g GateState) Apply(sig LockSignal, now time.Time) GateState {
	switch sig.Kind {
	case SignalStatus:
		g.HaveStatus = true
		g.Locked = sig.Locked
		g.Present = sig.Present
	case SignalActivity:
		g.ActivityUntil = now.Add(ActivityLease)
	}
	return g
}

// APShouldBeUp is THE predicate.
//
// Down in exactly one situation: we have a status, it says LOCKED, it says
// nobody is present, and no recent activity is holding a lease. Everything
// else — every unknown, every parse failure, every state we have not seen — is
// up. Note the presence term is load-bearing, not a refinement: Teslas
// auto-lock at drive-away, so the car reads LOCKED for the whole drive, and
// without `!Present` this would cut the network every time you pull away.
func (g GateState) APShouldBeUp(now time.Time) bool {
	if !g.HaveStatus {
		return true
	}
	if now.Before(g.ActivityUntil) {
		return true
	}
	return !(g.Locked && !g.Present)
}

// DescribeFrame explains WHY DecodeLockSignal produced SignalNone for a frame.
// Diagnostic only — nothing in the predicate consults it.
//
// It exists because "38 frames: 0 status, 0 activity, 38 undecodable" (the
// first on-car run) is a dead end: it cannot distinguish "the car does not send
// state to a keyless listener, so the design's premise is wrong" from "the car
// does and this decoder is fumbling it". Those lead opposite ways. This walks
// the SAME gates DecodeLockSignal does, in the same order, and names the one
// that fired — using the protobuf types already vendored for the command path,
// not a hand-rolled parse.
func DescribeFrame(frame []byte) string {
	if len(frame) == 0 {
		return "empty frame"
	}
	head := frame
	if len(head) > 16 {
		head = head[:16]
	}
	var rm universal.RoutableMessage
	if err := proto.Unmarshal(frame, &rm); err != nil {
		return fmt.Sprintf("NOT a RoutableMessage: %v (len=%d head=%s)", err, len(frame), hex.EncodeToString(head))
	}

	parts := []string{fmt.Sprintf("len=%d", len(frame))}
	parts = append(parts, fmt.Sprintf("from_domain=%v", rm.GetFromDestination().GetDomain()))
	if ra := rm.GetFromDestination().GetRoutingAddress(); len(ra) > 0 {
		parts = append(parts, "from=routing_address(not a domain)")
	}
	parts = append(parts, fmt.Sprintf("to_domain=%v", rm.GetToDestination().GetDomain()))
	if len(rm.GetRequestUuid()) > 0 {
		parts = append(parts, "request_uuid=SET(solicited)")
	}
	if sd := rm.GetSignatureData(); sd != nil {
		if sd.GetAES_GCM_ResponseData() != nil {
			parts = append(parts, "SEALED(AES_GCM_Response)")
		} else {
			parts = append(parts, "signature_data=present")
		}
	}

	switch {
	case len(rm.GetProtobufMessageAsBytes()) > 0:
		payload := rm.GetProtobufMessageAsBytes()
		parts = append(parts, fmt.Sprintf("payload=%dB", len(payload)))
		var fv vcsec.FromVCSECMessage
		if err := proto.Unmarshal(payload, &fv); err != nil {
			parts = append(parts, "payload NOT a FromVCSECMessage")
		} else if sub := fv.GetSubMessage(); sub != nil {
			parts = append(parts, fmt.Sprintf("vcsec_submsg=%T", sub))
		} else {
			parts = append(parts, "FromVCSECMessage with NO sub_message")
		}
	case len(rm.GetSessionInfo()) > 0:
		parts = append(parts, fmt.Sprintf("session_info=%dB (handshake, not state)", len(rm.GetSessionInfo())))
	case rm.GetSignedMessageStatus() != nil:
		parts = append(parts, fmt.Sprintf("signed_message_status=%v", rm.GetSignedMessageStatus().GetOperationStatus()))
	default:
		parts = append(parts, "no payload of any known kind")
	}
	return strings.Join(parts, " ")
}
