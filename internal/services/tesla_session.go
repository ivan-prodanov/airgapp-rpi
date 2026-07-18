// tesla_session.go — raw byte-forwarder over an active BLE connection.
//
// V4.4 Phase 3b of the BLE-key rearchitecture. With the client now
// holding its own non-extractable WebCrypto P-256 keypair (Phase 3a),
// it can derive a Tesla session key locally — but it still needs the
// Pi's BLE radio to actually talk to the car. This file is that
// bridge: open a BLE session, exchange raw protobuf bytes, close.
// The Pi never inspects the bytes, never decrypts them, never holds
// a session key — they're opaque RoutableMessage frames.
//
// Concurrency model:
//
//   * Linux can host only one BLE adapter client at a time, and the
//     SDK's session state isn't thread-safe under interleaving. So
//     exactly ONE BLE session is alive at any moment, enforced by
//     TeslaService.bleMu (acquired in AcquireBLEForVIN, released in
//     the session's close callback).
//
//   * While a session is open, the existing /api/ble/cmd/* path
//     blocks on bleMu — first one wins, second waits until the first
//     calls Close (or the idle reaper does it). The "either / or"
//     property survives because both paths route through bleMu.
//
//   * Idle TTL: 5 min from last Exchange. After that the reaper
//     force-closes and releases bleMu so a stuck client never
//     livelocks the BLE adapter.
//
// Phase 3c will port the Tesla session crypto (P-256 ECDH against the
// car's ephemeral pubkey from SessionInfo, AES-GCM under the derived
// key, HMAC counter) into TypeScript. The wire shape on this file
// stays the same: client posts bytes, gets bytes back.
package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// bleSessionTTL is how long a session can sit idle before the reaper
// closes it. 5 min matches Tesla's own BLE session timeout window
// reasonably well — long enough for a multi-command UX flow, short
// enough that a stuck client doesn't pin the BLE adapter overnight.
const bleSessionTTL = 5 * time.Minute

// bleSessionDefaultTimeout is the per-Exchange wait if the caller
// doesn't pass timeout_ms. Tesla BLE round-trips are usually 300-800
// ms; 5 s is a generous upper bound that catches transient stalls
// without holding the HTTP request open absurdly long.
const bleSessionDefaultTimeout = 5 * time.Second

// bleSessionMaxTimeout caps per-Exchange waits so a misbehaving
// client can't tie up the BLE radio + HTTP worker indefinitely.
const bleSessionMaxTimeout = 30 * time.Second

// BLESession is the public-facing description returned by Open. The
// raw connection is intentionally NOT exported — Exchange / Close are
// the only operations external callers can perform.
type BLESession struct {
	ID  string `json:"session_id"`
	VIN string `json:"vin"`
}

// bleConn is the minimal surface Exchange/runPump need from a BLE
// connection. *ble.Connection (github.com/teslamotors/vehicle-command
// /pkg/connector/ble) satisfies it structurally, so production code
// is unaffected; tests substitute a fake so the pump/demux logic is
// exercisable without a real BLE radio.
type bleConn interface {
	Receive() <-chan []byte
	Send(ctx context.Context, payload []byte) error
}

// frameWaiter is one in-flight Exchange call's registration with the
// session's pump: "deliver me the frame whose correlator matches
// wantAddr/wantUUID." Both empty means "match anything" — the
// defensive fallback preserved from the pre-pump Exchange for
// outgoing payloads that (unusually) carry no correlator at all.
type frameWaiter struct {
	wantAddr []byte
	wantUUID []byte
	deliver  chan []byte
}

// internalSession is the live bookkeeping for one open BLE link. A
// dedicated pump goroutine (runPump) is the SOLE reader of
// conn.Receive() for the session's lifetime: it demuxes each incoming
// frame to a waiting Exchange call by correlator or, failing that,
// fans it out to unsolicited subscribers (Phase 1 consumers; none
// exist yet in Phase 0, so an unmatched frame is simply dropped —
// the same outcome as today's manual skip-loop).
type internalSession struct {
	id        string
	vin       string
	conn      bleConn
	release   func() // closes conn + releases TeslaService.bleMu
	createdAt time.Time
	lastUsed  time.Time

	stop     chan struct{} // closed to tell runPump to stop, from Close/reaper
	stopOnce sync.Once
	pumpDone chan struct{} // closed when runPump has returned

	mu      sync.Mutex
	waiters []*frameWaiter
	subs    map[int]chan []byte
	subSeq  int
	closed  bool
}

// newInternalSession builds a session with its pump-support fields
// initialized. Used by Open and (with a fake conn) by tests.
func newInternalSession(id, vin string, conn bleConn, release func()) *internalSession {
	now := time.Now()
	return &internalSession{
		id:        id,
		vin:       vin,
		conn:      conn,
		release:   release,
		createdAt: now,
		lastUsed:  now,
		stop:      make(chan struct{}),
		pumpDone:  make(chan struct{}),
		subs:      make(map[int]chan []byte),
	}
}

// BLESessionService manages the at-most-one active BLE session. Held
// by services.Services; consumed by the /api/ble/sessions handlers.
//
// Construction needs a TeslaService reference because Open routes
// through AcquireBLEForVIN. We don't embed TeslaService — composition,
// not inheritance, so the public surface stays narrow.
type BLESessionService struct {
	tesla *TeslaService

	mu       sync.Mutex
	sessions map[string]*internalSession // 0 or 1 entries; bleMu serialises
}

// NewBLESessionService wires the service.
func NewBLESessionService(t *TeslaService) *BLESessionService {
	return &BLESessionService{
		tesla:    t,
		sessions: make(map[string]*internalSession),
	}
}

// Sentinel errors so handlers can map to HTTP codes precisely.
var (
	ErrBLESessionNotFound = errors.New("BLE session not found")
	ErrBLESessionTimeout  = errors.New("BLE session exchange timed out waiting for response")
)

// Open scans for the given VIN and opens a fresh BLE connection. If
// vin is empty, falls back to TeslaService's configured VIN. Returns
// the session metadata on success — the caller drives subsequent
// Exchange + Close by session ID.
//
// Holds bleMu for the session's lifetime. If a session already exists
// (forgotten by a previous client), Open blocks on bleMu until that
// session is reaped — there's no "take over" semantic because we
// don't know whether the previous client is mid-command.
func (s *BLESessionService) Open(ctx context.Context, vin string) (*BLESession, error) {
	if vin == "" {
		v, err := s.tesla.RequireVIN()
		if err != nil {
			return nil, err
		}
		vin = v
	}

	conn, release, err := s.tesla.AcquireBLEForVIN(ctx, vin)
	if err != nil {
		return nil, err
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		release()
		return nil, fmt.Errorf("session id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	sess := newInternalSession(id, vin, conn, release)
	go sess.runPump()

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()

	log.Printf("[BLE-SESSION] opened %s (vin=%s)", id, vin)
	go s.reaper(id)

	return &BLESession{ID: id, VIN: vin}, nil
}

// Exchange sends payload over the BLE link and returns the response
// frame addressed to the routing_address (or, when that's absent,
// the uuid) carried in the outgoing payload. Caller is responsible
// for the payload being a well-formed RoutableMessage — we DO peek
// at it (fields 7 and 51) to know what to match against on the way
// back.
//
// Why we demux rather than returning the first frame: in practice
// the car often pushes asynchronous frames (VCSEC unsolicited
// notifications, late responses to prior commands, fragmented
// responses split across BLE notifications) into the BLE receive
// channel. A naive "return next frame" semantic delivers those
// to the caller as if they were the response to the current request,
// the client's AES-GCM decrypt fails because the AAD's REQUEST_HASH
// doesn't match, and the user sees a perpetual "Pi returned stale
// response" / decrypt-failure loop with no way out. Filtering here
// is the actual fix; the client doesn't have enough information to
// recover this on its own (each retry just adds another late-frame
// to the queue).
//
// Why route_address is the primary correlator and not request_uuid:
// the upstream Tesla SDK (internal/dispatcher/dispatcher.go) uses
// a per-request random routing_address for VCSEC, and only sets
// request_uuid in responses for NON-VCSEC domains. VCSEC GET_STATUS
// replies (used by every closure/lock state read) come back with
// to_destination.routing_address set and request_uuid empty — so a
// uuid-only filter swallows them and Verify perpetually times out.
// Matching by to_destination.routing_address works for both VCSEC
// and Infotainment and for the SessionInfo handshake.
//
// The actual demux now happens in the session's pump goroutine
// (runPump), which is the sole reader of conn.Receive(). Exchange
// just registers a frameWaiter describing the correlator it wants,
// sends, and waits on that waiter's private deliver channel. Frames
// that don't match any waiter (unsolicited broadcasts, stale
// late-arrivals) are routed to unsolicited subscribers by the pump
// instead of being handed to us — so no drain/skip loop is needed
// here anymore; the pump owns routing.
//
// Updates lastUsed so the reaper's TTL clock resets.
func (s *BLESessionService) Exchange(ctx context.Context, id string, payload []byte, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = bleSessionDefaultTimeout
	}
	if timeout > bleSessionMaxTimeout {
		timeout = bleSessionMaxTimeout
	}

	sess, err := s.get(id)
	if err != nil {
		return nil, err
	}

	// Extract correlators from our outgoing RoutableMessage:
	//   wantAddr = fromDestination.routing_address (field 7 → 2)
	//   wantUUID = uuid (field 51)
	// The car copies our fromDestination into the response's
	// toDestination, and (for non-VCSEC domains) our uuid into
	// request_uuid. Either is enough to claim the frame as ours.
	wantAddr := extractRoutableFromRoutingAddress(payload)
	wantUUID := extractRoutableUUID(payload)

	waiter, err := sess.registerWaiter(wantAddr, wantUUID)
	if err != nil {
		return nil, err
	}

	if err := sess.conn.Send(ctx, payload); err != nil {
		sess.unregisterWaiter(waiter)
		return nil, fmt.Errorf("BLE send: %w", err)
	}

	deadline := time.After(timeout)
	select {
	case resp, ok := <-waiter.deliver:
		if !ok {
			return nil, errors.New("BLE connection closed")
		}
		s.touch(id)
		return resp, nil
	case <-deadline:
		sess.unregisterWaiter(waiter)
		return nil, ErrBLESessionTimeout
	case <-ctx.Done():
		sess.unregisterWaiter(waiter)
		return nil, ctx.Err()
	}
}

// runPump is the SOLE reader of s.conn.Receive() for the session's
// lifetime, started by Open right after the session is created. Every
// incoming frame is routed to at most one destination: a matching
// frameWaiter (removed once delivered) or, failing that, every
// unsolicited subscriber. Both deliveries are non-blocking sends —
// a slow or absent consumer never blocks the pump or wedges the BLE
// link; frames are dropped (and logged) instead.
//
// Two independent shutdown signals are recognized:
//   - s.stop, closed by Close()/reaper() when the session is torn
//     down. This is the primary path in practice: the vehicle-command
//     SDK's *ble.Connection.Close() does not close its inbox channel,
//     so conn.Receive() returning closed can't be relied on to ever
//     happen for the real connector.
//   - conn.Receive() itself closing (ok == false) — kept for fakes/
//     future connectors that do close it, and exercised by the P0.T2
//     test.
//
// Either path runs shutdownPump exactly once (closing all outstanding
// deliver + subscriber channels so nothing blocks forever) and closes
// pumpDone so callers can observe the pump has fully stopped.
func (s *internalSession) runPump() {
	defer close(s.pumpDone)
	for {
		select {
		case frame, ok := <-s.conn.Receive():
			if !ok {
				s.shutdownPump()
				return
			}
			s.routeFrame(frame)
		case <-s.stop:
			s.shutdownPump()
			return
		}
	}
}

// routeFrame delivers one frame read by runPump to the first matching
// waiter, or — if none matches — fans it out to every unsolicited
// subscriber.
func (s *internalSession) routeFrame(frame []byte) {
	gotAddr := extractRoutableToRoutingAddress(frame)
	gotUUID := extractRoutableRequestUUID(frame)

	s.mu.Lock()
	matched := -1
	for i, w := range s.waiters {
		noCorrelator := len(w.wantAddr) == 0 && len(w.wantUUID) == 0
		addrMatch := len(w.wantAddr) != 0 && bytesEqual(gotAddr, w.wantAddr)
		uuidMatch := len(w.wantUUID) != 0 && bytesEqual(gotUUID, w.wantUUID)
		if addrMatch || uuidMatch || noCorrelator {
			matched = i
			break
		}
	}

	if matched < 0 {
		// Unsolicited (or a reply nobody's waiting on anymore, e.g.
		// after a timeout) — fan out, dropping on a full buffer.
		for subID, ch := range s.subs {
			select {
			case ch <- frame:
			default:
				log.Printf("[BLE-SESSION] subscriber %d buffer full, dropping frame for %s", subID, s.id)
			}
		}
		s.mu.Unlock()
		return
	}

	w := s.waiters[matched]
	s.waiters = append(s.waiters[:matched], s.waiters[matched+1:]...)
	s.mu.Unlock()

	select {
	case w.deliver <- frame:
	default:
		log.Printf("[BLE-SESSION] waiter delivery channel full for %s, dropping matched frame", s.id)
	}
}

// shutdownPump runs exactly once (called only from runPump, itself
// single-goroutine) when the pump is stopping. It unblocks every
// waiting Exchange call and every subscriber rather than leaving them
// to hang until their own timeout/ctx.
func (s *internalSession) shutdownPump() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, w := range s.waiters {
		close(w.deliver)
	}
	s.waiters = nil
	for subID, ch := range s.subs {
		close(ch)
		delete(s.subs, subID)
	}
}

// stopPump signals runPump to stop via s.stop. Safe to call multiple
// times (Close + a racing reaper tick, for instance) — sync.Once
// makes the channel close idempotent.
func (s *internalSession) stopPump() {
	s.stopOnce.Do(func() { close(s.stop) })
}

// registerWaiter adds a frameWaiter for the given correlator pair.
// The deliver channel is buffered (cap 1) so runPump's send never
// blocks even if Exchange hasn't reached its select yet.
func (s *internalSession) registerWaiter(wantAddr, wantUUID []byte) (*frameWaiter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("BLE connection closed before send")
	}
	w := &frameWaiter{wantAddr: wantAddr, wantUUID: wantUUID, deliver: make(chan []byte, 1)}
	s.waiters = append(s.waiters, w)
	return w, nil
}

// unregisterWaiter removes a waiter that timed out or whose caller
// gave up (ctx.Done) before the pump matched it. A no-op if the pump
// already matched and removed it first — whichever side gets there
// first wins, and there's no double-delivery either way since the
// pump only sends after removing.
func (s *internalSession) unregisterWaiter(w *frameWaiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ww := range s.waiters {
		if ww == w {
			s.waiters = append(s.waiters[:i], s.waiters[i+1:]...)
			break
		}
	}
}

// subscribe registers an unsolicited-frame fan-out channel (Phase 1:
// the WebSocket forwarder will call this). Returns an id for
// unsubscribe and a receive-only channel with a small buffer — a slow
// or absent consumer never blocks the pump; frames are dropped
// instead. If the pump has already shut down, returns an
// already-closed channel so a caller's range/receive loop ends
// immediately instead of hanging.
func (s *internalSession) subscribe() (int, <-chan []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.subSeq
	s.subSeq++
	ch := make(chan []byte, 8)
	if s.closed {
		close(ch)
		return id, ch
	}
	s.subs[id] = ch
	return id, ch
}

// unsubscribe removes and closes the named subscriber channel. A
// no-op if the pump already closed it (session torn down first).
func (s *internalSession) unsubscribe(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.subs[id]; ok {
		delete(s.subs, id)
		close(ch)
	}
}

// extractRoutableUUID pulls field 51 (uuid, LEN) out of a
// RoutableMessage protobuf. Returns nil if not present.
//
// Tag for field 51 wire-type 2 (LEN): (51<<3)|2 = 410 = 0x9A 0x03
// varint-encoded.
func extractRoutableUUID(buf []byte) []byte {
	return scanProtoField(buf, 51, 2)
}

// extractRoutableRequestUUID pulls field 50 (request_uuid, LEN) out
// of a RoutableMessage protobuf. Returns nil if not present.
//
// Tag for field 50 wire-type 2 (LEN): (50<<3)|2 = 402 = 0x92 0x03
// varint-encoded.
func extractRoutableRequestUUID(buf []byte) []byte {
	return scanProtoField(buf, 50, 2)
}

// extractRoutableFromRoutingAddress pulls
// from_destination.routing_address out of a RoutableMessage.
// fromDestination is field 7 (Destination message, LEN); inside
// it, routing_address is field 2 of the Destination oneof.
//
// Returns nil if the sub-field isn't present (e.g. the Destination
// oneof picked `domain` instead of `routing_address`).
func extractRoutableFromRoutingAddress(buf []byte) []byte {
	from := scanProtoField(buf, 7, 2)
	if from == nil {
		return nil
	}
	return scanProtoField(from, 2, 2)
}

// extractRoutableToRoutingAddress pulls to_destination.routing_address
// out of a RoutableMessage. to_destination is field 6.
func extractRoutableToRoutingAddress(buf []byte) []byte {
	to := scanProtoField(buf, 6, 2)
	if to == nil {
		return nil
	}
	return scanProtoField(to, 2, 2)
}

// scanProtoField walks a top-level protobuf message looking for a
// specific (fieldNumber, wireType) tag and returns the bytes of the
// first matching LEN-type field. Skips unknown fields without
// recursing into sub-messages.
//
// Hand-rolled rather than using protobuf.Unmarshal because:
//  1. We don't want to pull a generated proto descriptor into the
//     byte-forwarder package, which is meant to be format-agnostic.
//  2. Decoding the full RoutableMessage would force us to track the
//     proto file across the upstream SDK, and we'd recompile every
//     time Tesla added a sub-message we don't care about. A 30-line
//     wire-format walker is cheap and stable.
func scanProtoField(buf []byte, fieldNumber, wireType int) []byte {
	i := 0
	for i < len(buf) {
		tag, n := readVarint(buf[i:])
		if n == 0 {
			return nil
		}
		i += n
		fn := int(tag >> 3)
		wt := int(tag & 0x7)
		if fn == fieldNumber && wt == wireType && wt == 2 {
			ln, m := readVarint(buf[i:])
			if m == 0 || i+m+int(ln) > len(buf) {
				return nil
			}
			i += m
			return buf[i : i+int(ln)]
		}
		// Skip the field's payload by wire type.
		switch wt {
		case 0: // varint
			_, m := readVarint(buf[i:])
			if m == 0 {
				return nil
			}
			i += m
		case 1: // 64-bit
			if i+8 > len(buf) {
				return nil
			}
			i += 8
		case 2: // LEN
			ln, m := readVarint(buf[i:])
			if m == 0 || i+m+int(ln) > len(buf) {
				return nil
			}
			i += m + int(ln)
		case 5: // 32-bit
			if i+4 > len(buf) {
				return nil
			}
			i += 4
		default:
			return nil
		}
	}
	return nil
}

// readVarint decodes a protobuf varint from buf, returning the value
// and the number of bytes consumed (0 on truncation).
func readVarint(buf []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i, b := range buf {
		v |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
		if shift >= 64 {
			return 0, 0
		}
	}
	return 0, 0
}

// bytesEqual is a tiny equality helper to avoid importing
// bytes.Equal just for two-byte-slice comparisons.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Close removes the session, closes the BLE connection, and releases
// the adapter mutex. Idempotent — closing an unknown id returns
// ErrBLESessionNotFound, but the caller can treat that as "already
// cleaned up." Phase 3 client code does this in a finally{} block so
// stuck sessions are rare in practice.
func (s *BLESessionService) Close(id string) error {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return ErrBLESessionNotFound
	}
	delete(s.sessions, id)
	s.mu.Unlock()

	sess.stopPump()
	sess.release()
	log.Printf("[BLE-SESSION] closed %s (vin=%s, lifetime=%v)",
		id, sess.vin, time.Since(sess.createdAt))
	return nil
}

// get fetches a session by id with the map mutex held. Returns
// ErrBLESessionNotFound if no such id.
func (s *BLESessionService) get(id string) (*internalSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrBLESessionNotFound
	}
	return sess, nil
}

// touch updates lastUsed on the named session. Used by Exchange to
// keep the reaper from killing an actively-used session.
func (s *BLESessionService) touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.lastUsed = time.Now()
	}
}

// reaper background-closes the session if it sits idle past
// bleSessionTTL. Recomputes the wake time from lastUsed each cycle so
// an active session never gets killed mid-conversation. Exits once
// the session is gone — either reaped here or closed externally.
func (s *BLESessionService) reaper(id string) {
	for {
		s.mu.Lock()
		sess, ok := s.sessions[id]
		if !ok {
			s.mu.Unlock()
			return
		}
		idle := time.Since(sess.lastUsed)
		if idle >= bleSessionTTL {
			delete(s.sessions, id)
			s.mu.Unlock()
			sess.stopPump()
			sess.release()
			log.Printf("[BLE-SESSION] reaped %s (idle %v)", id, idle)
			return
		}
		// Wake up just after the next deadline.
		wait := bleSessionTTL - idle + time.Second
		s.mu.Unlock()
		time.Sleep(wait)
	}
}
