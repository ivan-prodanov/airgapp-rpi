package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// errNotImplemented marks the unused-by-these-tests corners of
// fakeBLESessions — Open/Exchange/Close are never called by EventsBLE
// or its tests, but the bleSessions interface requires them.
var errNotImplemented = errors.New("not implemented in fake")

// fakeBLESessions is a minimal bleSessions implementation for
// EventsBLE tests — no real BLE adapter involved. Only Subscribe/
// Unsubscribe are exercised by the events path; Open/Exchange/Close
// are stubbed since the interface requires them.
type fakeBLESessions struct {
	subChans map[string]chan []byte
	subErrs  map[string]error

	// currentID/currentLive back CurrentSession — set them to model a live
	// watcher-held session for the PairExternalPubkey preemption tests.
	currentID   string
	currentLive bool

	mu          sync.Mutex
	unsubCalled []string
	closeCalled []string
}

func (f *fakeBLESessions) Open(ctx context.Context, vin string) (*services.BLESession, error) {
	return nil, errNotImplemented
}

func (f *fakeBLESessions) Exchange(ctx context.Context, id string, payload []byte, timeout time.Duration) ([]byte, error) {
	return nil, errNotImplemented
}

func (f *fakeBLESessions) Close(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalled = append(f.closeCalled, id)
	return nil
}

// CurrentSession reports the fake's configured live-session id, if any —
// set currentID/currentLive to model a watcher-held session.
func (f *fakeBLESessions) CurrentSession() (string, bool) {
	return f.currentID, f.currentLive
}

func (f *fakeBLESessions) Subscribe(id string) (int, <-chan []byte, error) {
	if err, ok := f.subErrs[id]; ok {
		return 0, nil, err
	}
	ch, ok := f.subChans[id]
	if !ok {
		return 0, nil, services.ErrBLESessionNotFound
	}
	return 1, ch, nil
}

func (f *fakeBLESessions) Unsubscribe(id string, subID int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unsubCalled = append(f.unsubCalled, id)
}

// newTestTokenService builds a real TeslaTokenService against a
// throwaway sqlite file (WAL mode needs a real file, not :memory:) so
// tests exercise the exact same Validate() path BLEBearerRequired and
// EventsBLE both use — no faking of the auth comparison itself.
func newTestTokenService(t *testing.T) *services.TeslaTokenService {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return services.NewTeslaTokenService(db)
}

func newEventsTestServer(t *testing.T, h *TeslaHandler) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/api/ble/sessions/{id}/events", h.EventsBLE)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func wsURL(srv *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + path
}

func TestEventsBLE_BadToken_Returns401NoUpgrade(t *testing.T) {
	tokens := newTestTokenService(t)
	if _, err := tokens.Issue("phone"); err != nil {
		t.Fatalf("issue token: %v", err)
	}

	h := &TeslaHandler{tokens: tokens, bleSess: &fakeBLESessions{}}
	srv := newEventsTestServer(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, wsURL(srv, "/api/ble/sessions/abc/events?token=totally-wrong"), nil)
	if err == nil {
		conn.CloseNow()
		t.Fatalf("expected dial to fail on bad token, it succeeded")
	}
	if resp == nil {
		t.Fatalf("expected a non-nil HTTP response on dial failure, got nil (err=%v)", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestEventsBLE_UnknownSession_Returns404NoUpgrade(t *testing.T) {
	tokens := newTestTokenService(t)
	issue, err := tokens.Issue("phone")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	fake := &fakeBLESessions{
		subErrs: map[string]error{"missing-id": services.ErrBLESessionNotFound},
	}
	h := &TeslaHandler{tokens: tokens, bleSess: fake}
	srv := newEventsTestServer(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, wsURL(srv, "/api/ble/sessions/missing-id/events?token="+issue.Plain), nil)
	if err == nil {
		conn.CloseNow()
		t.Fatalf("expected dial to fail on unknown session, it succeeded")
	}
	if resp == nil || resp.StatusCode != 404 {
		status := -1
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("status = %d, want 404 (err=%v)", status, err)
	}
}

func TestEventsBLE_GoodTokenAndSession_StreamsFrame(t *testing.T) {
	tokens := newTestTokenService(t)
	issue, err := tokens.Issue("phone")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	ch := make(chan []byte, 1)
	fake := &fakeBLESessions{subChans: map[string]chan []byte{"sess-1": ch}}
	h := &TeslaHandler{tokens: tokens, bleSess: fake}
	srv := newEventsTestServer(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, wsURL(srv, "/api/ble/sessions/sess-1/events?token="+issue.Plain), nil)
	if err != nil {
		t.Fatalf("dial failed: %v (status=%v)", err, resp)
	}
	defer conn.CloseNow()

	knownFrame := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03}
	ch <- knownFrame

	readCtx, readCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readCancel()
	_, data, err := conn.Read(readCtx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}

	var got eventsFrame
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	want := base64.StdEncoding.EncodeToString(knownFrame)
	if got.FrameB64 != want {
		t.Fatalf("frame_b64 = %q, want %q", got.FrameB64, want)
	}

	conn.Close(websocket.StatusNormalClosure, "")
}

// newTestTeslaService builds a real *services.TeslaService against a
// throwaway sqlite file (mirrors newTestTokenService above). No VIN is
// configured, so RequestPairingExternal fails fast on requireVIN — well
// before it would touch a real BLE adapter — which is exactly what lets
// TestPairExternalPubkey_PreemptsLiveSession exercise the handler's
// preemption step without any BLE fake.
func newTestTeslaService(t *testing.T) *services.TeslaService {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test-tesla.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	audit := services.NewAuditService(db)
	return services.NewTeslaService(db, audit)
}

// validPubkeyB64 is a syntactically valid (but not car-registered) 65-byte
// SEC1-uncompressed P-256 point, base64-encoded, so it passes
// PairExternalPubkey's format check and reaches RequestPairingExternal.
func validPubkeyB64() string {
	pub := make([]byte, 65)
	pub[0] = 0x04
	return base64.StdEncoding.EncodeToString(pub)
}

// TestPairExternalPubkey_PreemptsLiveSession proves the fix for the
// key-enrollment starvation regression: TeslaService.sendUnauthenticated
// (which RequestPairingExternal uses) takes bleMu with no preemption of its
// own, and the lockwatch watcher now holds a BLE session open indefinitely
// by design — so without an explicit preempt here, enrollment would block
// on bleMu forever behind a session nothing ever closes.
//
// RequestPairingExternal itself is NOT faked — it's a concrete
// *services.TeslaService method, and with no VIN configured it fails fast on
// requireVIN (no real BLE touched), so this test can run the real handler
// path end-to-end and still assert deterministically and quickly. Per the
// task's guidance, this only asserts the preemption step (Close called with
// the live session id) rather than faking the whole BLE SDK to observe
// enrollment's outcome.
func TestPairExternalPubkey_PreemptsLiveSession(t *testing.T) {
	fake := &fakeBLESessions{currentID: "sess-live", currentLive: true}
	h := &TeslaHandler{tesla: newTestTeslaService(t), bleSess: fake}

	body, _ := json.Marshal(map[string]string{"public_key_b64": validPubkeyB64()})
	req := httptest.NewRequest(http.MethodPost, "/api/ble/pair/external-pubkey", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.PairExternalPubkey(w, req)

	fake.mu.Lock()
	closed := append([]string(nil), fake.closeCalled...)
	fake.mu.Unlock()

	if len(closed) != 1 || closed[0] != "sess-live" {
		t.Fatalf("Close calls = %v, want exactly [\"sess-live\"] (enrollment must preempt the live session before proceeding)", closed)
	}

	// Not the point of this test, but confirm we actually reached
	// RequestPairingExternal (no VIN configured → 502) rather than bailing
	// out earlier for an unrelated reason.
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d (expected a requireVIN failure past the preemption step)", w.Code, http.StatusBadGateway)
	}
}

// TestPairExternalPubkey_NoLiveSession_DoesNotCloseAnything guards against
// over-eager preemption: when CurrentSession reports nothing live, the
// handler must not call Close at all.
func TestPairExternalPubkey_NoLiveSession_DoesNotCloseAnything(t *testing.T) {
	fake := &fakeBLESessions{}
	h := &TeslaHandler{tesla: newTestTeslaService(t), bleSess: fake}

	body, _ := json.Marshal(map[string]string{"public_key_b64": validPubkeyB64()})
	req := httptest.NewRequest(http.MethodPost, "/api/ble/pair/external-pubkey", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.PairExternalPubkey(w, req)

	fake.mu.Lock()
	closed := append([]string(nil), fake.closeCalled...)
	fake.mu.Unlock()

	if len(closed) != 0 {
		t.Fatalf("Close calls = %v, want none (no live session to preempt)", closed)
	}
}
