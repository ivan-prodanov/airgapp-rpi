// tesla_session.go — HTTP surface for the raw BLE byte forwarder.
//
// V4.4 Phase 3b + Phase 1 (WS events). Four endpoints, mounted under
// /api/ble:
//
//   POST   /api/ble/sessions             — open, returns {session_id, vin}
//   POST   /api/ble/sessions/{id}/exchange — body {payload_b64, timeout_ms}
//                                            returns {response_b64}
//   DELETE /api/ble/sessions/{id}        — close
//   GET    /api/ble/sessions/{id}/events?token=<bearer> — WebSocket
//                                            upgrade; streams unsolicited
//                                            frames as they arrive.
//
// Payloads are RoutableMessage protobuf bytes. The handlers don't
// parse or inspect them — they just shuttle base64-encoded bytes to
// and from the BLE radio. All Tesla-protocol semantics live in the
// client; this layer is genuinely a forwarder.
package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// eventsPingInterval is how often EventsBLE sends a WS ping to keep
// the connection alive through NAT/load-balancer idle timeouts and to
// detect a dead peer promptly instead of waiting on a TCP timeout.
const eventsPingInterval = 30 * time.Second

// eventsWriteTimeout bounds each individual WS write/ping so a stalled
// peer can't wedge the handler goroutine (and, transitively, hold the
// session's subscriber slot) forever.
const eventsWriteTimeout = 10 * time.Second

// OpenBLESession creates a fresh BLE link and registers it in the
// session map. Only one session can be open at a time per Pi — see
// BLESessionService for the bleMu reasoning. Empty VIN in the request
// body falls back to the Pi's configured VIN.
func (h *TeslaHandler) OpenBLESession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		VIN string `json:"vin"`
	}
	// Tolerant decode — an empty body is fine; we just want VIN if
	// it's there.
	_ = decodeJSON(r, &body)

	ctx, cancel := teslaCtx(r, 30*time.Second)
	defer cancel()

	sess, err := h.bleSess.Open(ctx, body.VIN)
	if err != nil {
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if user := GetUser(r); user != nil && h.audit != nil {
		h.audit.Log("tesla.ble_session_open",
			user.Username+" opened BLE session "+sess.ID+" (vin="+sess.VIN+")")
	}
	JSON(w, http.StatusOK, sess)
}

// ExchangeBLE sends one payload over the active session and returns
// the first response frame. The handler doesn't enforce any structure
// on payload — the client is expected to be sending well-formed
// RoutableMessage protobufs (whatever crypto.subtle has produced).
//
// timeout_ms is optional; we clamp to [0, 30000] and default to 5000.
// The HTTP context gets timeout+5s so the handler outlives the BLE
// wait without 502'ing on margin races.
func (h *TeslaHandler) ExchangeBLE(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var body struct {
		PayloadB64 string `json:"payload_b64"`
		TimeoutMs  int    `json:"timeout_ms"`
	}
	if err := decodeJSON(r, &body); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, err := base64.StdEncoding.DecodeString(body.PayloadB64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid base64 in payload_b64: "+err.Error())
		return
	}

	timeout := time.Duration(body.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}

	ctx, cancel := teslaCtx(r, timeout+5*time.Second)
	defer cancel()

	resp, err := h.bleSess.Exchange(ctx, id, payload, timeout)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrBLESessionNotFound):
			JSONError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, services.ErrBLESessionTimeout):
			JSONError(w, http.StatusGatewayTimeout, err.Error())
		default:
			JSONError(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	JSON(w, http.StatusOK, map[string]string{
		"response_b64": base64.StdEncoding.EncodeToString(resp),
	})
}

// CloseBLESession tears down the session — closes the BLE link and
// releases the adapter mutex. Idempotent from the caller's POV: a
// 404 means "already closed or never existed."
func (h *TeslaHandler) CloseBLESession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.bleSess.Close(id); err != nil {
		if errors.Is(err, services.ErrBLESessionNotFound) {
			JSONError(w, http.StatusNotFound, err.Error())
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user := GetUser(r); user != nil && h.audit != nil {
		h.audit.Log("tesla.ble_session_close",
			user.Username+" closed BLE session "+id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// eventsFrame is the sole message shape EventsBLE ever sends: one
// unsolicited BLE frame, base64-encoded, per WS text message.
type eventsFrame struct {
	FrameB64 string `json:"frame_b64"`
}

// EventsBLE upgrades to a WebSocket and streams the session's
// unsolicited frames (VCSEC status pushes — closure/lock changes,
// etc.) as they arrive, one JSON text message per frame:
// {"frame_b64": "<base64>"}.
//
// Auth is deliberately NOT delegated to BLEBearerRequired: this route
// is registered outside that middleware's group (see router.go)
// because the RN WebSocket client has no way to set an Authorization
// header on the upgrade request. Instead the bearer travels as a
// `?token=` query param, and this handler validates it itself, using
// the exact same h.tokens.Validate comparison BLEBearerRequired uses
// for the header-based routes — so a query-param bearer gets no
// weaker a check than a header one. We re-derive this even though
// nothing else currently guards the route, precisely so that adding
// or moving middleware later can't silently make this the ONLY check
// and then have someone assume it doesn't need one.
//
// Auth and session-lookup failures both return a plain HTTP error
// BEFORE the WS upgrade — once websocket.Accept succeeds we can no
// longer send a normal status code, only close the socket, so both
// checks must happen first.
func (h *TeslaHandler) EventsBLE(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if _, err := h.tokens.Validate(token); err != nil {
		// Deliberately generic, same as BLEBearerRequired: don't
		// distinguish missing/malformed/unknown/revoked, and never
		// log the token itself.
		JSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	id := chi.URLParam(r, "id")
	subID, ch, err := h.bleSess.Subscribe(id)
	if err != nil {
		if errors.Is(err, services.ErrBLESessionNotFound) {
			JSONError(w, http.StatusNotFound, err.Error())
			return
		}
		JSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Callers are mobile/RN clients or ad-hoc tools (websocat),
		// not browser pages relying on same-origin cookies — the
		// resource is bearer-gated the same way the REST endpoints
		// are (see BLECORS's identical reasoning), so Origin doesn't
		// add anything and would only break non-browser clients that
		// don't send one.
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		// Upgrade failed (e.g. not a WS request at all) — nothing
		// sent yet, and we haven't consumed the subscriber slot in a
		// way that outlives this request, so just release it.
		h.bleSess.Unsubscribe(id, subID)
		return
	}
	defer func() {
		h.bleSess.Unsubscribe(id, subID)
		c.CloseNow()
	}()

	// We never expect data frames from the client. CloseRead spins up
	// a background reader that discards anything the peer sends,
	// answers pings/pongs, and — critically — cancels the returned
	// context the moment the peer closes the connection or the
	// underlying read fails. That's our sole signal for "client
	// disconnected" since this handler otherwise only ever writes.
	//
	// DETACH from r.Context() first: the root chi middleware.Timeout(30s)
	// deadlines every request, which for a normal REST call is fine but would
	// tear down this LONG-LIVED WebSocket every 30s (observed on-device as a
	// steady 30s reconnect churn). WithoutCancel keeps request-scoped values
	// but drops the deadline, so the stream lives until the peer disconnects
	// (CloseRead cancels ctx) or the session's pump closes the subscription.
	ctx := c.CloseRead(context.WithoutCancel(r.Context()))

	ticker := time.NewTicker(eventsPingInterval)
	defer ticker.Stop()

	for {
		select {
		case frame, ok := <-ch:
			if !ok {
				// Session closed/reaped — its pump closed every
				// subscriber channel on shutdown.
				return
			}
			payload, err := json.Marshal(eventsFrame{FrameB64: base64.StdEncoding.EncodeToString(frame)})
			if err != nil {
				log.Printf("[BLE-EVENTS] marshal frame for session %s: %v", id, err)
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, eventsWriteTimeout)
			err = c.Write(wctx, websocket.MessageText, payload)
			cancel()
			if err != nil {
				return
			}
		case <-ticker.C:
			wctx, cancel := context.WithTimeout(ctx, eventsWriteTimeout)
			err := c.Ping(wctx)
			cancel()
			if err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
