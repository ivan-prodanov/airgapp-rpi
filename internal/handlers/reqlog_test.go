package handlers

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
)

// newTestFormatter builds a RedactingLogFormatter that writes to buf instead
// of stdout, so the test can inspect exactly what would have been logged.
func newTestFormatter(buf *bytes.Buffer) *RedactingLogFormatter {
	return &RedactingLogFormatter{
		inner: &middleware.DefaultLogFormatter{
			Logger:  log.New(buf, "", 0),
			NoColor: true,
		},
	}
}

// TestRedactingLogFormatter_RedactsTokenQueryParam is the core regression
// test for the credential-to-logs disclosure: the BLE events WebSocket
// upgrade authenticates via ?token=<bearer> (RN can't set an Authorization
// header on a WS upgrade), and chi's stock middleware.Logger logs
// r.RequestURI verbatim — including the live bearer token — to the Pi's
// stdout/journal on every connection. The redacting formatter must strip
// the token's value while preserving the rest of the query string.
func TestRedactingLogFormatter_RedactsTokenQueryParam(t *testing.T) {
	var buf bytes.Buffer
	formatter := newTestFormatter(&buf)

	handler := middleware.RequestLogger(formatter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/ble/sessions/abc/events?token=SUPER-SECRET-BEARER&foo=bar", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	out := buf.String()

	if strings.Contains(out, "SUPER-SECRET-BEARER") {
		t.Fatalf("log output leaked the bearer token: %q", out)
	}
	if !strings.Contains(out, "token=REDACTED") {
		t.Fatalf("expected redacted token marker in log output, got: %q", out)
	}
	if !strings.Contains(out, "foo=bar") {
		t.Fatalf("expected non-sensitive query param to be preserved, got: %q", out)
	}
}

// TestRedactingLogFormatter_NoQueryString ensures the formatter is robust
// when there is nothing to redact — it must not panic or drop the request
// line.
func TestRedactingLogFormatter_NoQueryString(t *testing.T) {
	var buf bytes.Buffer
	formatter := newTestFormatter(&buf)

	handler := middleware.RequestLogger(formatter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/ble/pair", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	out := buf.String()
	if !strings.Contains(out, "/api/ble/pair") {
		t.Fatalf("expected request path in log output, got: %q", out)
	}
}

// TestRedactingLogFormatter_PreservesOtherParams checks that only the
// sensitive key is touched when there are several non-sensitive params
// around it.
func TestRedactingLogFormatter_PreservesOtherParams(t *testing.T) {
	var buf bytes.Buffer
	formatter := newTestFormatter(&buf)

	handler := middleware.RequestLogger(formatter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x?a=1&token=SECRET2&b=2", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	out := buf.String()
	if strings.Contains(out, "SECRET2") {
		t.Fatalf("log output leaked the token: %q", out)
	}
	for _, want := range []string{"a=1", "b=2", "token=REDACTED"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in log output, got: %q", want, out)
		}
	}
}
