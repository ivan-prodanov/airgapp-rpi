package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Installing Tailscale takes longer than the 30 s every other request gets.
func TestTimeoutSkipsInstall(t *testing.T) {
	var deadline time.Time
	var has bool
	h := requestTimeout(30*time.Second, "/api/remote/install")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, has = r.Context().Deadline()
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/remote/install", nil))
	if has {
		t.Fatalf("install has a request deadline (%v)", time.Until(deadline))
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/devices", nil))
	if !has || time.Until(deadline) > 30*time.Second {
		t.Fatalf("other routes: deadline %v, has %v", time.Until(deadline), has)
	}
}
