package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
	"github.com/iulianfsdro/rpi-network-filter/web"
)

// System replaces Settings and Remote access; Firewall, Stats and Bandwidth
// are gone, pages and APIs both (their services and stored data stay).
func TestRoutes_SystemReplacesOldPages(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	svc := &services.Services{Auth: services.NewAuthService(db), Audit: services.NewAuditService(db)}
	h := NewRouterWithFS(db, svc, config.Config{}, web.Content)

	routes := map[string]bool{}
	if err := chi.Walk(h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !routes["GET /system"] || !routes["GET /api/system/vitals"] {
		t.Error("missing /system or /api/system/vitals")
	}
	for r := range routes {
		for _, gone := range []string{"/firewall", "/stats", "/bandwidth", "/api/system/stats", "funnel/ble/disable"} {
			if strings.Contains(strings.SplitN(r, " ", 2)[1], gone) {
				t.Errorf("route still registered: %s", r)
			}
		}
	}
	for _, old := range []string{"/settings", "/remote-access"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", old, nil))
		if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/system" {
			t.Errorf("GET %s: %d → %q, want 301 → /system", old, rec.Code, rec.Header().Get("Location"))
		}
	}
}
