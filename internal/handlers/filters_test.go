package handlers

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type filtersTest struct {
	r    *chi.Mux
	db   *sql.DB
	tl   *services.TrafficLogService
	exec *executor.Executor
}

// newFiltersTest wires the real filter, DNS, firewall, traffic and SNI
// services onto a throwaway database with a DryRun executor (it records the
// commands instead of running them).
func newFiltersTest(t *testing.T) filtersTest {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	exec := executor.New(true)
	cfg := config.Config{LANInterface: "wlan0", WANInterface: "wlan1", LANGateway: "192.168.4.1", SNIProxyPort: 8444, DNSUpstream: "1.1.1.1"}
	svc := &services.Services{
		Filter:     services.NewFilterService(db),
		Firewall:   services.NewFirewallService(db, exec, cfg),
		DNS:        services.NewDNSService(db, exec, cfg),
		Audit:      services.NewAuditService(db),
		TrafficLog: services.NewTrafficLogService(db),
	}
	svc.SNIProxy = services.NewSNIProxyService(cfg, db, svc.TrafficLog)
	h := NewFiltersHandler(svc, nil)
	r := chi.NewRouter()
	r.Route("/api/filters", func(r chi.Router) {
		r.Get("/", h.List)
		r.Put("/{id}/enabled", h.SetEnabled)
		r.Delete("/{id}", h.Delete)
		r.Post("/{id}/domains", h.CreateDomain)
		r.Delete("/domains/{domainID}", h.DeleteDomain)
	})
	return filtersTest{r, db, svc.TrafficLog, exec}
}

func (ft filtersTest) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	ft.r.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func (ft filtersTest) userFilter(t *testing.T, name string, enabled int) string {
	t.Helper()
	var id string
	if err := ft.db.QueryRow(`INSERT INTO filters (name, description, is_system, enabled) VALUES (?, '', 0, ?) RETURNING id`, name, enabled).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// Turning a filter on reaches the traffic classifier (and the SNI proxy) at
// once, not on the next 30 s refresh.
func TestSetEnabledTakesEffectNow(t *testing.T) {
	ft := newFiltersTest(t)
	id := ft.userFilter(t, "Live", 0)
	if _, err := ft.db.Exec(`INSERT INTO filter_domains (preset_id, domain) VALUES (?, 'ok.example')`, id); err != nil {
		t.Fatal(err)
	}
	ft.tl.RefreshAllowCache()
	if ft.tl.IsAllowListed("ok.example") {
		t.Fatal("allow-listed before the filter is on")
	}
	if rec := ft.do(t, "PUT", "/api/filters/"+id+"/enabled", `{"enabled":true}`); rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	if !ft.tl.IsAllowListed("ok.example") {
		t.Error("turning the filter on did not reach the allow cache")
	}
}

// Deleting a user filter that owns a port re-applies the firewall, so the
// port closes now (ports can belong to user filters since v29).
func TestDeleteFilterReappliesFirewall(t *testing.T) {
	ft := newFiltersTest(t)
	id := ft.userFilter(t, "Tunes", 1)
	if _, err := ft.db.Exec(`INSERT INTO filter_tcp_ports (preset_id, port) VALUES (?, 4070)`, id); err != nil {
		t.Fatal(err)
	}
	before := len(ft.exec.Recorded())
	if rec := ft.do(t, "DELETE", "/api/filters/"+id, ""); rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	applied := false
	for _, c := range ft.exec.Recorded()[before:] {
		if strings.HasPrefix(c, "nft ") {
			applied = true
		}
	}
	if !applied {
		t.Errorf("no nft apply after deleting a filter with a port: %v", ft.exec.Recorded()[before:])
	}
}
