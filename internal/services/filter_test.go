package services

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

func domainEnabled(t *testing.T, db *sql.DB, id int64) bool {
	t.Helper()
	var e int
	if err := db.QueryRow("SELECT enabled FROM filter_domains WHERE id = ?", id).Scan(&e); err != nil {
		t.Fatalf("read enabled for domain %d: %v", id, err)
	}
	return e == 1
}

// TestCreateDomain_DisabledAndProtectedAndDescription verifies the four
// filter-domain safety behaviours: new domains are created disabled
// (review-then-enable), protected Tesla endpoints (and broad parents)
// are rejected outright, and an empty description is rejected — every
// allow-list entry needs a justification.
func TestCreateDomain_DisabledAndProtectedAndDescription(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	// A fresh filter — the seeded Tesla AP/Nav filter already ships
	// auth.tesla.com (we'd conflict if we used it).
	fID := freshFilter(t, db, "FilterTest")

	// 1. A new domain is created DISABLED, even if the request says enabled.
	id, err := fs.CreateDomain(fID, models.FilterDomain{
		Domain: "auth.tesla.com", Description: "test OAuth", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateDomain(auth.tesla.com): %v", err)
	}
	if domainEnabled(t, db, id) {
		t.Errorf("a newly added domain was enabled — it must default to disabled")
	}

	// 2. Re-adding an already-enabled domain must NOT flip it back off.
	mustExec(t, db, "UPDATE filter_domains SET enabled = 1 WHERE id = ?", id)
	if _, err := fs.CreateDomain(fID, models.FilterDomain{
		Domain: "auth.tesla.com", Description: "second take",
	}); err != nil {
		t.Fatalf("re-add CreateDomain: %v", err)
	}
	if !domainEnabled(t, db, id) {
		t.Errorf("re-adding a domain disabled a live entry — enabled must be left untouched")
	}

	// 3. Protected Tesla endpoints are rejected — a misclick never lands.
	for _, bad := range []string{
		"hermes-prd.ap.tesla.services",
		"hermes-api.prd.eu.vn.cloud.tesla.com", // EU variant
		"tesla.services",                       // catastrophically broad
	} {
		if _, err := fs.CreateDomain(fID, models.FilterDomain{
			Domain: bad, Description: "should never land",
		}); err == nil {
			t.Errorf("CreateDomain accepted a protected/dangerous domain %q — must reject", bad)
		}
	}

	// 4. Empty / whitespace-only description is rejected.
	for _, desc := range []string{"", "   ", "\t\n"} {
		if _, err := fs.CreateDomain(fID, models.FilterDomain{
			Domain: "spotify.com", Description: desc,
		}); !errors.Is(err, ErrDescRequired) {
			t.Errorf("CreateDomain with description=%q returned %v, want ErrDescRequired", desc, err)
		}
	}
}

// TestSystemFilterCannotBeDeleted — the seeded Tesla AP/Nav (and the
// other system filters) must not be removable via the API. They can
// still be edited or extended.
func TestSystemFilterCannotBeDeleted(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	id := filterID(t, db, "Nav") // v22 renamed "Tesla AP/Nav" -> "Nav"
	if err := fs.Delete(id); !errors.Is(err, ErrSystemFilter) {
		t.Errorf("Delete(Nav) = %v, want ErrSystemFilter", err)
	}
}

// TestFilterEnabledToggleAffectsAllowedDomains — flipping a filter's
// enabled flag changes what the global allow-list returns, even though
// the underlying domain rows didn't change. This is the property the
// whole UX rework relies on.
func TestFilterEnabledToggleAffectsAllowedDomains(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	fID := freshFilter(t, db, "Streaming")

	// Add one domain and enable it.
	id, err := fs.CreateDomain(fID, models.FilterDomain{
		Domain: "stream.example.com", Description: "test",
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	mustExec(t, db, "UPDATE filter_domains SET enabled = 1 WHERE id = ?", id)

	// Filter off → domain is NOT in the global allow list.
	if err := fs.SetEnabled(fID, false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	got, _ := fs.AllEnabledDomains()
	for _, d := range got {
		if d == "stream.example.com" {
			t.Errorf("domain leaked into allow-list while filter is OFF: %v", got)
		}
	}

	// Filter on → domain IS in the global allow list.
	if err := fs.SetEnabled(fID, true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	got, _ = fs.AllEnabledDomains()
	found := false
	for _, d := range got {
		if d == "stream.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("enabled filter's domain missing from allow-list: %v", got)
	}
}

// TestListAndGetSurfaceFilterPorts verifies the filter service attaches each
// port-hole (filter_udp_ports / filter_tcp_ports) as its own entry WITH the
// v24 description, so a ports-only filter like "Car Apps" lists its ports (one
// row each, justified) instead of rendering empty.
func TestListAndGetSurfaceFilterPorts(t *testing.T) {
	db := memDB(t) // migrations incl. v23 (ports) + v24 (descriptions)
	fs := NewFilterService(db)

	all, err := fs.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	car := filterByName(t, all, "Car Apps")

	// UDP first then TCP, each ascending: UDP 443, UDP 19302, TCP 4070, TCP 5228.
	want := []models.FilterPort{
		{Proto: "UDP", Port: 443},
		{Proto: "UDP", Port: 19302},
		{Proto: "TCP", Port: 4070},
		{Proto: "TCP", Port: 5228},
	}
	if len(car.Ports) != len(want) {
		t.Fatalf("Car Apps has %d ports, want %d (%v)", len(car.Ports), len(want), car.Ports)
	}
	for i, w := range want {
		p := car.Ports[i]
		if p.Proto != w.Proto || p.Port != w.Port {
			t.Errorf("port[%d] = %s %d, want %s %d", i, p.Proto, p.Port, w.Proto, w.Port)
		}
		if p.Description == "" {
			t.Errorf("port %s %d has no description (v24 backfill missing)", p.Proto, p.Port)
		}
	}

	// Get() attaches ports with descriptions too.
	got, err := fs.Get(car.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Ports) != len(want) || got.Ports[0].Description == "" {
		t.Errorf("Get() ports = %v, want %d described entries", got.Ports, len(want))
	}

	// A domain-only filter has no ports (nil/empty), not a crash.
	if nav := filterByName(t, all, "Nav"); len(nav.Ports) != 0 {
		t.Errorf("Nav should have no ports, got %v", nav.Ports)
	}
}

func filterByName(t *testing.T, fs []models.Filter, name string) models.Filter {
	t.Helper()
	for _, f := range fs {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("filter %q not found", name)
	return models.Filter{}
}
