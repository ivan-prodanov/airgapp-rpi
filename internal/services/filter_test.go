package services

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

// dnsAllowed is the global allow-list as DNS builds it.
func dnsAllowed(t *testing.T, db *sql.DB) []string {
	t.Helper()
	got, err := NewDNSService(db, executor.New(true), config.Config{DNSUpstream: "1.1.1.1"}).allowedDomains()
	if err != nil {
		t.Fatalf("allowedDomains: %v", err)
	}
	return got
}

// TestCreateDomain_Protected verifies the filter-domain safety floor:
// protected Tesla endpoints (and broad parents) are rejected outright.
// (Domains have no switch of their own since v27, and the note is optional.)
func TestCreateDomain_Protected(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	fID := freshFilter(t, db, "FilterTest")

	// Protected Tesla endpoints are rejected — a misclick never lands.
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
}

// TestSystemFilterCannotBeDeleted — the seeded Tesla AP/Nav (and the
// other system filters) must not be removable via the API. They can
// still be edited or extended.
func TestSystemFilterCannotBeDeleted(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	id := filterID(t, db, "Navigation") // v28 merged Nav and Maps
	if err := fs.Delete(id); !errors.Is(err, ErrSystemFilter) {
		t.Errorf("Delete(Navigation) = %v, want ErrSystemFilter", err)
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
	if _, err := fs.CreateDomain(fID, models.FilterDomain{
		Domain: "stream.example.com", Description: "test",
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	// Filter off → domain is NOT in the global allow list.
	if err := fs.SetEnabled(fID, false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	got := dnsAllowed(t, db)
	for _, d := range got {
		if d == "stream.example.com" {
			t.Errorf("domain leaked into allow-list while filter is OFF: %v", got)
		}
	}

	// Filter on → domain IS in the global allow list.
	if err := fs.SetEnabled(fID, true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	got = dnsAllowed(t, db)
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
// v24 description (Connectivity's since v29), so the UI lists each port as
// its own justified row.
func TestListAndGetSurfaceFilterPorts(t *testing.T) {
	db := memDB(t) // migrations incl. v23 (ports) + v24 (descriptions)
	fs := NewFilterService(db)

	all, err := fs.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	car := filterByName(t, all, "Connectivity")

	// UDP first then TCP, each ascending: UDP 443, UDP 19302, TCP 5228.
	want := []models.FilterPort{
		{Proto: "UDP", Port: 443},
		{Proto: "UDP", Port: 19302},
		{Proto: "TCP", Port: 5228},
	}
	if len(car.Ports) != len(want) {
		t.Fatalf("Connectivity has %d ports, want %d (%v)", len(car.Ports), len(want), car.Ports)
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
	if nav := filterByName(t, all, "Navigation"); len(nav.Ports) != 0 {
		t.Errorf("Navigation should have no ports, got %v", nav.Ports)
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

// A domain's note is optional: an allow-list entry no longer needs a written
// justification to be added.
func TestCreateDomain_NoteOptional(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	fID := freshFilter(t, db, "NoteTest")
	if _, err := fs.CreateDomain(fID, models.FilterDomain{Domain: "cdn.example.com"}); err != nil {
		t.Errorf("CreateDomain without a note: %v", err)
	}
}

// A pasted URL, a wildcard or a trailing dot is stored as the bare host.
func TestCreateDomain_Normalises(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	fID := freshFilter(t, db, "NormTest")
	for raw, want := range map[string]string{
		"https://CDN.Example.com:443/path?q=1#x": "cdn.example.com",
		"*.media.example.com.":                   "media.example.com",
	} {
		id, err := fs.CreateDomain(fID, models.FilterDomain{Domain: raw})
		if err != nil {
			t.Errorf("CreateDomain(%q): %v", raw, err)
			continue
		}
		var got string
		db.QueryRow(`SELECT domain FROM filter_domains WHERE id = ?`, id).Scan(&got)
		if got != want {
			t.Errorf("CreateDomain(%q) stored %q, want %q", raw, got, want)
		}
	}
}

// Rejections speak the design's words: the Filters page shows them as they are.
func TestCreateDomain_Messages(t *testing.T) {
	db := memDB(t)
	fs := NewFilterService(db)
	fID := freshFilter(t, db, "MsgTest")
	if _, err := fs.CreateDomain(fID, models.FilterDomain{Domain: "dup.example.com"}); err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]string{
		"not a domain!":                "Enter a domain like cdn.example.com.",
		"hermes-prd.ap.tesla.services": "hermes-prd.ap.tesla.services is always blocked. It can't be allowed.",
		"tesla.services":               "tesla.services is too broad: it would also allow always-blocked Tesla domains. Add the exact subdomain instead.",
		"dup.example.com":              "dup.example.com is already in MsgTest.",
	} {
		_, err := fs.CreateDomain(fID, models.FilterDomain{Domain: raw})
		if err == nil || err.Error() != want {
			t.Errorf("CreateDomain(%q) error = %v, want %q", raw, err, want)
		}
	}
}
