package services

import (
	"database/sql"
	"errors"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/iulianfsdro/rpi-network-filter/internal/database"
)

// migratedDB returns a fresh in-memory SQLite DB with all migrations
// applied — exercises the v12 FTS5/trigram + v13 muted_domains schema.
func migratedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestQueryPaginatedFTSSearch(t *testing.T) {
	svc := NewTrafficLogService(migratedDB(t))

	for _, d := range []string{
		"www.youtube.com",
		"hermes-prd.ap.tesla.services",
		"auth.tesla.com",
	} {
		svc.insertEntry(TrafficEntry{Domain: d, Action: "query", Source: "dns"})
	}

	// Substring match on a single domain.
	if r := svc.QueryPaginated(TrafficFilter{Query: "youtube"}); r.Total != 1 ||
		len(r.Entries) != 1 || r.Entries[0].Domain != "www.youtube.com" {
		t.Fatalf("search 'youtube': total=%d entries=%d", r.Total, len(r.Entries))
	}

	// Mid-string substring spanning two rows (the FTS5 trigram win).
	if r := svc.QueryPaginated(TrafficFilter{Query: "tesla"}); r.Total != 2 {
		t.Fatalf("search 'tesla': total=%d, want 2", r.Total)
	}

	// Sub-3-char query takes the LIKE fallback (trigram needs 3-grams).
	if r := svc.QueryPaginated(TrafficFilter{Query: "yo"}); r.Total != 1 {
		t.Fatalf("search 'yo' (LIKE fallback): total=%d, want 1", r.Total)
	}
}

func TestMuteDropsAtIngest(t *testing.T) {
	svc := NewTrafficLogService(migratedDB(t))

	if _, err := svc.AddMuted("tesla.services"); err != nil {
		t.Fatalf("AddMuted: %v", err)
	}
	if !svc.isMuted("hermes-prd.ap.tesla.services") {
		t.Fatal("isMuted should match a deeper subdomain of a suffix pattern")
	}

	svc.insertEntry(TrafficEntry{Domain: "hermes-prd.ap.tesla.services", Action: "query", Source: "dns"})
	svc.insertEntry(TrafficEntry{Domain: "www.youtube.com", Action: "query", Source: "dns"})

	// The muted domain's event was dropped; the other was kept.
	if r := svc.QueryPaginated(TrafficFilter{Query: "tesla"}); r.Total != 0 {
		t.Fatalf("muted domain should not be logged: total=%d", r.Total)
	}
	if r := svc.QueryPaginated(TrafficFilter{Query: "youtube"}); r.Total != 1 {
		t.Fatalf("unmuted domain should be logged: total=%d", r.Total)
	}

	// Unmuting resumes logging.
	var id int64
	if err := svc.db.QueryRow("SELECT id FROM muted_domains LIMIT 1").Scan(&id); err != nil {
		t.Fatalf("read mute id: %v", err)
	}
	if err := svc.RemoveMuted(id); err != nil {
		t.Fatalf("RemoveMuted: %v", err)
	}
	svc.insertEntry(TrafficEntry{Domain: "hermes-prd.ap.tesla.services", Action: "query", Source: "dns"})
	if r := svc.QueryPaginated(TrafficFilter{Query: "tesla"}); r.Total != 1 {
		t.Fatalf("after unmute the event should be logged: total=%d", r.Total)
	}
}

func TestDNSResolvable(t *testing.T) {
	svc := NewTrafficLogService(migratedDB(t))
	svc.allowSuffix = []string{"youtube.com", "googleapis.com"}

	cases := map[string]bool{
		"youtube.com":             true,
		"www.youtube.com":         true,
		"youtubei.googleapis.com": true,
		"notgoogle.com":           false,
		"evilyoutube.com":         false, // not a subdomain of youtube.com
	}
	for d, want := range cases {
		if got := svc.dnsResolvable(d); got != want {
			t.Errorf("dnsResolvable(%q) = %v, want %v", d, got, want)
		}
	}

	// Protected-deny wins even if an allow suffix would otherwise match.
	svc.allowSuffix = []string{"tesla.services"}
	if svc.dnsResolvable("hermes-prd.ap.tesla.services") {
		t.Error("a protected-deny domain must never classify as resolvable")
	}
}

func TestBlockedFilterIncludesSinkholed(t *testing.T) {
	svc := NewTrafficLogService(migratedDB(t))
	svc.insertEntry(TrafficEntry{Domain: "evil.example", DstPort: "443", Protocol: "TLS", Action: "blocked", Source: "forward"})
	svc.insertEntry(TrafficEntry{Domain: "telemetry.example", Action: "sinkholed", Source: "dns"})
	svc.insertEntry(TrafficEntry{Domain: "ok.example", Action: "resolved", Source: "dns"})

	// "blocked" spans forward denials AND DNS sinkholes.
	if r := svc.QueryPaginated(TrafficFilter{Action: "blocked"}); r.Total != 2 {
		t.Fatalf("blocked filter should include forward-blocked + sinkholed: total=%d, want 2", r.Total)
	}
	// Dedicated filters stay exact.
	if r := svc.QueryPaginated(TrafficFilter{Action: "sinkholed"}); r.Total != 1 {
		t.Fatalf("sinkholed filter: total=%d, want 1", r.Total)
	}
	if r := svc.QueryPaginated(TrafficFilter{Action: "resolved"}); r.Total != 1 {
		t.Fatalf("resolved filter: total=%d, want 1", r.Total)
	}
	if r := svc.QueryPaginated(TrafficFilter{Action: "all"}); r.Total != 3 {
		t.Fatalf("all filter: total=%d, want 3", r.Total)
	}
}

// The Muted dialog shows the server's words as they are.
func TestAddMuted_BadDomain(t *testing.T) {
	svc := NewTrafficLogService(migratedDB(t))
	if _, err := svc.AddMuted("not a domain!"); !errors.Is(err, ErrBadMuteDomain) {
		t.Fatalf("AddMuted(bad) = %v, want ErrBadMuteDomain", err)
	}
	if ErrBadMuteDomain.Error() != "Enter a domain like apple.com." {
		t.Fatalf("copy %q", ErrBadMuteDomain.Error())
	}
}

// The enrol host is answered by the Pi itself; its lookups are logged as
// resolved, not sinkholed.
func TestEnrolHostLoggedResolved(t *testing.T) {
	svc := NewTrafficLogService(migratedDB(t))
	if svc.dnsResolvable("airgapp.me") {
		t.Fatal("resolvable before it's a local name")
	}
	svc.SetLocalNames([]string{"airgapp.me"})
	if !svc.dnsResolvable("airgapp.me") || svc.dnsResolvable("other.example") {
		t.Fatal("local name not treated as resolved")
	}
}
