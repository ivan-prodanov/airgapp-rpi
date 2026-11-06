package database

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// openMemory returns a fresh in-memory SQLite DB — no file, no fixtures.
func openMemory(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrateFreshAppliesAll(t *testing.T) {
	db := openMemory(t)

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var v int
	if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&v); err != nil {
		t.Fatalf("schema_version read: %v", err)
	}
	if v != len(migrations) {
		t.Errorf("applied version = %d, want %d", v, len(migrations))
	}
}

func TestMigrateIdempotent(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		t.Fatalf("schema_version count: %v", err)
	}
	if count != len(migrations) {
		t.Errorf("schema_version rows = %d, want %d (double-applied?)", count, len(migrations))
	}
}

// TestMigrateDropsLegacyTables verifies every legacy table from prior
// migrations is gone after the full chain runs — allowed_domains (v6),
// blocked_domains (v14), policies / policy_allowed_domains / device_policies
// (v15), dns_blocklist (v15), presets / preset_domains / device_presets
// (v16, replaced by filters / filter_domains).
func TestMigrateDropsLegacyTables(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, dead := range []string{
		"allowed_domains", "blocked_domains",
		"policies", "policy_allowed_domains", "device_policies",
		"dns_blocklist",
		"presets", "device_presets",
		"preset_domains", // renamed to filter_domains in v16
	} {
		var name string
		err := db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", dead,
		).Scan(&name)
		if err == nil {
			t.Errorf("legacy table %q still exists after migration", dead)
		} else if err != sql.ErrNoRows {
			t.Fatalf("query sqlite_master for %q: %v", dead, err)
		}
	}
}

// TestMigrateAddsDeviceStatus verifies the devices table accepts the
// three valid status values (blocked/filtered/open). The CREATE TABLE
// default is still 'unknown' from v15; upsertDevice in NetworkService
// explicitly inserts 'blocked' for fresh rows, so the user never sees a
// surfaced 'unknown' status in the UI.
func TestMigrateAcceptsAllThreeStatuses(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, s := range []string{"blocked", "filtered", "open"} {
		if _, err := db.Exec(
			`INSERT INTO devices (mac_address, status) VALUES (?, ?)`,
			"AA:BB:CC:DD:EE:"+s[:2], s,
		); err != nil {
			t.Errorf("insert status=%q rejected: %v", s, err)
		}
	}
}

// filterDomainSet returns the set of domain names attached to a filter.
func filterDomainSet(t *testing.T, db *sql.DB, filterName string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`
		SELECT fd.domain FROM filter_domains fd
		JOIN filters f ON f.id = fd.preset_id
		WHERE f.name = ?`, filterName)
	if err != nil {
		t.Fatalf("query %s domains: %v", filterName, err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[d] = true
	}
	return out
}

// TestMigrateSeedsSystemFilters verifies the five system filters exist with
// the right curated contents. Tesla AP/Nav contains the audited-safe three
// (auth.tesla.com / bare go.tesla.services / managed-charging are
// catastrophic and must never appear). Maps & Time, YouTube, Netflix, and
// Disney+ are system filters too.
func TestMigrateSeedsSystemFilters(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// v22: "Tesla AP/Nav"->"Nav", "Maps & Time"->"Maps", plus new
	// System-group filters Time / Grok / Connectivity.
	for _, want := range []string{"Nav", "Maps", "Time", "Grok", "Connectivity", "YouTube", "Netflix", "Twitch"} {
		var isSys int
		err := db.QueryRow(
			"SELECT is_system FROM filters WHERE name=?", want,
		).Scan(&isSys)
		if err != nil {
			t.Errorf("system filter %q missing: %v", want, err)
			continue
		}
		if isSys != 1 {
			t.Errorf("filter %q is_system = %d, want 1", want, isSys)
		}
	}

	// Disney+ must NOT exist after v19 — the v15 seed row was deleted.
	var disneyCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM filters WHERE name='Disney+'").Scan(&disneyCount); err != nil {
		t.Fatalf("count Disney+ filter: %v", err)
	}
	if disneyCount != 0 {
		t.Errorf("Disney+ filter still present after v19 drop: count=%d", disneyCount)
	}
	// Its domain rows must be gone too (FK isn't ON DELETE CASCADE, the
	// migration deletes them explicitly first). Check for ORPHANS — rows
	// whose preset_id no longer resolves to a filter — rather than by domain
	// name: v23's Hulu filter legitimately carries Disney/BAMTech hosts
	// (disneyplus.com, disney-plus.net, dssott.com, bamgrid.com) under the
	// Hulu+Disney bundle, so a name-based check would false-positive on those.
	var orphanDomains int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM filter_domains fd
		LEFT JOIN filters f ON f.id = fd.preset_id
		WHERE f.id IS NULL
	`).Scan(&orphanDomains); err != nil {
		t.Fatalf("count orphan domains: %v", err)
	}
	if orphanDomains != 0 {
		t.Errorf("orphaned filter_domains rows survived the Disney+ drop: %d", orphanDomains)
	}

	// Nav (v22, was "Tesla AP/Nav"): Tesla nav/driving data only. v22 moved
	// maps-eu-prd to Maps; Google maps live in Maps.
	wantNav := map[string]bool{
		"daws.tesla.services":     true,
		"apmv3.go.tesla.services": true,
	}
	gotNav := filterDomainSet(t, db, "Nav")
	if len(gotNav) != len(wantNav) {
		t.Errorf("Nav has %d domains, want exactly %d", len(gotNav), len(wantNav))
	}
	for d := range wantNav {
		if !gotNav[d] {
			t.Errorf("Nav missing %q", d)
		}
	}
	for d := range gotNav {
		if !wantNav[d] {
			t.Errorf("Nav has unexpected %q — must be Tesla-nav only", d)
		}
	}
	if gotNav["maps.googleapis.com"] || gotNav["maps-eu-prd.go.tesla.services"] {
		t.Errorf("Nav still contains a map host — v22 moved those to Maps")
	}

	// Maps (v22, was "Maps & Time"): Google map hosts + the Tesla maps
	// backend. v22 moved pool.ntp.org out to Time and maps-eu-prd in from Nav.
	wantMaps := map[string]bool{
		"mt.l.google.com":               true,
		"mt0.google.com":                true,
		"mt1.google.com":                true,
		"mt2.google.com":                true,
		"mt3.google.com":                true,
		"tile.googleapis.com":           true,
		"maps.googleapis.com":           true,
		"places.googleapis.com":         true,
		"www.googleapis.com":            true,
		"maps-eu-prd.go.tesla.services": true,
	}
	gotMaps := filterDomainSet(t, db, "Maps")
	if len(gotMaps) != len(wantMaps) {
		t.Errorf("Maps has %d domains, want exactly %d", len(gotMaps), len(wantMaps))
	}
	for d := range wantMaps {
		if !gotMaps[d] {
			t.Errorf("Maps missing %q", d)
		}
	}
	if gotMaps["pool.ntp.org"] {
		t.Errorf("Maps still has pool.ntp.org — v22 moved it to Time")
	}

	// YouTube: 14 domains after v19; v23 adds 4 more (cnrd.io, t1.cnrd.io,
	// content-autofill.googleapis.com, googleapis.com) curated live for YT
	// Music → 18. oauth2.googleapis.com, seeded disabled in v19, is flipped
	// on by v23 (see the enabled-state block below).
	wantYT := map[string]bool{
		"accounts.google.bg":              true,
		"accounts.google.com":             true,
		"fonts.googleapis.com":            true,
		"fonts.gstatic.com":               true,
		"gds.google.com":                  true,
		"ggpht.com":                       true,
		"googlevideo.com":                 true,
		"lh3.googleusercontent.com":       true, // v19
		"oauth2.googleapis.com":           true, // v19, v23 enabled it
		"www.gstatic.com":                 true, // www.google.com moved to Connectivity in v22
		"youtu.be":                        true,
		"youtube-ui.l.google.com":         true,
		"youtube.com":                     true,
		"ytimg.com":                       true,
		"cnrd.io":                         true, // v23
		"t1.cnrd.io":                      true, // v23
		"content-autofill.googleapis.com": true, // v23
		"googleapis.com":                  true, // v23
	}
	gotYT := filterDomainSet(t, db, "YouTube")
	if len(gotYT) != len(wantYT) {
		t.Errorf("YouTube has %d domains, want exactly %d", len(gotYT), len(wantYT))
	}
	for d := range wantYT {
		if !gotYT[d] {
			t.Errorf("YouTube missing %q", d)
		}
	}

	// Twitch: new system filter in v19. 9 curated CDN/endpoint hosts.
	// Idempotency check: this also covers the path where the operator
	// had created Twitch manually in the UI (is_system=0) before v19
	// ran — the UPDATE inside v19 promotes it to is_system=1.
	wantTwitch := map[string]bool{
		"ext-twitch.tv":         true,
		"jtvw.net":              true,
		"live-video.net":        true,
		"static-cdn.jtvnw.net":  true,
		"ttvnw.net":             true,
		"ttvw.net":              true,
		"twitch.map.fastly.net": true,
		"twitch.tv":             true,
		"twitchcdn.net":         true,
	}
	gotTwitch := filterDomainSet(t, db, "Twitch")
	if len(gotTwitch) != len(wantTwitch) {
		t.Errorf("Twitch has %d domains, want exactly %d", len(gotTwitch), len(wantTwitch))
	}
	for d := range wantTwitch {
		if !gotTwitch[d] {
			t.Errorf("Twitch missing %q", d)
		}
	}
	// Twitch must be marked is_system=1 (v19 promoted any pre-existing
	// user-created Twitch filter as part of the same migration).
	var twitchIsSys int
	if err := db.QueryRow("SELECT is_system FROM filters WHERE name='Twitch'").Scan(&twitchIsSys); err != nil {
		t.Fatalf("read Twitch is_system: %v", err)
	}
	if twitchIsSys != 1 {
		t.Errorf("Twitch is_system = %d, want 1 (v19 promotes manual Twitch filters too)", twitchIsSys)
	}

	// v22 System-group additions: Time, Grok, Connectivity + the coupled
	// UDP ports.
	if got := filterDomainSet(t, db, "Time"); !got["pool.ntp.org"] || len(got) != 1 {
		t.Errorf("Time domains = %v, want exactly {pool.ntp.org}", got)
	}
	gotGrok := filterDomainSet(t, db, "Grok")
	for _, d := range []string{"assistant-api.prd.euw1.vn.cloud.tesla.com", "assistant-api.prd.na.vn.cloud.tesla.com"} {
		if !gotGrok[d] {
			t.Errorf("Grok missing %q", d)
		}
	}
	if gotC := filterDomainSet(t, db, "Connectivity"); !gotC["www.google.com"] || !gotC["google.com"] {
		t.Errorf("Connectivity = %v, want www.google.com + google.com", gotC)
	}
	if filterDomainSet(t, db, "YouTube")["www.google.com"] {
		t.Errorf("www.google.com still in YouTube — v22 should have moved it to Connectivity")
	}
	for _, tc := range []struct {
		filter string
		port   int
	}{{"Time", 123}, {"Grok", 18113}} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM filter_udp_ports fup JOIN filters f ON f.id=fup.preset_id WHERE f.name=? AND fup.port=?`, tc.filter, tc.port).Scan(&n); err != nil {
			t.Fatalf("count udp port: %v", err)
		}
		if n != 1 {
			t.Errorf("%s should have exactly one udp port %d (found %d)", tc.filter, tc.port, n)
		}
	}
	// Grok ships ENABLED as of v23 (operator default; v22 shipped it off and
	// v23's UPDATE supersedes that) and stays in the System group.
	var grokEnabled int
	var grokGrp string
	if err := db.QueryRow("SELECT enabled, grp FROM filters WHERE name='Grok'").Scan(&grokEnabled, &grokGrp); err != nil {
		t.Fatalf("read Grok: %v", err)
	}
	if grokEnabled != 1 {
		t.Errorf("Grok ships enabled=%d, want 1 (v23 enabled it by default)", grokEnabled)
	}
	if grokGrp != "System" {
		t.Errorf("Grok grp=%q, want System", grokGrp)
	}

	// Seed enabled-state invariants. As of v23 every system-filter domain
	// row is enabled — v23 flipped on the last disabled one
	// (oauth2.googleapis.com in YouTube).
	enabledFilters := map[string]int{
		"Nav":          0, // 0 disabled rows
		"Maps":         0,
		"Time":         0,
		"Grok":         0, // filter enabled (v23); its domain rows are enabled too
		"Connectivity": 0,
		"Twitch":       0,
		"YouTube":      0, // v23 enabled oauth2.googleapis.com — nothing off now
	}
	for fname, wantDisabled := range enabledFilters {
		var disabled int
		if err := db.QueryRow(`
			SELECT COUNT(*) FROM filter_domains fd
			JOIN filters f ON f.id = fd.preset_id
			WHERE f.name=? AND fd.enabled = 0
		`, fname).Scan(&disabled); err != nil {
			t.Fatalf("count disabled in %s: %v", fname, err)
		}
		if disabled != wantDisabled {
			t.Errorf("%s has %d disabled rows; want exactly %d", fname, disabled, wantDisabled)
		}
	}
	// oauth2.googleapis.com: seeded disabled in v19, enabled by v23.
	var oauth2Enabled int
	if err := db.QueryRow(`
		SELECT fd.enabled FROM filter_domains fd
		JOIN filters f ON f.id = fd.preset_id
		WHERE f.name='YouTube' AND fd.domain='oauth2.googleapis.com'
	`).Scan(&oauth2Enabled); err != nil {
		t.Fatalf("read oauth2 enabled: %v", err)
	}
	if oauth2Enabled != 1 {
		t.Errorf("oauth2.googleapis.com enabled=%d, want 1 (v23 enabled it)", oauth2Enabled)
	}
}

// TestMigrateV23SeedsLiveState verifies v23 reproduces the operator's
// deployed appliance: the dashboard-built streaming/app filters and their
// domains, the new filter_tcp_ports table, and the always-on "Car Apps"
// filter that owns the car's non-HTTPS port-holes via the (car-agnostic)
// filter->port model.
func TestMigrateV23SeedsLiveState(t *testing.T) {
	db := openMemory(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// filter_tcp_ports table exists (TCP sibling of filter_udp_ports).
	var tbl string
	if err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='filter_tcp_ports'",
	).Scan(&tbl); err != nil {
		t.Fatalf("filter_tcp_ports table missing: %v", err)
	}

	// The 6 dashboard-built filters: present, user-owned, enabled.
	for _, name := range []string{"Max", "Hulu", "TikTok", "Spotify", "Prime", "F1"} {
		var isSys, enabled int
		if err := db.QueryRow("SELECT is_system, enabled FROM filters WHERE name=?", name).Scan(&isSys, &enabled); err != nil {
			t.Errorf("user filter %q missing: %v", name, err)
			continue
		}
		if isSys != 0 {
			t.Errorf("%s is_system=%d, want 0 (operator-deletable)", name, isSys)
		}
		if enabled != 1 {
			t.Errorf("%s enabled=%d, want 1", name, enabled)
		}
	}

	// Spot-check representative seeded domains under the right filter.
	for _, tc := range []struct{ filter, domain string }{
		{"Max", "max.com"}, {"Max", "hbomax.com"},
		{"Hulu", "hulu.com"}, {"Hulu", "disneyplus.com"},
		{"TikTok", "tiktok.com"}, {"Spotify", "spotify.com"},
		{"Prime", "primevideo.com"}, {"F1", "formula1.com"},
		{"Netflix", "onetrust.com"}, {"YouTube", "googleapis.com"},
		{"Grok", "speechcontainerpipeline.blob.core.windows.net"},
	} {
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM filter_domains d JOIN filters f ON f.id=d.preset_id WHERE f.name=? AND d.domain=?`,
			tc.filter, tc.domain,
		).Scan(&n); err != nil {
			t.Fatalf("domain check: %v", err)
		}
		if n != 1 {
			t.Errorf("%s should contain %q exactly once (found %d)", tc.filter, tc.domain, n)
		}
	}

	// Car Apps: always-on system filter in the System group.
	var caSys, caEnabled int
	var caGrp string
	if err := db.QueryRow("SELECT is_system, enabled, grp FROM filters WHERE name='Car Apps'").Scan(&caSys, &caEnabled, &caGrp); err != nil {
		t.Fatalf("Car Apps filter missing: %v", err)
	}
	if caSys != 1 || caEnabled != 1 || caGrp != "System" {
		t.Errorf("Car Apps is_system=%d enabled=%d grp=%q, want 1/1/System", caSys, caEnabled, caGrp)
	}

	// Car Apps owns exactly its 4 port-holes: udp 443+19302, tcp 5228+4070.
	for _, tc := range []struct {
		table string
		port  int
	}{{"filter_udp_ports", 443}, {"filter_udp_ports", 19302}, {"filter_tcp_ports", 5228}, {"filter_tcp_ports", 4070}} {
		var n int
		q := "SELECT COUNT(*) FROM " + tc.table + " p JOIN filters f ON f.id=p.preset_id WHERE f.name='Car Apps' AND p.port=?"
		if err := db.QueryRow(q, tc.port).Scan(&n); err != nil {
			t.Fatalf("%s port check: %v", tc.table, err)
		}
		if n != 1 {
			t.Errorf("Car Apps should own %s port %d exactly once (found %d)", tc.table, tc.port, n)
		}
	}

	// A fresh install must carry NO legacy MAC-pinned port-hole rules — they
	// only ever existed as runtime firewall_rules on the deployed Pi, and
	// v23's DELETE removes them there.
	var fw int
	if err := db.QueryRow(`SELECT COUNT(*) FROM firewall_rules WHERE direction='forward' AND action='accept' AND ((protocol='udp' AND dest_port IN ('443','19302')) OR (protocol='tcp' AND dest_port IN ('5228','4070')))`).Scan(&fw); err != nil {
		t.Fatalf("firewall_rules check: %v", err)
	}
	if fw != 0 {
		t.Errorf("fresh install has %d legacy MAC-pinned port-hole rules, want 0", fw)
	}
}
