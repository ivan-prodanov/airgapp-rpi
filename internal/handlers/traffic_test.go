package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type trafficTest struct {
	r   *chi.Mux
	db  *sql.DB
	svc *services.Services
}

func newTrafficTest(t *testing.T) trafficTest {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	svc := &services.Services{
		Filter:     services.NewFilterService(db),
		TrafficLog: services.NewTrafficLogService(db),
		Network:    services.NewNetworkService(db, config.Config{}),
	}
	h := NewTrafficHandler(svc)
	r := chi.NewRouter()
	r.Get("/api/traffic/feed", h.Feed)
	return trafficTest{r, db, svc}
}

type feedResp struct {
	Entries []struct {
		ID       int64                 `json:"id"`
		Time     string                `json:"time"`
		Client   string                `json:"client"`
		ClientIP string                `json:"client_ip"`
		Domain   string                `json:"domain"`
		DstIP    string                `json:"dst_ip"`
		Port     string                `json:"port"`
		Proto    string                `json:"proto"`
		Action   string                `json:"action"`
		Class    string                `json:"class"`
		Locked   bool                  `json:"locked"`
		Cover    *services.FilterCover `json:"cover"`
		MutedBy  string                `json:"muted_by"`
	} `json:"entries"`
	LastID int64 `json:"last_id"`
	Muted  int   `json:"muted"`
}

func (tt trafficTest) feed(t *testing.T, query string) feedResp {
	t.Helper()
	rec := httptest.NewRecorder()
	tt.r.ServeHTTP(rec, httptest.NewRequest("GET", "/api/traffic/feed"+query, nil))
	if rec.Code != 200 {
		t.Fatalf("GET feed%s: %d %s", query, rec.Code, rec.Body.String())
	}
	var out feedResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return out
}

// event inserts one query_log row and returns its id.
func (tt trafficTest) event(t *testing.T, ip, mac, domain, dst, port, proto, action, source string) int64 {
	t.Helper()
	res, err := tt.db.Exec(`INSERT INTO query_log (timestamp, client_ip, domain, dst_ip, dst_port, protocol, action, client_mac, source, policy)
		VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, '')`, ip, domain, dst, port, proto, action, mac, source)
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// filterWith creates a user filter listing domains, on or off.
func (tt trafficTest) filterWith(t *testing.T, name string, on bool, domains ...string) int64 {
	t.Helper()
	id, err := tt.svc.Filter.Create(models.Filter{Name: name})
	if err != nil {
		t.Fatalf("create filter: %v", err)
	}
	for _, d := range domains {
		if _, err := tt.svc.Filter.CreateDomain(id, models.FilterDomain{Domain: d}); err != nil {
			t.Fatalf("add %s: %v", d, err)
		}
	}
	if on {
		if err := tt.svc.Filter.SetEnabled(id, true); err != nil {
			t.Fatalf("enable: %v", err)
		}
	}
	tt.svc.TrafficLog.RefreshAllowCache()
	return id
}

func ids(r feedResp) []int64 {
	out := make([]int64, len(r.Entries))
	for i, e := range r.Entries {
		out[i] = e.ID
	}
	return out
}

// The page asks only for what's new since the last id it saw; the answer's
// last_id is the whole log's, so a filtered poll never rescans.
func TestTrafficFeed_AfterID(t *testing.T) {
	tt := newTrafficTest(t)
	a := tt.event(t, "192.168.4.10", "", "a.example.com", "", "53", "DNS", "resolved", "dns")
	b := tt.event(t, "192.168.4.10", "", "b.example.com", "", "53", "DNS", "resolved", "dns")
	c := tt.event(t, "192.168.4.10", "", "c.example.com", "", "53", "DNS", "resolved", "dns")

	first := tt.feed(t, "")
	if got := fmt.Sprint(ids(first)); got != fmt.Sprint([]int64{c, b, a}) {
		t.Fatalf("first page ids %s, want newest first %v", got, []int64{c, b, a})
	}
	if first.LastID != c {
		t.Fatalf("last_id %d, want %d", first.LastID, c)
	}
	if again := tt.feed(t, fmt.Sprintf("?after=%d", c)); len(again.Entries) != 0 || again.LastID != c {
		t.Fatalf("nothing new: got %v last_id %d", ids(again), again.LastID)
	}
	d := tt.event(t, "192.168.4.10", "", "d.example.com", "", "53", "DNS", "resolved", "dns")
	if got := tt.feed(t, fmt.Sprintf("?after=%d", c)); fmt.Sprint(ids(got)) != fmt.Sprint([]int64{d}) || got.LastID != d {
		t.Fatalf("after %d: got %v last_id %d, want [%d]", c, ids(got), got.LastID, d)
	}
	// A blocked-only poll still advances last_id past rows it didn't return.
	if got := tt.feed(t, fmt.Sprintf("?after=%d&outcome=blocked", c)); len(got.Entries) != 0 || got.LastID != d {
		t.Fatalf("filtered poll: got %v last_id %d, want none and %d", ids(got), got.LastID, d)
	}

	for i := 0; i < 250; i++ {
		tt.event(t, "192.168.4.10", "", "bulk.example.com", "", "53", "DNS", "resolved", "dns")
	}
	if got := tt.feed(t, "?after=0&limit=999"); len(got.Entries) != 200 {
		t.Fatalf("limit cap: %d entries, want 200", len(got.Entries))
	}
	if got := tt.feed(t, ""); len(got.Entries) != 80 {
		t.Fatalf("default limit: %d entries, want 80", len(got.Entries))
	}
}

// Allowed is allowed+resolved and Blocked is blocked+sinkholed, the same
// classes as everywhere else; protocol and search narrow it further.
func TestTrafficFeed_Outcome(t *testing.T) {
	tt := newTrafficTest(t)
	al := tt.event(t, "192.168.4.10", "", "cdn.example.com", "203.0.113.5", "443", "TLS", "allowed", "sniproxy")
	re := tt.event(t, "192.168.4.10", "", "api.example.org", "", "53", "DNS", "resolved", "dns")
	bl := tt.event(t, "192.168.4.10", "", "ads.example.net", "203.0.113.9", "443", "TCP", "blocked", "forward")
	si := tt.event(t, "192.168.4.10", "", "track.example.net", "", "53", "DNS", "sinkholed", "dns")

	if got := fmt.Sprint(ids(tt.feed(t, "?outcome=allowed"))); got != fmt.Sprint([]int64{re, al}) {
		t.Errorf("allowed: %s, want %v", got, []int64{re, al})
	}
	if got := fmt.Sprint(ids(tt.feed(t, "?outcome=blocked"))); got != fmt.Sprint([]int64{si, bl}) {
		t.Errorf("blocked: %s, want %v", got, []int64{si, bl})
	}
	if got := fmt.Sprint(ids(tt.feed(t, "?outcome=all"))); got != fmt.Sprint([]int64{si, bl, re, al}) {
		t.Errorf("all: %s", got)
	}
	if got := fmt.Sprint(ids(tt.feed(t, "?proto=tls"))); got != fmt.Sprint([]int64{al}) {
		t.Errorf("proto=tls: %s, want [%d]", got, al)
	}
	if got := fmt.Sprint(ids(tt.feed(t, "?q=examp"))); got != fmt.Sprint([]int64{si, bl, re, al}) {
		t.Errorf("q=examp: %s", got)
	}
	if got := fmt.Sprint(ids(tt.feed(t, "?q=cdn.example"))); got != fmt.Sprint([]int64{al}) {
		t.Errorf("q=cdn.example: %s, want [%d]", got, al)
	}
}

// Each entry carries what its row shows: the verdict class, a locked Allow,
// the filter that lists it, the mute that covers it and the device's name.
func TestTrafficFeed_EntryContext(t *testing.T) {
	entry := func(t *testing.T, r feedResp, id int64) (e struct {
		ID       int64                 `json:"id"`
		Time     string                `json:"time"`
		Client   string                `json:"client"`
		ClientIP string                `json:"client_ip"`
		Domain   string                `json:"domain"`
		DstIP    string                `json:"dst_ip"`
		Port     string                `json:"port"`
		Proto    string                `json:"proto"`
		Action   string                `json:"action"`
		Class    string                `json:"class"`
		Locked   bool                  `json:"locked"`
		Cover    *services.FilterCover `json:"cover"`
		MutedBy  string                `json:"muted_by"`
	}) {
		t.Helper()
		for _, x := range r.Entries {
			if x.ID == id {
				return x
			}
		}
		t.Fatalf("entry %d missing", id)
		return
	}

	t.Run("cover_prefers_enabled", func(t *testing.T) {
		tt := newTrafficTest(t)
		tt.filterWith(t, "Off one", false, "example.com")
		on := tt.filterWith(t, "On one", true, "example.com")
		id := tt.event(t, "192.168.4.10", "", "cdn.example.com", "203.0.113.5", "443", "TLS", "blocked", "sniproxy")
		e := entry(t, tt.feed(t, ""), id)
		if e.Cover == nil || e.Cover.ID != on || e.Cover.Name != "On one" || !e.Cover.Enabled {
			t.Fatalf("cover %+v, want the enabled filter %d", e.Cover, on)
		}
		if e.Class != "blocked" || e.Locked {
			t.Fatalf("class %q locked %v", e.Class, e.Locked)
		}
	})
	t.Run("cover_off_filter", func(t *testing.T) {
		tt := newTrafficTest(t)
		off := tt.filterWith(t, "Pending one", false, "example.com")
		id := tt.event(t, "192.168.4.10", "", "example.com", "", "53", "DNS", "sinkholed", "dns")
		if e := entry(t, tt.feed(t, ""), id); e.Cover == nil || e.Cover.ID != off || e.Cover.Enabled {
			t.Fatalf("cover %+v, want off filter %d", e.Cover, off)
		}
	})
	t.Run("locked", func(t *testing.T) {
		tt := newTrafficTest(t)
		id := tt.event(t, "192.168.4.10", "", "hermes-prd.ap.tesla.services", "203.0.113.7", "443", "TLS", "blocked", "sniproxy")
		if e := entry(t, tt.feed(t, ""), id); !e.Locked || e.Cover != nil || e.Class != "blocked" {
			t.Fatalf("locked %v cover %+v class %q, want locked, no cover, blocked", e.Locked, e.Cover, e.Class)
		}
	})
	t.Run("muted_by", func(t *testing.T) {
		tt := newTrafficTest(t)
		id := tt.event(t, "192.168.4.10", "", "push.apple.com", "", "53", "DNS", "resolved", "dns")
		if _, err := tt.svc.TrafficLog.AddMuted("apple.com"); err != nil {
			t.Fatal(err)
		}
		r := tt.feed(t, "")
		if e := entry(t, r, id); e.MutedBy != "apple.com" {
			t.Fatalf("muted_by %q, want apple.com", e.MutedBy)
		}
		if r.Muted != 1 {
			t.Fatalf("muted count %d, want 1", r.Muted)
		}
	})
	t.Run("legacy_query", func(t *testing.T) {
		tt := newTrafficTest(t)
		tt.filterWith(t, "Listed", true, "example.com")
		listed := tt.event(t, "192.168.4.10", "", "www.example.com", "", "53", "DNS", "query", "dns")
		unlisted := tt.event(t, "192.168.4.10", "", "other.example.net", "", "53", "DNS", "query", "dns")
		r := tt.feed(t, "")
		if e := entry(t, r, listed); e.Action != "resolved" || e.Class != "allowed" {
			t.Fatalf("listed query row: action %q class %q, want resolved/allowed", e.Action, e.Class)
		}
		if e := entry(t, r, unlisted); e.Action != "sinkholed" || e.Class != "blocked" {
			t.Fatalf("unlisted query row: action %q class %q, want sinkholed/blocked", e.Action, e.Class)
		}
	})
	t.Run("client_by_mac", func(t *testing.T) {
		tt := newTrafficTest(t)
		tt.db.Exec(`INSERT INTO devices (mac_address, ip_address, alias) VALUES ('AA:BB:CC:00:00:01', '192.168.4.20', 'Laptop')`)
		// nflog writes dst(6):src(6):ethertype(2); the source is octets 7-12.
		id := tt.event(t, "192.168.4.99", "11:22:33:44:55:66:aa:bb:cc:00:00:01:08:00", "", "203.0.113.9", "443", "UDP", "blocked", "forward")
		if e := entry(t, tt.feed(t, ""), id); e.Client != "Laptop" || e.ClientIP != "192.168.4.99" {
			t.Fatalf("client %q ip %q, want Laptop / 192.168.4.99", e.Client, e.ClientIP)
		}
	})
	t.Run("client_by_ip", func(t *testing.T) {
		tt := newTrafficTest(t)
		tt.db.Exec(`INSERT INTO devices (mac_address, ip_address, hostname) VALUES ('AA:BB:CC:00:00:02', '192.168.4.21', 'speaker')`)
		tt.db.Exec(`INSERT INTO devices (mac_address, ip_address) VALUES ('AA:BB:CC:00:00:03', '192.168.4.22')`)
		a := tt.event(t, "192.168.4.21", "", "api.example.com", "", "53", "DNS", "resolved", "dns")
		b := tt.event(t, "192.168.4.22", "", "api.example.com", "", "53", "DNS", "resolved", "dns")
		r := tt.feed(t, "")
		if e := entry(t, r, a); e.Client != "speaker" {
			t.Fatalf("client %q, want the hostname", e.Client)
		}
		if e := entry(t, r, b); e.Client != "Unknown device" {
			t.Fatalf("client %q, want Unknown device", e.Client)
		}
	})
	t.Run("unknown_client", func(t *testing.T) {
		tt := newTrafficTest(t)
		id := tt.event(t, "192.168.4.77", "", "api.example.com", "", "53", "DNS", "resolved", "dns")
		if e := entry(t, tt.feed(t, ""), id); e.Client != "192.168.4.77" {
			t.Fatalf("client %q, want the IP", e.Client)
		}
	})
	t.Run("no_domain", func(t *testing.T) {
		tt := newTrafficTest(t)
		id := tt.event(t, "192.168.4.10", "", "", "203.0.113.9", "443", "UDP", "blocked", "forward")
		e := entry(t, tt.feed(t, ""), id)
		if e.Domain != "" || e.DstIP != "203.0.113.9" || e.Locked || e.Cover != nil || e.Class != "blocked" || e.Port != "443" || e.Proto != "UDP" {
			t.Fatalf("no-domain row %+v", e)
		}
	})
}

// A poll while searching looks only at the new rows: its cost doesn't grow
// with how many rows in the whole log match (measured: 549 ms at 400k rows
// before the fix, 2 ms after). Timed against a search over the whole log, so
// it holds under the race detector too.
func TestTrafficFeed_SearchPollStaysInRange(t *testing.T) {
	tt := newTrafficTest(t)
	if _, err := tt.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40000)
		INSERT INTO query_log (timestamp, client_ip, domain, dst_ip, dst_port, protocol, action, client_mac, source, policy)
		SELECT CURRENT_TIMESTAMP, '192.168.4.10', 'cdn.example.com', '', '53', 'DNS', 'resolved', '', 'dns', '' FROM n`); err != nil {
		t.Fatal(err)
	}
	last := tt.feed(t, "?limit=1").LastID
	tt.event(t, "192.168.4.10", "", "new.example.com", "", "53", "DNS", "resolved", "dns")
	timed := func(q string) (feedResp, time.Duration) {
		best := time.Hour
		var r feedResp
		for i := 0; i < 3; i++ {
			start := time.Now()
			r = tt.feed(t, q)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return r, best
	}
	_, whole := timed("?q=example&limit=1")
	poll, took := timed(fmt.Sprintf("?after=%d&q=example", last))
	if len(poll.Entries) != 1 {
		t.Fatalf("poll returned %d rows, want 1", len(poll.Entries))
	}
	if took*4 > whole {
		t.Fatalf("a search poll for one new row took %v, a search of the whole log %v: the poll scans every match", took, whole)
	}
}

// "Search domain · client · IP": a device's name finds its rows.
func TestTrafficFeed_SearchByDeviceName(t *testing.T) {
	tt := newTrafficTest(t)
	tt.db.Exec(`INSERT INTO devices (mac_address, ip_address, alias) VALUES ('AA:BB:CC:00:00:31', '192.168.4.31', 'iPhone')`)
	mine := tt.event(t, "192.168.4.31", "", "apple.com", "", "53", "DNS", "resolved", "dns")
	tt.event(t, "192.168.4.10", "", "cdn.example.com", "", "53", "DNS", "resolved", "dns")
	if got := tt.feed(t, "?q=iphone"); fmt.Sprint(ids(got)) != fmt.Sprint([]int64{mine}) {
		t.Fatalf("q=iphone: %v, want [%d]", ids(got), mine)
	}
}

// An allowed connection whose site didn't answer gets its own class, so the
// console shows "No answer" rather than calling it allowed or blocked.
func TestVerdictClassUnreachable(t *testing.T) {
	for action, want := range map[string]string{"allowed": "allowed", "resolved": "allowed", "blocked": "blocked", "sinkholed": "blocked", "unreachable": "unreachable"} {
		if got := verdictClass(action); got != want {
			t.Errorf("verdictClass(%q) = %q, want %q", action, got, want)
		}
	}
}
