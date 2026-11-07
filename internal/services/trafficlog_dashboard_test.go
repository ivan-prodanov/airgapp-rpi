package services

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	dashTeslaMAC = "aa:bb:cc:00:00:01"
	dashTeslaIP  = "192.168.4.42"
	dashOtherMAC = "aa:bb:cc:00:00:02"
	dashOtherIP  = "192.168.4.43"
)

// logRow inserts one query_log row at the given age. DNS rows carry no MAC.
func logRow(t *testing.T, db *sql.DB, age time.Duration, mac, ip, domain, action, source string) {
	t.Helper()
	ts := time.Now().Add(-age).UTC().Format("2006-01-02 15:04:05")
	if _, err := db.Exec(`INSERT INTO query_log (timestamp, client_ip, domain, dst_ip, dst_port, protocol, action, client_mac, source)
		VALUES (?, ?, ?, '', '', 'TLS', ?, ?, ?)`, ts, ip, domain, action, mac, source); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func domainsOf(hs []HostVerdict) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = h.Domain
	}
	return out
}

func TestRecentHosts_DistinctNewestFirst(t *testing.T) {
	db := memDB(t)
	s := NewTrafficLogService(db)
	logRow(t, db, 5*time.Minute, dashTeslaMAC, dashTeslaIP, "a.example", "blocked", "sniproxy")
	logRow(t, db, 4*time.Minute, "", dashTeslaIP, "b.example", "resolved", "dns") // DNS: IP only
	logRow(t, db, 3*time.Minute, dashTeslaMAC, dashTeslaIP, "a.example", "allowed", "sniproxy")
	logRow(t, db, 2*time.Minute, dashOtherMAC, dashOtherIP, "c.example", "allowed", "sniproxy")
	logRow(t, db, 2*time.Minute, dashTeslaMAC, dashTeslaIP, "", "blocked", "forward")
	logRow(t, db, time.Minute, dashTeslaMAC, dashTeslaIP, "d.example", "logged", "forward")

	got, err := s.RecentHosts(dashTeslaMAC, dashTeslaIP, time.Now().Add(-24*time.Hour), 7)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(domainsOf(got)) != "[a.example b.example]" {
		t.Fatalf("hosts = %v, want [a.example b.example]", domainsOf(got))
	}
	if !got[0].Crossed || !got[1].Crossed {
		t.Errorf("a.example's latest event was allowed and b.example resolved; both cross: %+v", got)
	}
}

func TestRecentHosts_Limit(t *testing.T) {
	db := memDB(t)
	s := NewTrafficLogService(db)
	for i := 0; i < 9; i++ {
		logRow(t, db, time.Duration(9-i)*time.Minute, dashTeslaMAC, dashTeslaIP, fmt.Sprintf("h%d.example", i), "blocked", "sniproxy")
	}
	got, _ := s.RecentHosts(dashTeslaMAC, dashTeslaIP, time.Now().Add(-24*time.Hour), 7)
	if len(got) != 7 || got[0].Domain != "h8.example" || got[6].Domain != "h2.example" {
		t.Errorf("want the 7 newest h8..h2, got %v", domainsOf(got))
	}
}

func TestRecentHosts_Window(t *testing.T) {
	db := memDB(t)
	s := NewTrafficLogService(db)
	logRow(t, db, 25*time.Hour, dashTeslaMAC, dashTeslaIP, "old.example", "allowed", "sniproxy")
	got, err := s.RecentHosts(dashTeslaMAC, dashTeslaIP, time.Now().Add(-24*time.Hour), 7)
	if err != nil || len(got) != 0 {
		t.Errorf("want no hosts and no error, got %v, %v", got, err)
	}
}

func TestRecentHosts_Safe(t *testing.T) {
	db := memDB(t)
	s := NewTrafficLogService(db)
	if _, err := db.Exec(`UPDATE filters SET enabled = 1 WHERE name = 'Connectivity'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO filter_domains (preset_id, domain, description)
		SELECT id, 'ok.example', 'test' FROM filters WHERE name = 'Connectivity'`); err != nil {
		t.Fatal(err)
	}
	s.RefreshAllowCache()
	logRow(t, db, 3*time.Minute, dashTeslaMAC, dashTeslaIP, "ok.example", "allowed", "sniproxy")
	logRow(t, db, 2*time.Minute, dashTeslaMAC, dashTeslaIP, "bad.example", "blocked", "sniproxy")
	logRow(t, db, time.Minute, dashTeslaMAC, dashTeslaIP, "x.ap.tesla.services", "blocked", "sniproxy")

	got, _ := s.RecentHosts(dashTeslaMAC, dashTeslaIP, time.Now().Add(-24*time.Hour), 7)
	safe := map[string]bool{}
	for _, h := range got {
		safe[h.Domain] = h.Safe
	}
	if !safe["ok.example"] || safe["bad.example"] || safe["x.ap.tesla.services"] {
		t.Errorf("safe = %v, want only ok.example safe", safe)
	}
}

func TestClassCountsSince(t *testing.T) {
	db := memDB(t)
	s := NewTrafficLogService(db)
	add := func(n int, mac, ip, action string, age time.Duration) {
		for i := 0; i < n; i++ {
			logRow(t, db, age, mac, ip, "x.example", action, "sniproxy")
		}
	}
	add(2, dashTeslaMAC, dashTeslaIP, "blocked", time.Minute)
	add(3, "", dashTeslaIP, "sinkholed", time.Minute)
	add(1, dashTeslaMAC, dashTeslaIP, "allowed", time.Minute)
	add(4, "", dashTeslaIP, "resolved", time.Minute)
	add(5, dashTeslaMAC, dashTeslaIP, "logged", time.Minute)
	add(1, dashTeslaMAC, dashTeslaIP, "blocked", 25*time.Hour)
	add(7, dashOtherMAC, dashOtherIP, "blocked", time.Minute)

	blocked, allowed := s.ClassCountsSince(dashTeslaMAC, dashTeslaIP, time.Now().Add(-24*time.Hour))
	if blocked != 5 || allowed != 5 {
		t.Errorf("blocked=%d allowed=%d, want 5 and 5", blocked, allowed)
	}
}

// ActiveSince reports which clients produced any traffic recently: by MAC for
// forward/SNI rows, by IP for DNS rows (which carry no MAC).
func TestActiveSince(t *testing.T) {
	db := memDB(t)
	s := NewTrafficLogService(db)
	logRow(t, db, 2*time.Second, "AA:BB:CC:00:00:0A", "192.168.4.10", "a.example", "allowed", "sniproxy")
	logRow(t, db, 2*time.Second, "", "192.168.4.11", "b.example", "resolved", "dns")
	logRow(t, db, 30*time.Second, "aa:bb:cc:00:00:0c", "192.168.4.12", "c.example", "blocked", "sniproxy")
	macs, ips, err := s.ActiveSince(time.Now().Add(-5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !macs["aa:bb:cc:00:00:0a"] || !ips["192.168.4.11"] || macs["aa:bb:cc:00:00:0c"] || ips["192.168.4.12"] {
		t.Errorf("macs=%v ips=%v; want A by MAC, B by IP, not C", macs, ips)
	}
}

// RecentHosts must not walk the whole retention window: a parked car with no
// rows in 24 h used to make SQLite read every row of each action across 30
// days, on the daemon's only DB connection. The host scan is bounded to the
// window by row id.
func TestRecentHosts_BoundedScan(t *testing.T) {
	db := memDB(t)
	var plan []string
	rows, err := db.Query("EXPLAIN QUERY PLAN "+recentHostsSQL("(client_ip = ?)"), int64(1), "2026-01-01 00:00:00", "192.168.4.42")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, parent, notused int
		var detail string
		rows.Scan(&id, &parent, &notused, &detail)
		plan = append(plan, detail)
	}
	if joined := fmt.Sprint(plan); !strings.Contains(joined, "rowid>?") {
		t.Errorf("host scan is not bounded by row id: %v", plan)
	}
}

// AllowedByHostSince counts the rows that reached a host — allowed and
// resolved — per host, over the window.
func TestAllowedByHostSince(t *testing.T) {
	db := memDB(t)
	s := NewTrafficLogService(db)
	logRow(t, db, time.Minute, dashTeslaMAC, dashTeslaIP, "r1.googlevideo.com", "allowed", "sniproxy")
	logRow(t, db, time.Minute, dashOtherMAC, dashOtherIP, "R1.googlevideo.com", "allowed", "sniproxy")
	logRow(t, db, time.Minute, "", dashTeslaIP, "googlevideo.com", "resolved", "dns")
	logRow(t, db, time.Minute, dashTeslaMAC, dashTeslaIP, "googlevideo.com", "blocked", "sniproxy")
	logRow(t, db, time.Minute, "", dashTeslaIP, "googlevideo.com", "sinkholed", "dns")
	logRow(t, db, time.Minute, dashTeslaMAC, dashTeslaIP, "googlevideo.com", "logged", "forward")
	logRow(t, db, 8*24*time.Hour, dashTeslaMAC, dashTeslaIP, "googlevideo.com", "allowed", "sniproxy")
	got, err := s.AllowedByHostSince(time.Now().Add(-7 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got["r1.googlevideo.com"] != 2 || got["googlevideo.com"] != 1 || len(got) != 2 {
		t.Errorf("got %v, want r1.googlevideo.com:2 googlevideo.com:1", got)
	}
}
