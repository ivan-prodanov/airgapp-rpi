package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// The Dashboard is about the Tesla: the device whose alias or hostname says so.
// Among several, an online one wins, then the most recently seen.
func TestPickTesla(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		devs []models.Device
		want string // MAC of the expected device; "" means nil
	}{
		{"no match", []models.Device{{MACAddress: "m1", Alias: "Laptop"}, {MACAddress: "m2", Hostname: "phone"}}, ""},
		{"alias match", []models.Device{{MACAddress: "m1", Alias: "tv"}, {MACAddress: "m2", Alias: "Model Y (garage)", Hostname: "tesla_y"}}, "m2"},
		{"case-insensitive", []models.Device{{MACAddress: "m1", Alias: "TESLA"}}, "m1"},
		{"hostname only", []models.Device{{MACAddress: "m1", Hostname: "Tesla-Model-3"}}, "m1"},
		{"online beats newer", []models.Device{
			{MACAddress: "m1", Alias: "tesla a", Online: false, LastSeen: now},
			{MACAddress: "m2", Alias: "tesla b", Online: true, LastSeen: now.Add(-time.Hour)},
		}, "m2"},
		{"both online: newest", []models.Device{
			{MACAddress: "m1", Alias: "tesla a", Online: true, LastSeen: now.Add(-time.Hour)},
			{MACAddress: "m2", Alias: "tesla b", Online: true, LastSeen: now},
		}, "m2"},
	}
	for _, c := range cases {
		got := pickTesla(c.devs)
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%s: got %s, want nil", c.name, got.MACAddress)
		case c.want != "" && (got == nil || got.MACAddress != c.want):
			t.Errorf("%s: got %v, want %s", c.name, got, c.want)
		}
	}
}

// newDashboardHandler wires the two services the Dashboard API uses onto a
// throwaway database (WAL mode needs a real file, not :memory:).
func newDashboardHandler(t *testing.T) (*DashboardHandler, *sql.DB) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	svc := &services.Services{
		Network:    services.NewNetworkService(db, config.Config{}),
		TrafficLog: services.NewTrafficLogService(db),
	}
	return NewDashboardHandler(svc, nil), db
}

func getDashboard(t *testing.T, h *DashboardHandler) (int, map[string]any, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.API(rec, httptest.NewRequest("GET", "/api/dashboard", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return rec.Code, body, rec.Body.String()
}

func TestDashboardAPI_NoTesla(t *testing.T) {
	h, db := newDashboardHandler(t)
	if _, err := db.Exec(`INSERT INTO devices (mac_address, ip_address, hostname, alias, status, last_seen)
		VALUES ('AA:BB:CC:00:00:09', '192.168.4.50', 'laptop', '', 'open', datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	code, body, raw := getDashboard(t, h)
	want := map[string]any{"tesla": nil, "hosts": []any{}, "blocked_24h": float64(0), "allowed_24h": float64(0)}
	if code != 200 || fmt.Sprint(body) != fmt.Sprint(want) {
		t.Errorf("got %d %s, want 200 %v", code, raw, want)
	}
}

func TestDashboardAPI_Tesla(t *testing.T) {
	h, db := newDashboardHandler(t)
	if _, err := db.Exec(`INSERT INTO devices (mac_address, ip_address, hostname, alias, status, last_seen)
		VALUES ('AA:BB:CC:00:00:01', '192.168.4.42', 'tesla_model_y', 'Model Y', 'filtered', datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct{ mac, domain, action string }{
		{"aa:bb:cc:00:00:01", "a.example", "blocked"},
		{"", "b.example", "resolved"},
		{"aa:bb:cc:00:00:01", "b.example", "allowed"},
	} {
		if _, err := db.Exec(`INSERT INTO query_log (timestamp, client_ip, domain, action, client_mac, source)
			VALUES (datetime('now'), '192.168.4.42', ?, ?, ?, 'sniproxy')`, r.domain, r.action, r.mac); err != nil {
			t.Fatal(err)
		}
	}
	code, body, raw := getDashboard(t, h)
	tesla, _ := body["tesla"].(map[string]any)
	hosts, _ := body["hosts"].([]any)
	if code != 200 || tesla == nil || tesla["status"] != "filtered" || tesla["online"] != true || len(hosts) != 2 {
		t.Fatalf("got %d %s", code, raw)
	}
	if body["blocked_24h"] != float64(1) || body["allowed_24h"] != float64(2) {
		t.Errorf("counts: %s", raw)
	}
	for _, gone := range []string{"lock_state", "devices_online", "system"} {
		if _, ok := body[gone]; ok {
			t.Errorf("old field %q still served", gone)
		}
	}
}

// The gate follows the Tesla's policy, as in the design: Blocked → nothing
// crosses, Open → everything does, Filtered → allow-listed hosts cross. Raw
// event verdicts can't be used: a blocked car's DNS still logs "resolved", and
// an open car's traffic bypasses the Pi and isn't logged at all.
func TestDashboardAPI_CrossingFollowsPolicy(t *testing.T) {
	for _, c := range []struct {
		status string
		want   bool // crossed, for a host that is not allow-listed and was "resolved"
	}{{"blocked", false}, {"open", true}, {"filtered", false}} {
		h, db := newDashboardHandler(t)
		if _, err := db.Exec(`INSERT INTO devices (mac_address, ip_address, hostname, alias, status, last_seen)
			VALUES ('AA:BB:CC:00:00:01', '192.168.4.42', 'tesla', '', ?, datetime('now'))`, c.status); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO query_log (timestamp, client_ip, domain, action, client_mac, source)
			VALUES (datetime('now'), '192.168.4.42', 'x.example', 'resolved', '', 'dns')`); err != nil {
			t.Fatal(err)
		}
		_, body, raw := getDashboard(t, h)
		hosts, _ := body["hosts"].([]any)
		if len(hosts) != 1 || hosts[0].(map[string]any)["crossed"] != c.want {
			t.Errorf("%s: %s, want crossed=%v", c.status, raw, c.want)
		}
	}
}
