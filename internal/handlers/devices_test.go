package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

const devMAC = "AA:BB:CC:00:00:10"

// newDevicesTest wires a DevicesHandler onto a throwaway database and routes
// /api/devices through chi so {mac} resolves. Firewall and DNS are not wired:
// the endpoints under test don't touch them.
func newDevicesTest(t *testing.T) (*chi.Mux, *sql.DB) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	h := &DevicesHandler{
		network:    services.NewNetworkService(db, config.Config{}),
		trafficLog: services.NewTrafficLogService(db),
		audit:      services.NewAuditService(db),
	}
	r := chi.NewRouter()
	r.Route("/api/devices", func(r chi.Router) {
		r.Get("/", h.List)
		r.Put("/{mac}", h.Update)
	})
	return r, db
}

func addDevice(t *testing.T, db *sql.DB, mac, ip, host, alias string, ignore int) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO devices (mac_address, ip_address, hostname, alias, status, ignore_traffic_log, last_seen)
		VALUES (?, ?, ?, ?, 'blocked', ?, datetime('now'))`, mac, ip, host, alias, ignore); err != nil {
		t.Fatal(err)
	}
}

func addLogRows(t *testing.T, db *sql.DB, mac, ip, action string, n int, age string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := db.Exec(`INSERT INTO query_log (timestamp, client_ip, domain, action, client_mac, source)
			VALUES (datetime('now', ?), ?, 'x.example', ?, ?, 'sniproxy')`, age, ip, action, strings.ToLower(mac)); err != nil {
			t.Fatal(err)
		}
	}
}

func countRows(t *testing.T, db *sql.DB, mac string) int {
	t.Helper()
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM query_log WHERE LOWER(client_mac) = LOWER(?)`, mac).Scan(&n)
	return n
}

func putDevice(r *chi.Mux, mac, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/devices/"+mac, strings.NewReader(body)))
	return rec
}

func deviceRow(t *testing.T, db *sql.DB, mac string) (alias string, ignore int) {
	t.Helper()
	if err := db.QueryRow(`SELECT alias, ignore_traffic_log FROM devices WHERE mac_address = ?`, mac).Scan(&alias, &ignore); err != nil {
		t.Fatal(err)
	}
	return
}

// Renaming must not touch logging: before, the rename body reset the flag to
// "log" and wiped nothing; now a rename of a muted device keeps it muted.
func TestUpdateDevice_RenameKeepsLogging(t *testing.T) {
	r, db := newDevicesTest(t)
	addDevice(t, db, devMAC, "192.168.4.60", "car", "", 1)
	addLogRows(t, db, devMAC, "192.168.4.60", "blocked", 2, "-1 minute")
	if rec := putDevice(r, devMAC, `{"alias":"Car"}`); rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	alias, ignore := deviceRow(t, db, devMAC)
	if alias != "Car" || ignore != 1 || countRows(t, db, devMAC) != 2 {
		t.Errorf("alias=%q ignore=%d rows=%d, want Car, 1, 2", alias, ignore, countRows(t, db, devMAC))
	}
}

// Turning logging off keeps the name and wipes the history, once.
func TestUpdateDevice_LogOffWipesOnce(t *testing.T) {
	r, db := newDevicesTest(t)
	addDevice(t, db, devMAC, "192.168.4.60", "tv", "TV", 0)
	addLogRows(t, db, devMAC, "192.168.4.60", "allowed", 3, "-1 minute")
	if rec := putDevice(r, devMAC, `{"ignore_traffic_log":true}`); rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	alias, ignore := deviceRow(t, db, devMAC)
	if alias != "TV" || ignore != 1 || countRows(t, db, devMAC) != 0 {
		t.Errorf("alias=%q ignore=%d rows=%d, want TV, 1, 0", alias, ignore, countRows(t, db, devMAC))
	}
}

func TestUpdateDevice_Empty(t *testing.T) {
	r, db := newDevicesTest(t)
	addDevice(t, db, devMAC, "192.168.4.60", "tv", "TV", 0)
	rec := putDevice(r, devMAC, `{}`)
	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 400 || body["error"] != "nothing to update" {
		t.Errorf("got %d %s, want 400 nothing to update", rec.Code, rec.Body)
	}
}

func listDevices(t *testing.T, r *chi.Mux) []map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/api/devices/", nil))
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return out
}

// The Devices page needs to know which device is the Tesla and how much of its
// traffic the gate blocked this hour; nothing else changes in the list.
func TestListDevices_MarksTesla(t *testing.T) {
	t.Run("with a Tesla", func(t *testing.T) {
		r, db := newDevicesTest(t)
		addDevice(t, db, "AA:BB:CC:00:00:01", "192.168.4.42", "tesla_model_y", "Model Y", 0)
		addDevice(t, db, "AA:BB:CC:00:00:02", "192.168.4.43", "laptop", "", 0)
		addLogRows(t, db, "AA:BB:CC:00:00:01", "192.168.4.42", "blocked", 3, "-10 minutes")
		addLogRows(t, db, "AA:BB:CC:00:00:01", "192.168.4.42", "sinkholed", 2, "-10 minutes")
		addLogRows(t, db, "AA:BB:CC:00:00:01", "192.168.4.42", "blocked", 1, "-2 hours")
		for _, d := range listDevices(t, r) {
			switch d["mac_address"] {
			case "AA:BB:CC:00:00:01":
				if d["tesla"] != true || d["blocked_1h"] != float64(5) {
					t.Errorf("Tesla element: tesla=%v blocked_1h=%v, want true, 5", d["tesla"], d["blocked_1h"])
				}
			default:
				if _, ok := d["tesla"]; ok {
					t.Errorf("%v marked as the Tesla", d["mac_address"])
				}
				if _, ok := d["blocked_1h"]; ok {
					t.Errorf("%v has blocked_1h", d["mac_address"])
				}
			}
		}
	})
	t.Run("without a Tesla", func(t *testing.T) {
		r, db := newDevicesTest(t)
		addDevice(t, db, "AA:BB:CC:00:00:02", "192.168.4.43", "laptop", "", 0)
		for _, d := range listDevices(t, r) {
			if _, ok := d["tesla"]; ok {
				t.Errorf("%v marked as the Tesla", d["mac_address"])
			}
		}
	})
}
