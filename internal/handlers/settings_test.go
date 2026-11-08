package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/database"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type settingsTest struct {
	r  *chi.Mux
	db *sql.DB
	h  *SettingsHandler
}

func newSettingsTest(t *testing.T) settingsTest {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	h := NewSettingsHandler(db, &services.Services{Audit: services.NewAuditService(db)}, nil)
	h.applyHotspot = func() error { return nil }
	h.applyDNS = func() error { return nil }
	r := chi.NewRouter()
	r.Get("/api/settings", h.Get)
	r.Put("/api/settings", h.Update)
	return settingsTest{r, db, h}
}

func (st settingsTest) do(t *testing.T, method, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	st.r.ServeHTTP(rec, httptest.NewRequest(method, "/api/settings", strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (st settingsTest) setting(t *testing.T, key string) string {
	t.Helper()
	var v string
	st.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v
}

// Nothing is saved unless everything is valid, and the page learns which field.
func TestUpdateSettings_RejectsBeforeSaving(t *testing.T) {
	st := newSettingsTest(t)
	before := st.setting(t, "ap_ssid")
	code, out := st.do(t, "PUT", `{"ap_ssid":"New name","ap_channel":"13"}`)
	if code != 400 || out["key"] != "ap_channel" || out["error"] != "Pick a channel the hotspot supports." {
		t.Fatalf("got %d %v", code, out)
	}
	if got := st.setting(t, "ap_ssid"); got != before {
		t.Fatalf("ap_ssid saved despite the bad channel: %q", got)
	}
}

// A hotspot that won't restart is reported, not hidden in a goroutine.
func TestUpdateSettings_ApplyErrorReturned(t *testing.T) {
	st := newSettingsTest(t)
	st.h.applyHotspot = func() error { return errors.New("restart hostapd: exit status 1") }
	code, out := st.do(t, "PUT", `{"ap_ssid":"Airgapp","ap_channel":"6"}`)
	if code != 500 || out["error"] != "Saved, but the hotspot didn't restart: restart hostapd: exit status 1" {
		t.Fatalf("got %d %v", code, out)
	}
	if st.setting(t, "ap_ssid") != "Airgapp" {
		t.Fatal("the valid settings should be saved")
	}
}

// Only what changed applies: DNS for resolvers, nothing for retention, and an
// empty hotspot password means unchanged.
func TestUpdateSettings_AppliesWhatChanged(t *testing.T) {
	st := newSettingsTest(t)
	var hot, dns int
	st.h.applyHotspot = func() error { hot++; return nil }
	st.h.applyDNS = func() error { dns++; return nil }
	pw := st.setting(t, "ap_password")
	if code, out := st.do(t, "PUT", `{"dns_upstream":"9.9.9.9","ap_password":""}`); code != 200 {
		t.Fatalf("got %d %v", code, out)
	}
	if hot != 0 || dns != 1 || st.setting(t, "ap_password") != pw || st.setting(t, "dns_upstream") != "9.9.9.9" {
		t.Fatalf("hotspot %d dns %d password %q upstream %q", hot, dns, st.setting(t, "ap_password"), st.setting(t, "dns_upstream"))
	}
	if code, _ := st.do(t, "PUT", `{"log_retention_days":"90"}`); code != 200 || hot != 0 || dns != 1 || st.setting(t, "log_retention_days") != "90" {
		t.Fatalf("retention: code %d hotspot %d dns %d", code, hot, dns)
	}
}

// The hotspot password never leaves the server; the page only learns it's set.
func TestGetSettings_HidesPassword(t *testing.T) {
	st := newSettingsTest(t)
	st.db.Exec(`INSERT INTO settings (key, value) VALUES ('ap_password','secret-pass') ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
	code, out := st.do(t, "GET", "")
	if code != 200 {
		t.Fatalf("GET: %d", code)
	}
	if _, ok := out["ap_password"]; ok {
		t.Fatal("GET /api/settings returned ap_password")
	}
	if out["ap_password_set"] != "true" {
		t.Fatalf("ap_password_set = %v", out["ap_password_set"])
	}
}

// A new dashboard password signs out every browser, this one included.
func TestChangePassword_EndsAllSessions(t *testing.T) {
	st := newSettingsTest(t)
	auth := services.NewAuthService(st.db)
	st.h.svc.Auth = auth
	if err := auth.CreateUser("owner", "old-password"); err != nil {
		t.Fatal(err)
	}
	a, err := auth.Login("owner", "old-password")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := auth.Login("owner", "old-password")
	user, _ := auth.ValidateSession(a)
	req := httptest.NewRequest("PUT", "/api/settings/password", strings.NewReader(`{"password":"new-password"}`))
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, user))
	rec := httptest.NewRecorder()
	st.h.ChangePassword(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"signed_out":true`) {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	for _, tok := range []string{a, b} {
		if _, err := auth.ValidateSession(tok); err == nil {
			t.Errorf("session %s… still valid", tok[:6])
		}
	}
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Name != "session" || c[0].MaxAge >= 0 {
		t.Errorf("cookie not cleared: %+v", c)
	}
	if _, err := auth.Login("owner", "new-password"); err != nil {
		t.Errorf("new password doesn't sign in: %v", err)
	}
}
