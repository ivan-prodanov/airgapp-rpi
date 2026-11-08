package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

type SettingsHandler struct {
	db       *sql.DB
	svc      *services.Services
	renderer *Renderer
	// Applying runs synchronously so a failure reaches the page; tests replace these.
	applyHotspot func() error
	applyDNS     func() error
}

func NewSettingsHandler(db *sql.DB, svc *services.Services, renderer *Renderer) *SettingsHandler {
	h := &SettingsHandler{db: db, svc: svc, renderer: renderer}
	h.applyHotspot = func() error { return svc.Hotspot.Apply() }
	// The resolvers feed dnsmasq and the Open devices' DNS redirect.
	h.applyDNS = func() error {
		if err := svc.DNS.Apply(); err != nil {
			return err
		}
		return svc.Firewall.Apply()
	}
	return h
}

func (h *SettingsHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "settings.html", map[string]string{"page": "settings"})
}

// Get returns the settings, except the hotspot password: the page only learns
// whether one is set.
func (h *SettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT key, value FROM settings")
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	settings := map[string]string{"ap_password_set": "false"}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		if k == "ap_password" {
			if v != "" {
				settings["ap_password_set"] = "true"
			}
			continue
		}
		settings[k] = v
	}
	JSON(w, http.StatusOK, settings)
}

// Update validates every value first (400 names the field), saves them in one
// transaction, then applies what changed and reports a failure to apply.
func (h *SettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := services.ValidateSettings(in); err != nil {
		var se *services.SettingError
		if errors.As(err, &se) {
			JSON(w, http.StatusBadRequest, map[string]string{"error": se.Msg, "key": se.Key})
			return
		}
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if v, ok := in["dns_upstream"]; ok {
		in["dns_upstream"] = strings.Join(services.SplitUpstreams(v), ",")
	}
	if in["ap_password"] == "" {
		delete(in, "ap_password") // empty means unchanged
	}

	tx, err := h.db.Begin()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hotspot, dns := false, false
	keys := make([]string, 0, len(in))
	for k, v := range in {
		if _, err := tx.Exec("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", k, v); err != nil {
			tx.Rollback()
			JSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		keys = append(keys, k)
		switch k {
		case "ap_ssid", "ap_password", "ap_channel", "ap_country":
			hotspot = true
		case "dns_upstream":
			dns = true
		}
	}
	if err := tx.Commit(); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.Strings(keys)
	h.svc.Audit.Log("settings.update", "changed "+strings.Join(keys, ", "))

	if hotspot {
		if err := h.applyHotspot(); err != nil {
			JSONError(w, http.StatusInternalServerError, "Saved, but the hotspot didn't restart: "+err.Error())
			return
		}
	}
	if dns {
		if err := h.applyDNS(); err != nil {
			JSONError(w, http.StatusInternalServerError, "Saved, but DNS didn't reload: "+err.Error())
			return
		}
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *SettingsHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r)

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Password) < 8 {
		JSONError(w, http.StatusBadRequest, "Use at least 8 characters.")
		return
	}

	if err := h.svc.Auth.ResetPassword(user.Username, req.Password); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// A new password signs every browser out, this one included.
	if err := h.svc.Auth.EndAllSessions(); err != nil {
		JSONError(w, http.StatusInternalServerError, "Password changed, but other sessions are still signed in: "+err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})

	h.svc.Audit.Log("auth.password_change", "user="+user.Username)

	JSON(w, http.StatusOK, map[string]bool{"signed_out": true})
}
