// Preview-only dev server for the AIRGAP admin UI.
//
//	go run ./cmd/preview
//	open http://localhost:8080
//
// Stubs every /api/* route with realistic mock data so the Alpine
// controllers in the templates can wire up without a real backend.
// State changes (status flips, toggle adds) persist in memory for the
// life of the process.
//
// Not built into the production binary. Delete this directory before
// shipping if you want.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/handlers"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
	web "github.com/iulianfsdro/rpi-network-filter/web"
)

// ── Mock state ─────────────────────────────────────────────

type kv map[string]any
type mockState struct {
	mu              sync.Mutex
	devicePuts      []map[string]any // PUT /api/devices/{mac} bodies, for the browser checks
	teslaLogTouched bool             // ?scenario=teslalogoff: logging was turned back on
	devices         []kv
	filters         []kv
	traffic         []kv
	muted           []kv
	settings        kv
	remote          kv
	tokens          []kv
	audit           []kv
	rebootAt        time.Time
	nextID          int64
}

var state = newMockState()

func newMockState() *mockState {
	now := time.Now()
	t := func(off time.Duration) string { return now.Add(-off).UTC().Format("2006-01-02 15:04:05") }
	s := &mockState{
		nextID: 100,
		devices: []kv{
			{"id": 1, "first_seen": ago("2400h"), "last_seen": ago("0s"), "mac_address": "F4:F5:D8:1A:22:C7", "alias": "Tesla M3 — Garage", "hostname": "TeslaModel3-DC22", "ip_address": "192.168.4.42", "status": "filtered", "online": true, "ignore_traffic_log": false},
			{"id": 2, "first_seen": ago("5000h"), "last_seen": ago("0s"), "mac_address": "AC:DE:48:00:11:22", "alias": "iPhone", "hostname": "iPhone", "ip_address": "192.168.4.31", "status": "open", "online": true, "ignore_traffic_log": false},
			{"id": 3, "first_seen": ago("5000h"), "last_seen": ago("0s"), "mac_address": "98:01:A7:9B:0C:14", "alias": "Work laptop", "hostname": "work-laptop", "ip_address": "192.168.4.22", "status": "open", "online": true, "ignore_traffic_log": false},
			{"id": 4, "first_seen": ago("3000h"), "last_seen": ago("0s"), "mac_address": "5C:CF:7F:8E:A4:11", "alias": "Sonos Beam", "hostname": "Sonos-BEAM", "ip_address": "192.168.4.51", "status": "blocked", "online": true, "ignore_traffic_log": true},
			{"id": 5, "first_seen": ago("1200h"), "last_seen": ago("0s"), "mac_address": "B8:27:EB:33:9D:18", "alias": "", "hostname": "raspberrypi-cam", "ip_address": "192.168.4.61", "status": "blocked", "online": true, "ignore_traffic_log": false},
			{"id": 6, "first_seen": ago("1200h"), "last_seen": ago("3h"), "mac_address": "DC:A6:32:71:5B:0E", "alias": "Roomba j7", "hostname": "iRobot-J7", "ip_address": "192.168.4.55", "status": "blocked", "online": false, "ignore_traffic_log": true},
			{"id": 7, "first_seen": ago("900h"), "last_seen": ago("0s"), "mac_address": "00:17:88:7E:12:6A", "alias": "Hue bridge", "hostname": "Philips-hue", "ip_address": "192.168.4.71", "status": "blocked", "online": true, "ignore_traffic_log": true},
			{"id": 8, "first_seen": ago("10m"), "last_seen": ago("0s"), "mac_address": "02:00:00:00:00:08", "alias": "", "hostname": "", "ip_address": "192.168.4.77", "status": "blocked", "online": true, "ignore_traffic_log": false},
		},
		filters: seedFilters(),
		traffic: []kv{
			{"id": 1, "timestamp": t(2 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "23.45.221.18", "dst_port": "443", "protocol": "TLS", "action": "allowed", "domain": "apmv3.go.tesla.services", "source": "forward"},
			{"id": 2, "timestamp": t(3 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "", "dst_port": "53", "protocol": "DNS", "action": "query", "domain": "maps-eu-prd.go.tesla.services", "source": "dns"},
			{"id": 3, "timestamp": t(6 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "199.66.11.9", "dst_port": "443", "protocol": "TLS", "action": "blocked", "domain": "hermes-prd.ap.tesla.services", "source": "forward"},
			{"id": 4, "timestamp": t(9 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "52.84.221.2", "dst_port": "443", "protocol": "TLS", "action": "blocked", "domain": "ota.vn.tesla.services", "source": "forward"},
			{"id": 5, "timestamp": t(12 * time.Second), "src_ip": "192.168.4.31", "src_mac": "AC:DE:48:00:11:22", "dst_ip": "17.253.144.10", "dst_port": "443", "protocol": "TLS", "action": "allowed", "domain": "icloud.com", "source": "forward"},
			{"id": 6, "timestamp": t(14 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "13.225.18.5", "dst_port": "443", "protocol": "TLS", "action": "blocked", "domain": "telemetry-prd.ap.tesla.services", "source": "forward"},
			{"id": 7, "timestamp": t(17 * time.Second), "src_ip": "192.168.4.42", "src_mac": "F4:F5:D8:1A:22:C7", "dst_ip": "104.18.32.97", "dst_port": "443", "protocol": "TLS", "action": "allowed", "domain": "maps.googleapis.com", "source": "forward"},
			{"id": 8, "timestamp": t(20 * time.Second), "src_ip": "192.168.4.22", "src_mac": "98:01:A7:9B:0C:14", "dst_ip": "142.250.180.46", "dst_port": "443", "protocol": "TLS", "action": "allowed", "domain": "google.com", "source": "forward"},
			{"id": 9, "timestamp": t(23 * time.Second), "src_ip": "192.168.4.51", "src_mac": "5C:CF:7F:8E:A4:11", "dst_ip": "184.169.218.45", "dst_port": "443", "protocol": "TLS", "action": "blocked", "domain": "sonos.com", "source": "forward"},
		},
		muted: []kv{
			{"id": 901, "pattern": "captive.apple.com", "match_type": "suffix", "enabled": true, "created_at": "2026-03-12T09:00:00Z", "since_id": int64(0)},
			{"id": 902, "pattern": "msftconnecttest.com", "match_type": "suffix", "enabled": true, "created_at": "2026-04-02T09:00:00Z", "since_id": int64(0)},
		},
		settings: kv{
			"ap_ssid":            "Airgapp",
			"ap_password":        "preview-password",
			"ap_channel":         "36",
			"ap_country":         "BG",
			"dns_upstream":       "1.1.1.1,8.8.8.8",
			"log_retention_days": "30",
		},
		remote: kv{"installed": true, "daemon_active": true, "authenticated": true, "backend_state": "Running",
			"tailnet_hostname": "airgapp-preview.example.ts.net", "tailnet_ipv4": "100.64.0.1",
			"ble_funnel": true, "ble_funnel_url": "https://airgapp-preview.example.ts.net/api/ble"},
		audit: []kv{
			{"id": int64(1), "action": "tesla.ble_session_open", "details": "Phone opened a car session", "timestamp": time.Now().Add(-70 * time.Minute).UTC().Format("2006-01-02 15:04:05")},
			{"id": int64(2), "action": "tesla.ble_session_close", "details": "Phone closed a car session", "timestamp": time.Now().Add(-64 * time.Minute).UTC().Format("2006-01-02 15:04:05")},
			{"id": int64(3), "action": "tesla.ble_session_open", "details": "Phone opened a car session", "timestamp": time.Now().Add(-12 * time.Minute).UTC().Format("2006-01-02 15:04:05")},
		},
		tokens: []kv{{"id": int64(40), "name": "Phone", "created_at": time.Now().Add(-26 * time.Hour).UTC().Format(time.RFC3339),
			"last_used_at": time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339), "plain": "preview-token-not-real"}},
	}
	return s
}

// ── HTTP helpers ──────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func okJSON(w http.ResponseWriter) { writeJSON(w, kv{"status": "ok"}) }

// seedFilters is the filter set after the redesign's migrations: the Car
// system group (with its ports) and the apps. Domains are the public service
// hosts the migrations seed; notes are short and hit counts are invented.
func seedFilters() []kv {
	id := int64(1000)
	next := func() int64 { id++; return id }
	type d struct {
		host, note string
		hits       int
	}
	type p struct {
		proto string
		port  int
		desc  string
	}
	mk := func(name, grp string, builtin, on bool, ds []d, ps []p) kv {
		doms, ports := []kv{}, []kv{}
		for _, x := range ds {
			doms = append(doms, kv{"id": next(), "domain": x.host, "description": x.note, "hits": x.hits})
		}
		for _, x := range ps {
			ports = append(ports, kv{"proto": x.proto, "port": x.port, "description": x.desc})
		}
		return kv{"id": next(), "name": name, "description": "", "is_system": builtin, "enabled": on, "group": grp, "ports": ports, "domains": doms}
	}
	return []kv{
		mk("Navigation", "System", true, true, []d{{"tile.googleapis.com", "Map tiles", 2042}, {"apmv3.go.tesla.services", "Autopilot map data", 1714}, {"daws.tesla.services", "Navigation data", 603}, {"places.googleapis.com", "Search in Maps", 597}, {"maps-eu-prd.go.tesla.services", "EU maps backend", 592}, {"mt0.google.com", "Map tiles", 264}, {"maps.googleapis.com", "Maps", 233}, {"mt.l.google.com", "Map tiles", 19}, {"www.googleapis.com", "Terrain", 7}, {"mt1.google.com", "Map tiles", 0}, {"mt2.google.com", "Map tiles", 0}, {"mt3.google.com", "Map tiles", 0}}, nil),
		mk("Time", "System", true, true, []d{{"pool.ntp.org", "Public NTP pool", 1045}}, []p{{"UDP", 123, "NTP time sync — public pool.ntp.org"}}),
		mk("Grok", "System", true, true, []d{{"assistant-api.prd.na.vn.cloud.tesla.com", "Voice assistant — NA", 197}, {"speechcontainerpipeline.blob.core.windows.net", "Speech", 66}, {"assistant-api.prd.euw1.vn.cloud.tesla.com", "Voice assistant — EU", 2}}, []p{{"UDP", 18113, "Grok voice assistant — QUIC"}}),
		mk("Connectivity", "System", true, true, []d{{"google.com", "Online check", 5193}, {"www.google.com", "Online check", 1793}, {"gstatic.com", "Chrome", 17}}, []p{{"UDP", 443, "QUIC (HTTP/3) for Google, YouTube, Maps and other apps"}, {"TCP", 5228, "Google push notifications (FCM)"}, {"UDP", 19302, "Google STUN for WebRTC calls"}}),
		mk("YouTube", "", true, true, []d{{"youtube.com", "Web app and API", 1068}, {"ytimg.com", "Thumbnails", 662}, {"googlevideo.com", "Video", 572}, {"ggpht.com", "Channel avatars", 302}, {"youtu.be", "Short links", 0}}, nil),
		mk("Netflix", "", true, true, []d{{"netflix.com", "App and API", 480}, {"nflxvideo.net", "Video", 289}, {"nflxso.net", "Static", 188}, {"nflxext.com", "Assets", 90}, {"nflximg.com", "Images", 0}}, nil),
		mk("Twitch", "", true, true, []d{{"twitch.tv", "Twitch", 0}, {"ttvnw.net", "Streams", 0}, {"live-video.net", "Video", 0}}, nil),
		mk("TikTok", "", false, true, []d{{"tiktok.com", "", 68}, {"tiktokcdn.com", "Video", 2}}, nil),
		mk("Max", "", false, true, []d{{"max.com", "", 152}, {"hbomax.com", "", 290}}, nil),
		mk("Spotify", "", false, true, []d{{"spotify.com", "", 298}}, []p{{"TCP", 4070, "Spotify access point"}}),
		mk("Hulu", "", false, true, []d{{"hulu.com", "", 3}, {"disneyplus.com", "", 3}}, nil),
		mk("Prime", "", false, true, []d{{"primevideo.com", "", 3}}, nil),
		mk("F1", "", false, true, []d{{"formula1.com", "", 30}}, nil),
	}
}

// ── Traffic feed mock ─────────────────────────────────────

// feedSeed events exist when the preview starts; more arrive with time.
const feedSeed = 60

// feedTotal is how many events the log holds now, and how many arrive per
// second, for a scenario.
func feedTotal(scenario string) (total int64, perSec float64) {
	perSec = 1
	switch scenario {
	case "quiet":
		perSec = 0
	case "burst":
		perSec = 50
	}
	return feedSeed + int64(time.Since(startedAt).Seconds()*perSec), perSec
}

// mix is splitmix64: a well-spread number from n, so event n is the same on
// every request.
func mix(n uint64) uint64 {
	n += 0x9e3779b97f4a7c15
	n = (n ^ (n >> 30)) * 0xbf58476d1ce4e5b9
	n = (n ^ (n >> 27)) * 0x94d049bb133111eb
	return n ^ (n >> 31)
}

var (
	feedTeslaDanger = []string{"hermes-prd.ap.tesla.services", "ota.vn.tesla.services", "telemetry-prd.ap.tesla.services",
		"logupload.vn.tesla.services", "api.mp.tesla.services", "storage.googleapis.com", "i.scdn.co", "audio-ak-spotify-com.akamaized.net"}
	feedTeslaSafe  = []string{"maps-eu-prd.go.tesla.services", "tile.googleapis.com", "pool.ntp.org", "www.google.com"}
	feedHomeDanger = []string{"doubleclick.net", "app-measurement.com", "ads.example.net"}
	feedHomeSafe   = []string{"icloud.com", "github.com", "apple.com", "push.apple.com", "spotify.com", "api.sonos.com"}
)

// mockEvent is event n as the real feed would describe it, given the
// preview's filters now; muted reports a mute that drops it at ingest.
func mockEvent(n int64, perSec float64) (e kv, muted bool) {
	r := mix(uint64(n))
	pick := func(a []string, k uint64) string { return a[k%uint64(len(a))] }
	// Half the events are the Tesla's; the rest are spread over the others.
	others := []int{1, 2, 3, 4, 7}
	dev := state.devices[0]
	if r%2 == 1 {
		dev = state.devices[others[(r>>8)%uint64(len(others))]]
	}
	tesla := dev["id"] == 1
	danger := (r>>16)%100 < 22
	if tesla {
		danger = (r>>16)%100 < 70
	}
	var domain string
	switch {
	case tesla && danger:
		domain = pick(feedTeslaDanger, r>>24)
	case tesla:
		domain = pick(feedTeslaSafe, r>>24)
	case danger:
		domain = pick(feedHomeDanger, r>>24)
	default:
		domain = pick(feedHomeSafe, r>>24)
	}
	dst := fmt.Sprintf("203.0.113.%d", 1+(r>>32)%250)
	port, proto, action := "443", "TLS", "allowed"
	switch {
	case (r>>40)%100 < 26:
		dst, port, proto, action = "", "53", "DNS", "resolved"
		if danger {
			action = "sinkholed"
		}
	case danger && (r>>40)%100 < 40: // a QUIC drop by address: no domain
		domain, proto, action = "", "UDP", "blocked"
	case danger:
		action = "blocked"
	case (r>>48)%100 < 12:
		proto = "TCP"
	}
	locked := domain != "" && services.IsAlwaysBlocked(domain)
	cover := mockCover(domain)
	// Once a filter that's on lists a domain, its new events pass.
	if danger && !locked && cover != nil && cover["enabled"] == true {
		action = map[string]string{"sinkholed": "resolved", "blocked": "allowed"}[action]
	}
	mutedBy := ""
	for _, m := range state.muted {
		p := m["pattern"].(string)
		if domain != "" && (domain == p || strings.HasSuffix(domain, "."+p)) {
			mutedBy = p
			if since, ok := m["since_id"].(int64); ok && n > since {
				return nil, true
			}
		}
	}
	class := "allowed"
	if action == "blocked" || action == "sinkholed" {
		class = "blocked"
	}
	// Event feedSeed arrives as the preview starts; earlier ones before it.
	at := startedAt.Add(time.Duration(float64(n-feedSeed) / max(perSec, 1) * float64(time.Second)))
	name := dev["alias"].(string)
	if name == "" {
		name = dev["hostname"].(string)
	}
	if name == "" {
		name = "Unknown device"
	}
	var cv any
	if !locked && cover != nil {
		cv = cover
	}
	return kv{"id": n, "time": at.UTC().Format("2006-01-02 15:04:05"), "client": name, "client_ip": dev["ip_address"],
		"domain": domain, "dst_ip": dst, "port": port, "proto": proto, "action": action, "class": class,
		"locked": locked && class == "blocked", "cover": cv, "muted_by": mutedBy}, false
}

// mockCover is the preview filter listing domain, an enabled one first.
func mockCover(domain string) kv {
	if domain == "" {
		return nil
	}
	var off kv
	for _, f := range state.filters {
		for _, d := range f["domains"].([]kv) {
			x := d["domain"].(string)
			if domain == x || strings.HasSuffix(domain, "."+x) {
				c := kv{"id": f["id"], "name": f["name"], "enabled": f["enabled"]}
				if f["enabled"] == true {
					return c
				}
				if off == nil {
					off = c
				}
			}
		}
	}
	return off
}

// mockFeed answers a feed request the way the real handler does.
func mockFeed(q url.Values) kv {
	total, perSec := feedTotal(q.Get("scenario"))
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 80
	}
	if limit > 200 {
		limit = 200
	}
	outcome, proto := q.Get("outcome"), strings.ToUpper(q.Get("proto"))
	needle := strings.ToLower(strings.TrimSpace(q.Get("q")))
	out := []kv{}
	for n := total; n > after && n > 0 && len(out) < limit; n-- {
		e, muted := mockEvent(n, perSec)
		if muted {
			continue
		}
		if (outcome == "allowed" || outcome == "blocked") && e["class"] != outcome {
			continue
		}
		if proto != "" && proto != "ALL" && e["proto"] != proto {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(fmt.Sprint(e["domain"], " ", e["client"], " ", e["client_ip"], " ", e["dst_ip"], " ", e["port"])), needle) {
			continue
		}
		out = append(out, e)
	}
	return kv{"entries": out, "last_id": total, "muted": len(state.muted)}
}

// mockAudit records an activity entry the way the real handlers do (caller holds state.mu).
func mockAudit(action, details string) {
	state.audit = append(state.audit, kv{"id": int64(len(state.audit) + 1), "action": action, "details": details,
		"timestamp": time.Now().UTC().Format("2006-01-02 15:04:05")})
}

// startedAt anchors the mock's growing counters.
var startedAt = time.Now()

// ago is an RFC 3339 timestamp the given duration ("10m", "3h") before now.
func ago(d string) string {
	dur, _ := time.ParseDuration(d)
	return time.Now().Add(-dur).UTC().Format(time.RFC3339)
}

func writeStatusJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func extractIDFromTail(path string) int64 {
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	n, _ := strconv.ParseInt(last, 10, 64)
	return n
}

// ── Template renderer ─────────────────────────────────────

type renderer struct{ tmplFS fs.FS }

func (r *renderer) renderPage(w http.ResponseWriter, page string, data map[string]string) {
	tmpl, err := template.ParseFS(r.tmplFS, "layout.html", page)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

func (r *renderer) renderLogin(w http.ResponseWriter) {
	tmpl, err := template.ParseFS(r.tmplFS, "login.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := tmpl.ExecuteTemplate(w, filepath.Base("login.html"), nil); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

// ── Main ──────────────────────────────────────────────────

// listenAddr lets a second preview run beside one already holding :8080.
var listenAddr = flag.String("addr", ":8080", "listen address")

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())
	tmplFS, _ := fs.Sub(web.Content, "templates")
	staticFS, _ := fs.Sub(web.Content, "static")
	r := &renderer{tmplFS: tmplFS}

	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", handlers.StaticHandler(staticFS))) // the server's own caching
	mux.HandleFunc("/netfilter-ca.crt", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write([]byte("-----BEGIN CERTIFICATE-----\nMOCK PREVIEW CERT — not a real CA\n-----END CERTIFICATE-----\n"))
	})

	// ── Pages ─────────────────────────────────────────
	mux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) { r.renderLogin(w) })
	for _, old := range []string{"/settings", "/remote-access"} { // System replaced them
		mux.HandleFunc(old, func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/system", http.StatusMovedPermanently)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		r.renderPage(w, "dashboard.html", map[string]string{"page": "dashboard"})
	})
	for _, page := range []string{"devices", "traffic", "filters", "system"} {
		p := page
		mux.HandleFunc("/"+p, func(w http.ResponseWriter, req *http.Request) {
			r.renderPage(w, p+".html", map[string]string{"page": p})
		})
	}

	// ── API stubs ─────────────────────────────────────
	// Login: password "wrong" and "locked" exercise the login page's error paths.
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		json.NewDecoder(req.Body).Decode(&body)
		switch body.Password {
		case "wrong":
			writeStatusJSON(w, http.StatusUnauthorized, kv{"error": "invalid credentials"})
		case "locked":
			w.Header().Set("Retry-After", "119")
			writeStatusJSON(w, http.StatusTooManyRequests, kv{"error": "too many failed attempts; try again in 1m59s"})
		default:
			w.Header().Set("Set-Cookie", "netfilter_session=preview; Path=/; SameSite=Lax")
			okJSON(w)
		}
	})
	// Remote access (example data only: this repository is public).
	// ?scenario=tsout starts signed out; tsmissing starts with Tailscale not installed.
	mux.HandleFunc("/api/remote/status", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		switch req.URL.Query().Get("scenario") {
		case "tsout":
			if state.remote["scenarioSeen"] == nil {
				state.remote["scenarioSeen"], state.remote["authenticated"], state.remote["ble_funnel"] = true, false, false
			}
		case "funneloff":
			if state.remote["scenarioSeen"] == nil {
				state.remote["scenarioSeen"], state.remote["ble_funnel"], state.remote["ble_funnel_url"] = true, false, ""
				state.remote["ble_funnel_error"] = "Funnel isn't enabled for this tailnet. Turn it on at https://login.tailscale.com/f/funnel?node=preview, then retry."
			}
		case "tsmissing":
			if state.remote["scenarioSeen"] == nil {
				state.remote["scenarioSeen"], state.remote["installed"], state.remote["authenticated"], state.remote["ble_funnel"] = true, false, false, false
			}
		}
		out := kv{}
		for k, v := range state.remote {
			if k != "scenarioSeen" {
				out[k] = v
			}
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/remote/funnel/ble/enable", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.remote["ble_funnel"], state.remote["ble_funnel_url"] = true, "https://airgapp-preview.example.ts.net/api/ble"
		delete(state.remote, "ble_funnel_error")
		out := kv{}
		for k, v := range state.remote {
			if k != "scenarioSeen" {
				out[k] = v
			}
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/remote/up", func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			AuthKey string `json:"auth_key"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		if !strings.HasPrefix(strings.TrimSpace(body.AuthKey), "tskey-") {
			writeStatusJSON(w, http.StatusInternalServerError, kv{"error": "auth key must start with `tskey-`"})
			return
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		state.remote["authenticated"], state.remote["ble_funnel"], state.remote["backend_state"] = true, true, "Running"
		mockAudit("remote.up", "owner signed in to Tailscale")
		writeJSON(w, kv{"ok": true})
	})
	mux.HandleFunc("/api/remote/logout", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.remote["authenticated"], state.remote["ble_funnel"], state.remote["backend_state"] = false, false, "NeedsLogin"
		mockAudit("remote.logout", "owner signed out of Tailscale")
		writeJSON(w, kv{"ok": true})
	})
	mux.HandleFunc("/api/remote/install", func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(800 * time.Millisecond)
		state.mu.Lock()
		defer state.mu.Unlock()
		state.remote["installed"], state.remote["daemon_active"], state.remote["backend_state"] = true, true, "NeedsLogin"
		writeJSON(w, kv{"ok": true})
	})
	mux.HandleFunc("/api/tesla/tokens", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method == http.MethodPost {
			var body struct{ Name string }
			_ = json.NewDecoder(req.Body).Decode(&body)
			name := strings.TrimSpace(body.Name)
			if name == "" {
				writeStatusJSON(w, http.StatusBadRequest, kv{"error": "token name cannot be empty"})
				return
			}
			id := state.nextID
			state.nextID++
			t := kv{"id": id, "name": name, "created_at": time.Now().UTC().Format(time.RFC3339), "plain": fmt.Sprintf("preview-token-%d", id)}
			state.tokens = append(state.tokens, t)
			mockAudit("tesla.token_issue", "owner issued BLE client token '"+name+"'")
			writeJSON(w, kv{"token": kv{"id": id, "name": name, "created_at": t["created_at"]}, "plain": t["plain"]})
			return
		}
		writeJSON(w, kv{"tokens": state.tokens})
	})
	mux.HandleFunc("/api/tesla/tokens/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete {
			http.NotFound(w, req)
			return
		}
		id := extractIDFromTail(req.URL.Path)
		state.mu.Lock()
		defer state.mu.Unlock()
		for _, t := range state.tokens {
			if t["id"] == id {
				mockAudit("tesla.token_delete", "owner removed BLE client token '"+t["name"].(string)+"'")
			}
		}
		state.tokens = filterOutInt(state.tokens, "id", id)
		okJSON(w)
	})
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Set-Cookie", "netfilter_session=; Path=/; Max-Age=0")
		okJSON(w)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, kv{"username": "admin"})
	})

	// Dashboard: the Tesla (first mock device named like one) and the hosts it
	// contacted. The pick rotates every 3.2 s so the page's sweep can be seen.
	// ?scenario=none|quiet|few drive the empty states for the browser checks.
	mux.HandleFunc("/api/dashboard", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		var tesla kv
		for _, d := range state.devices {
			name := strings.ToLower(fmt.Sprint(d["alias"], " ", d["hostname"]))
			if strings.Contains(name, "tesla") {
				tesla = kv{"status": d["status"], "online": d["online"]}
				break
			}
		}
		state.mu.Unlock()
		scenario := req.URL.Query().Get("scenario")
		switch scenario {
		case "slow": // a Pi under load: the page must not stack polls or show "No Tesla yet" while waiting
			time.Sleep(5 * time.Second)
		case "error":
			writeStatusJSON(w, http.StatusInternalServerError, kv{"error": "database is locked"})
			return
		}
		if tesla == nil || scenario == "none" {
			writeJSON(w, kv{"tesla": nil, "hosts": []kv{}, "blocked_24h": 0, "allowed_24h": 0})
			return
		}
		type host struct {
			name string
			safe bool
		}
		pool := []host{
			{"maps-eu-prd.go.tesla.services", true}, {"hermes-prd.ap.tesla.services", false},
			{"apmv3.go.tesla.services", true}, {"telemetry-prd.ap.tesla.services", false},
			{"daws.tesla.services", true}, {"ota.vn.tesla.services", false},
			{"maps.googleapis.com", true}, {"logupload-prod.vn.tesla.services", false},
			{"fake.hypnos.vn.tesla.services", false}, {"connman.vn.tesla.services", false},
			{"a-very-long-diagnostic-upload-endpoint.prd.vn.tesla.services", false},
			{"events.vn.tesla.services", false}, {"metrics.vn.tesla.services", false},
			{"weather-prd.tesla.services", true},
		}
		n := 7
		switch scenario {
		case "quiet":
			n = 0
		case "few":
			n = 3
		}
		window := time.Now().UnixMilli() / 3200
		churn := scenario == "churn" // the same hosts, with fresh event ids on every poll
		if churn {
			window = 0
		}
		status := fmt.Sprint(tesla["status"])
		hosts := []kv{}
		for i := 0; i < n; i++ {
			h := pool[(int(window)*5+i*3)%len(pool)] // step 3 is coprime with 14: 7 distinct, mixed safe and danger
			crossed := h.safe
			switch status {
			case "open":
				crossed = true
			case "blocked":
				crossed = false
			}
			id := window*10 + int64(n-i)
			if churn {
				id = time.Now().UnixNano()/1000 + int64(n-i)
			}
			hosts = append(hosts, kv{"id": id, "domain": h.name, "crossed": crossed, "safe": h.safe})
		}
		grow := (time.Now().Unix() % 100000) / 3
		if n == 0 {
			grow = 0
		}
		writeJSON(w, kv{"tesla": tesla, "hosts": hosts, "blocked_24h": 48280 + grow*5, "allowed_24h": 9044 + grow*2})
	})

	// Devices, as the real API serves them: the Tesla carries tesla:true and
	// blocked_1h. Scenarios for the browser checks ride on the page's own query
	// string, which the page forwards: ?scenario=notesla hides the Tesla,
	// ?fail=status makes policy changes fail.
	listDevices := func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		out := []kv{}
		teslaSeen := false
		for _, d := range state.devices {
			v := kv{}
			for k, x := range d {
				v[k] = x
			}
			if !teslaSeen && strings.Contains(strings.ToLower(fmt.Sprint(d["alias"], " ", d["hostname"])), "tesla") {
				teslaSeen = true
				if req.URL.Query().Get("scenario") == "notesla" {
					continue
				}
				blocked := 318 + int(time.Since(startedAt).Seconds())/2
				if d["status"] == "open" {
					blocked = 0
				}
				v["tesla"], v["blocked_1h"] = true, blocked
				if req.URL.Query().Get("scenario") == "teslalogoff" && !state.teslaLogTouched {
					v["ignore_traffic_log"] = true
				}
			}
			out = append(out, v)
		}
		if req.URL.Query().Get("scenario") == "slowlist" {
			// A poll still in flight when the user changes something: like the real
			// server, the answer reflects the database when the request arrived.
			state.mu.Unlock()
			time.Sleep(1500 * time.Millisecond)
			state.mu.Lock()
		}
		writeJSON(w, out)
	}
	mux.HandleFunc("/api/devices", listDevices)
	mux.HandleFunc("/api/devices/", func(w http.ResponseWriter, req *http.Request) {
		// /api/devices/, /api/devices/activity, /api/devices/{mac}, /api/devices/{mac}/status
		path := strings.TrimPrefix(req.URL.Path, "/api/devices/")
		if path == "" && req.Method == http.MethodGet {
			listDevices(w, req)
			return
		}
		segs := strings.Split(path, "/")
		state.mu.Lock()
		defer state.mu.Unlock()
		if path == "activity" {
			active := []string{}
			for _, d := range state.devices {
				if d["online"] == true && rand.Intn(4) == 0 {
					active = append(active, d["mac_address"].(string))
				}
			}
			writeJSON(w, kv{"active": active})
			return
		}
		mac := strings.ToUpper(segs[0])
		switch req.Method {
		case http.MethodDelete:
			state.devices = filterOut(state.devices, "mac_address", mac)
			okJSON(w)
		case http.MethodPut:
			if len(segs) >= 2 && segs[1] == "status" {
				if req.URL.Query().Get("fail") == "status" {
					writeStatusJSON(w, http.StatusInternalServerError, kv{"error": "could not apply the firewall"})
					return
				}
				var body struct{ Status string }
				_ = json.NewDecoder(req.Body).Decode(&body)
				for _, d := range state.devices {
					if strings.EqualFold(d["mac_address"].(string), mac) {
						d["status"] = body.Status
					}
				}
				// Like the real API: the status is saved, then applying the firewall fails.
				if req.URL.Query().Get("fail") == "status-after-save" {
					writeStatusJSON(w, http.StatusInternalServerError, kv{"error": "status set but failed to apply firewall: nft exited 1"})
					return
				}
				okJSON(w)
				return
			}
			// Partial update, like the real API: only the fields sent change.
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			_, hasAlias := body["alias"]
			_, hasLog := body["ignore_traffic_log"]
			if !hasAlias && !hasLog {
				writeStatusJSON(w, http.StatusBadRequest, kv{"error": "nothing to update"})
				return
			}
			state.devicePuts = append(state.devicePuts, body)
			if hasLog && req.URL.Query().Get("scenario") == "teslalogoff" {
				state.teslaLogTouched = true
			}
			for _, d := range state.devices {
				if strings.EqualFold(d["mac_address"].(string), mac) {
					if hasAlias {
						d["alias"] = body["alias"]
					}
					if hasLog {
						d["ignore_traffic_log"] = body["ignore_traffic_log"]
					}
				}
			}
			okJSON(w)
		default:
			http.NotFound(w, req)
		}
	})
	// The browser check reads what the page sent.
	mux.HandleFunc("/__preview/device-puts", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		writeJSON(w, state.devicePuts)
	})

	// Filters, with the real API's shape and rules (services.CheckAllowable,
	// the name rule, duplicates, built-ins can't be deleted).
	filterView := func(f kv, withDomains bool) kv {
		v := kv{}
		for k, x := range f {
			if k != "domains" {
				v[k] = x
			}
		}
		if withDomains {
			ds := append([]kv{}, f["domains"].([]kv)...)
			sort.SliceStable(ds, func(i, j int) bool {
				if ds[i]["hits"].(int) != ds[j]["hits"].(int) {
					return ds[i]["hits"].(int) > ds[j]["hits"].(int)
				}
				return ds[i]["domain"].(string) < ds[j]["domain"].(string)
			})
			v["domains"] = ds
		}
		return v
	}
	findFilter := func(id int64) kv {
		for _, f := range state.filters {
			if f["id"].(int64) == id {
				return f
			}
		}
		return nil
	}
	listFilters := func(w http.ResponseWriter, req *http.Request) {
		with := req.URL.Query().Get("domains") == "1"
		out := []kv{}
		for _, f := range state.filters {
			out = append(out, filterView(f, with))
		}
		writeJSON(w, out)
	}
	mux.HandleFunc("/api/filters", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method != http.MethodPost {
			listFilters(w, req)
			return
		}
		var body struct{ Name string }
		_ = json.NewDecoder(req.Body).Decode(&body)
		name := strings.TrimSpace(body.Name)
		if !services.ValidPresetName(name) {
			writeStatusJSON(w, http.StatusBadRequest, kv{"error": "invalid filter name"})
			return
		}
		for _, f := range state.filters {
			if strings.EqualFold(f["name"].(string), name) {
				writeStatusJSON(w, http.StatusBadRequest, kv{"error": "a filter named " + name + " already exists"})
				return
			}
		}
		id := state.nextID
		state.nextID++
		state.filters = append(state.filters, kv{"id": id, "name": name, "description": "", "is_system": false, "enabled": false, "group": "", "ports": []kv{}, "domains": []kv{}})
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, kv{"id": id})
	})
	mux.HandleFunc("/api/filters/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/api/filters/")
		segs := strings.Split(path, "/")
		state.mu.Lock()
		defer state.mu.Unlock()
		if path == "" {
			listFilters(w, req)
			return
		}
		if path == "check" {
			d, err := services.CheckAllowable(req.URL.Query().Get("domain"))
			reason := ""
			if err != nil {
				reason = err.Error()
			}
			writeJSON(w, kv{"domain": d, "allowable": err == nil, "reason": reason})
			return
		}
		// DELETE /api/filters/domains/{id}
		if segs[0] == "domains" && len(segs) == 2 && req.Method == http.MethodDelete {
			id, _ := strconv.ParseInt(segs[1], 10, 64)
			for _, f := range state.filters {
				f["domains"] = filterOutInt(f["domains"].([]kv), "id", id)
			}
			okJSON(w)
			return
		}
		id, _ := strconv.ParseInt(segs[0], 10, 64)
		f := findFilter(id)
		if f == nil {
			writeStatusJSON(w, http.StatusNotFound, kv{"error": "filter not found"})
			return
		}
		switch {
		case len(segs) == 2 && segs[1] == "enabled" && req.Method == http.MethodPut:
			var body struct{ Enabled bool }
			_ = json.NewDecoder(req.Body).Decode(&body)
			f["enabled"] = body.Enabled
			okJSON(w)
		case len(segs) == 1 && req.Method == http.MethodDelete:
			if f["is_system"] == true {
				writeStatusJSON(w, http.StatusConflict, kv{"error": "system filters cannot be deleted"})
				return
			}
			state.filters = filterOutInt(state.filters, "id", id)
			okJSON(w)
		case len(segs) == 2 && segs[1] == "domains" && req.Method == http.MethodPost:
			var body struct{ Domain, Description string }
			_ = json.NewDecoder(req.Body).Decode(&body)
			d, err := services.CheckAllowable(body.Domain)
			if err != nil {
				writeStatusJSON(w, http.StatusBadRequest, kv{"error": err.Error()})
				return
			}
			for _, x := range f["domains"].([]kv) {
				if x["domain"] == d {
					writeStatusJSON(w, http.StatusBadRequest, kv{"error": d + " is already in " + f["name"].(string) + "."})
					return
				}
			}
			nid := state.nextID
			state.nextID++
			f["domains"] = append(f["domains"].([]kv), kv{"id": nid, "domain": d, "description": strings.TrimSpace(body.Description), "hits": 0})
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, kv{"id": nid})
		case len(segs) == 2 && segs[1] == "domains":
			out := []kv{}
			for _, x := range f["domains"].([]kv) {
				out = append(out, kv{"id": x["id"], "preset_id": id, "domain": x["domain"], "description": x["description"]})
			}
			writeJSON(w, out)
		default:
			writeJSON(w, filterView(f, false))
		}
	})

	mux.HandleFunc("/api/system/traffic", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.URL.Path == "/api/system/traffic/clear" || strings.HasSuffix(req.URL.Path, "/clear") {
			state.traffic = []kv{}
			okJSON(w)
			return
		}
		page, _ := strconv.Atoi(req.URL.Query().Get("page"))
		if page <= 0 {
			page = 1
		}
		writeJSON(w, kv{
			"entries": state.traffic,
			"total":   len(state.traffic),
			"page":    page,
			"pages":   1,
		})
	})
	mux.HandleFunc("/api/system/traffic/clear", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.traffic = []kv{}
		okJSON(w)
	})
	mux.HandleFunc("/api/system/traffic/muted", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method == http.MethodPost {
			var body struct{ Domain string }
			_ = json.NewDecoder(req.Body).Decode(&body)
			pattern := services.NormalizeDomain(body.Domain)
			if pattern == "" {
				writeStatusJSON(w, http.StatusBadRequest, kv{"error": services.ErrBadMuteDomain.Error()})
				return
			}
			for _, m := range state.muted { // the real AddMuted is idempotent
				if m["pattern"] == pattern {
					writeJSON(w, kv{"id": m["id"]})
					return
				}
			}
			id := state.nextID
			state.nextID++
			total, _ := feedTotal("")
			state.muted = append(state.muted, kv{"id": id, "pattern": pattern, "match_type": "suffix", "enabled": true,
				"created_at": time.Now().UTC().Format(time.RFC3339), "since_id": total})
			writeJSON(w, kv{"id": id})
			return
		}
		out := append([]kv{}, state.muted...)
		sort.Slice(out, func(i, j int) bool { return out[i]["pattern"].(string) < out[j]["pattern"].(string) })
		writeJSON(w, out)
	})

	// GET /api/traffic/feed, generated: event n depends on n alone and the
	// log grows with time, so a poll after an id sees only newer events.
	// ?scenario=quiet (no new events), burst (about 100 per poll), slow, error.
	mux.HandleFunc("/api/traffic/feed", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		switch q.Get("scenario") {
		case "error":
			writeStatusJSON(w, http.StatusInternalServerError, kv{"error": "feed unavailable"})
			return
		case "slow":
			time.Sleep(1500 * time.Millisecond)
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		writeJSON(w, mockFeed(q))
	})
	mux.HandleFunc("/api/system/traffic/muted/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete {
			http.NotFound(w, req)
			return
		}
		id := extractIDFromTail(req.URL.Path)
		state.mu.Lock()
		defer state.mu.Unlock()
		state.muted = filterOutInt(state.muted, "id", id)
		okJSON(w)
	})

	// Settings validated with the server's own rules. ?scenario=hotspotfail: the
	// hotspot "doesn't restart" after a valid save.
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if req.Method == http.MethodPut {
			var body map[string]string
			_ = json.NewDecoder(req.Body).Decode(&body)
			if err := services.ValidateSettings(body); err != nil {
				var se *services.SettingError
				if errors.As(err, &se) {
					writeStatusJSON(w, http.StatusBadRequest, kv{"error": se.Msg, "key": se.Key})
					return
				}
				writeStatusJSON(w, http.StatusBadRequest, kv{"error": err.Error()})
				return
			}
			hotspot := false
			keys := []string{}
			for k, v := range body {
				if k == "ap_password" && v == "" {
					continue
				}
				if k == "dns_upstream" {
					v = strings.Join(services.SplitUpstreams(v), ",")
				}
				state.settings[k] = v
				keys = append(keys, k)
				hotspot = hotspot || strings.HasPrefix(k, "ap_")
			}
			sort.Strings(keys)
			mockAudit("settings.update", "changed "+strings.Join(keys, ", "))
			if hotspot && req.URL.Query().Get("scenario") == "hotspotfail" {
				writeStatusJSON(w, http.StatusInternalServerError, kv{"error": "Saved, but the hotspot didn't restart: restart hostapd: exit status 1"})
				return
			}
			okJSON(w)
			return
		}
		out := kv{"ap_password_set": "false"}
		for k, v := range state.settings {
			if k == "ap_password" {
				if v != "" {
					out["ap_password_set"] = "true"
				}
				continue
			}
			out[k] = v
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/settings/password", func(w http.ResponseWriter, req *http.Request) {
		var body struct{ Password string }
		_ = json.NewDecoder(req.Body).Decode(&body)
		if len(body.Password) < 8 {
			writeStatusJSON(w, http.StatusBadRequest, kv{"error": "Use at least 8 characters."})
			return
		}
		writeJSON(w, kv{"signed_out": true})
	})

	mux.HandleFunc("/api/system/audit", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		out := []kv{}
		for i := len(state.audit) - 1; i >= 0 && len(out) < 14; i-- {
			out = append(out, state.audit[i])
		}
		writeJSON(w, kv{"entries": out, "total": 5206 + len(state.audit), "since": "2026-05-22 08:00:00"})
	})
	// Vitals that move like a live Pi: uptime ticks, counters grow. ?scenario=nothermal: no sensor.
	mux.HandleFunc("/api/system/vitals", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if !state.rebootAt.IsZero() && time.Since(state.rebootAt) < 6*time.Second {
			writeStatusJSON(w, http.StatusBadGateway, kv{"error": "rebooting"})
			return
		}
		boot := startedAt.Add(-50 * time.Hour)
		if !state.rebootAt.IsZero() {
			boot = state.rebootAt.Add(6 * time.Second)
		}
		el := time.Since(startedAt).Seconds()
		up := time.Since(boot).Seconds()
		var temp any = math.Round((36.5+math.Sin(el/9)*1.4)*10) / 10
		if req.URL.Query().Get("scenario") == "nothermal" {
			temp = nil
		}
		writeJSON(w, kv{"uptime_s": int64(up), "temp_c": temp, "load1": math.Round((0.19+math.Sin(el/7)*0.05)*100) / 100,
			"mem_used": uint64(268e6), "mem_total": uint64(3977e6), "disk_used": uint64(6.2e9), "disk_total": uint64(15.1e9),
			"wan_rx": uint64(972119 + up*14200), "wan_tx": uint64(1426105 + up*3100), "wan_if": "usb0",
			"wan_ip": "192.168.8.100", "lan_ip": "192.168.4.1", "model": "Raspberry Pi 4 Model B", "os": "Debian 13"})
	})
	mux.HandleFunc("/api/system/reboot", func(w http.ResponseWriter, req *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.rebootAt = time.Now()
		mockAudit("system.reboot", "user requested reboot")
		writeJSON(w, kv{"status": "rebooting"})
	})
	mux.HandleFunc("/api/system/connectivity", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, []kv{
			{"host": "1.1.1.1:53", "success": true, "latency": "38 ms"},
			{"host": "8.8.8.8:53", "success": true, "latency": "42 ms"},
			{"host": "google.com:443", "success": true, "latency": "62 ms"},
		})
	})

	addr := *listenAddr
	fmt.Printf("AIRGAP preview · open http://localhost%s\n", addr)
	fmt.Println("Stub data resets on every restart. State changes are in-memory only.")
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ── helpers ───────────────────────────────────────────────

func filterOut(in []kv, key string, val string) []kv {
	out := in[:0]
	for _, m := range in {
		if !strings.EqualFold(fmt.Sprint(m[key]), val) {
			out = append(out, m)
		}
	}
	return out
}
func filterOutInt(in []kv, key string, val int64) []kv {
	out := []kv{}
	for _, m := range in {
		if int64(toInt(m[key])) != val {
			out = append(out, m)
		}
	}
	return out
}
func toInt(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}
func countEnabled(rs []kv) int {
	n := 0
	for _, r := range rs {
		if r["enabled"] == true {
			n++
		}
	}
	return n
}
