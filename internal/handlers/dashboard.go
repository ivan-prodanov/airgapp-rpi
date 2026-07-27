package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// compactAge renders an age for a one-line stat row: a single unit, no
// zero-valued tail. time.Duration's own String gives "9h0m0s" for nine hours,
// which is three units of noise in a row that has to read at a glance. A
// negative age (a clock step between the two reads) renders as "0s" rather
// than as a minus sign nobody can interpret.
func compactAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		if d < 0 {
			d = 0
		}
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + "d"
	}
}

type DashboardHandler struct {
	svc      *services.Services
	renderer *Renderer
}

func NewDashboardHandler(svc *services.Services, renderer *Renderer) *DashboardHandler {
	return &DashboardHandler{svc: svc, renderer: renderer}
}

func (h *DashboardHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "dashboard.html", map[string]string{"page": "dashboard"})
}

func (h *DashboardHandler) API(w http.ResponseWriter, r *http.Request) {
	online, total, _ := h.svc.Network.GetDeviceCount()
	sysInfo := h.svc.System.GetInfo()

	fwRules, _ := h.svc.Firewall.ListRules()
	activeRules := 0
	for _, r := range fwRules {
		if r.Enabled {
			activeRules++
		}
	}

	filters, _ := h.svc.Filter.List()
	enabledFilters := 0
	for _, f := range filters {
		if f.Enabled {
			enabledFilters++
		}
	}

	// Guardian hero counters: blocked / allowed over the trailing 24 h, plus
	// the size of the compile-time protected-deny floor. Best-effort — a
	// failed DB count folds to 0 so the dashboard never breaks the page.
	since := time.Now().Add(-24 * time.Hour)
	blocked24h := h.svc.TrafficLog.CountByActionSince("blocked", since)
	allowed24h := h.svc.TrafficLog.CountByActionSince("allowed", since)

	// Lock-gated WiFi (observe-only in Phase 1): what the watcher believes.
	lw := h.svc.LockWatch.Status()
	lockText := "Unknown"
	if lw.HaveStatus {
		if lw.Locked {
			lockText = "Locked"
		} else {
			lockText = "Unlocked"
		}
	}
	occupantText := "Unknown"
	if lw.HaveStatus {
		if lw.Present {
			occupantText = "Present"
		} else {
			occupantText = "Empty"
		}
	}
	lastSignalText := "never"
	if !lw.LastSignal.IsZero() {
		lastSignalText = time.Since(lw.LastSignal).Truncate(time.Second).String() + " ago"
	}
	// Link state is the ONLY field that separates "subscribed to a live session
	// and the car has said nothing" from "no VIN / dead adapter / out of range /
	// never subscribed at all" — every one of those renders identically in the
	// four rows above (Unknown / Unknown / Should be UP / never). The watcher
	// sets SessionID only after Subscribe succeeds and clears it on every exit
	// path, so it is exactly "are we attached right now".
	//
	// "Attached" alone still under-reports, though: it reads the same after two
	// seconds of a healthy quiet link as after nine hours of a link that has
	// said nothing. Age + frame count separate them — "Attached 2s · 0 frames"
	// is normal, "Attached 9h · 0 frames" is a car that has almost certainly
	// gone. Both come from the current attachment and are cleared with it.
	linkText := "Not attached"
	if lw.SessionID != "" {
		linkText = "Attached"
		if !lw.AttachedSince.IsZero() {
			linkText += " " + compactAge(time.Since(lw.AttachedSince))
		}
		linkText += " · " + strconv.Itoa(lw.FramesSeen) + " frame"
		if lw.FramesSeen != 1 {
			linkText += "s"
		}
	}

	JSON(w, http.StatusOK, map[string]any{
		"devices_online":    online,
		"devices_total":     total,
		"firewall_rules":    activeRules,
		"filters_total":     len(filters),
		"filters_enabled":   enabledFilters,
		"protected_deny":    services.ProtectedDenyCount(),
		"blocked_24h":       blocked24h,
		"allowed_24h":       allowed24h,
		"wan_reachable":     true, // placeholder until a WAN probe lives in SystemService
		"system":            sysInfo,
		"lock_state":        lockText,
		"lock_occupant":     occupantText,
		"lock_wifi_verdict": map[bool]string{true: "Should be UP", false: "Should be DOWN"}[lw.APShouldBeUp],
		"lock_last_signal":  lastSignalText,
		"lock_link":         linkText,
	})
}
