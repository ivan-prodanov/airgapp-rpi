package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// pickTesla returns the device the Dashboard is about: the one whose alias or
// hostname mentions "tesla" (any case). Among several, an online one wins, then
// the most recently seen. nil when there is none.
func pickTesla(devs []models.Device) *models.Device {
	var best *models.Device
	for i := range devs {
		d := devs[i]
		if !strings.Contains(strings.ToLower(d.Alias+" "+d.Hostname), "tesla") {
			continue
		}
		if best == nil ||
			(d.Online && !best.Online) ||
			(d.Online == best.Online && d.LastSeen.After(best.LastSeen)) {
			c := d
			best = &c
		}
	}
	return best
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

// API serves the Dashboard: the Tesla's policy, the hosts it contacted most
// recently (one lane each on the gate) and its event counts over 24 h. With no
// Tesla on the network, tesla is null and the rest is empty.
func (h *DashboardHandler) API(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"tesla": nil, "hosts": []services.HostVerdict{}, "blocked_24h": 0, "allowed_24h": 0}
	devs, err := h.svc.Network.ListDevices()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	if t := pickTesla(devs); t != nil {
		since := time.Now().Add(-24 * time.Hour)
		hosts, err := h.svc.TrafficLog.RecentHosts(t.MACAddress, t.IPAddress, since, 7)
		if err != nil {
			hosts = []services.HostVerdict{} // best-effort: the headline still renders
		}
		blocked, allowed := h.svc.TrafficLog.ClassCountsSince(t.MACAddress, t.IPAddress, since)
		resp["tesla"] = map[string]any{"status": t.Status, "online": t.Online}
		resp["hosts"] = hosts
		resp["blocked_24h"] = blocked
		resp["allowed_24h"] = allowed
	}
	JSON(w, http.StatusOK, resp)
}
