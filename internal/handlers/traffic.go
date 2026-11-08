package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// TrafficHandler serves the Traffic page's feed.
type TrafficHandler struct {
	trafficLog *services.TrafficLogService
	filter     *services.FilterService
	network    *services.NetworkService
}

func NewTrafficHandler(svc *services.Services) *TrafficHandler {
	return &TrafficHandler{trafficLog: svc.TrafficLog, filter: svc.Filter, network: svc.Network}
}

// feedEntry is one ledger row, with everything the row shows worked out here
// so the page needs one request per tick.
type feedEntry struct {
	ID       int64                 `json:"id"`
	Time     string                `json:"time"`
	Client   string                `json:"client"`
	ClientIP string                `json:"client_ip"`
	Domain   string                `json:"domain"`
	DstIP    string                `json:"dst_ip"`
	Port     string                `json:"port"`
	Proto    string                `json:"proto"`
	Action   string                `json:"action"`
	Class    string                `json:"class"`  // "allowed", "blocked", "unreachable", or ""
	Locked   bool                  `json:"locked"` // always blocked: Allow is shown locked
	Cover    *services.FilterCover `json:"cover"`  // the filter that lists the domain
	MutedBy  string                `json:"muted_by"`
}

// verdictClass maps an action onto the labels the console uses: allowed,
// blocked, or unreachable (allowed through, but the site never answered).
func verdictClass(action string) string {
	switch action {
	case "allowed", "resolved":
		return "allowed"
	case "blocked", "sinkholed":
		return "blocked"
	case "unreachable":
		return "unreachable"
	}
	return ""
}

// deviceName is how the console names a device: alias, else hostname.
func deviceName(d models.Device) string {
	if a := strings.TrimSpace(d.Alias); a != "" {
		return a
	}
	if h := strings.TrimSpace(d.Hostname); h != "" {
		return h
	}
	return "Unknown device"
}

// Feed is GET /api/traffic/feed?after=&outcome=&proto=&q=&limit=.
func (h *TrafficHandler) Feed(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	search := strings.TrimSpace(q.Get("q"))
	devices, err := h.network.ListDevices()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var named []string // devices whose name matches the search
	if needle := strings.ToLower(search); needle != "" {
		for _, d := range devices {
			if d.IPAddress != "" && (strings.Contains(strings.ToLower(d.Alias), needle) || strings.Contains(strings.ToLower(d.Hostname), needle)) {
				named = append(named, d.IPAddress)
			}
		}
	}
	rows, lastID, err := h.trafficLog.Feed(services.FeedFilter{
		After: after, Outcome: q.Get("outcome"), Proto: q.Get("proto"), Query: search, Limit: limit, ClientIPs: named,
	})
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cover, err := h.filter.CoverIndex()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// ListDevices is newest-seen first, so an IP reused by DHCP names the
	// device that holds it now.
	byMAC, byIP := map[string]string{}, map[string]string{}
	for _, d := range devices {
		byMAC[strings.ToUpper(d.MACAddress)] = deviceName(d)
		if d.IPAddress != "" {
			if _, seen := byIP[d.IPAddress]; !seen {
				byIP[d.IPAddress] = deviceName(d)
			}
		}
	}
	muted, err := h.trafficLog.ListMuted()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := make([]feedEntry, 0, len(rows))
	for _, e := range rows {
		action := h.trafficLog.Verdict(e)
		fe := feedEntry{
			ID: e.ID, Time: e.Timestamp, ClientIP: e.SrcIP, Domain: e.Domain, DstIP: e.DstIP,
			Port: e.DstPort, Proto: strings.ToUpper(e.Protocol), Action: action, Class: verdictClass(action),
			MutedBy: h.trafficLog.MutedBy(e.Domain),
		}
		if name, ok := byMAC[services.SourceMAC(e.SrcMAC)]; ok {
			fe.Client = name
		} else if name, ok := byIP[e.SrcIP]; ok {
			fe.Client = name
		} else {
			fe.Client = e.SrcIP
		}
		if e.Domain != "" {
			fe.Locked = fe.Class == "blocked" && services.IsAlwaysBlocked(e.Domain)
			if !fe.Locked {
				fe.Cover = cover(e.Domain)
			}
		}
		out = append(out, fe)
	}
	JSON(w, http.StatusOK, map[string]any{"entries": out, "last_id": lastID, "muted": len(muted)})
}
