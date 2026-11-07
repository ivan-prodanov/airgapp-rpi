package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
	"github.com/iulianfsdro/rpi-network-filter/internal/services"
)

// extractMAC URL-decodes the {mac} path param (chi does not decode path
// parameters), lowercases it, and validates the aa:bb:cc:dd:ee:ff shape
// via the canonical services.ValidMAC.
func extractMAC(r *http.Request) (string, error) {
	raw := chi.URLParam(r, "mac")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", errors.New("invalid mac encoding")
	}
	mac := strings.ToLower(strings.TrimSpace(decoded))
	if !services.ValidMAC(mac) {
		return "", errors.New("invalid mac format (want aa:bb:cc:dd:ee:ff)")
	}
	return mac, nil
}

type FiltersHandler struct {
	filter     *services.FilterService
	firewall   *services.FirewallService
	dns        *services.DNSService
	audit      *services.AuditService
	trafficLog *services.TrafficLogService
	sni        *services.SNIProxyService
	renderer   *Renderer

	hitsMu sync.Mutex // guards the 7-day hit counts, recomputed at most every 30 s
	hitsAt time.Time
	hits   map[string]int
}

func NewFiltersHandler(svc *services.Services, renderer *Renderer) *FiltersHandler {
	return &FiltersHandler{
		filter:     svc.Filter,
		firewall:   svc.Firewall,
		dns:        svc.DNS,
		audit:      svc.Audit,
		trafficLog: svc.TrafficLog,
		sni:        svc.SNIProxy,
		renderer:   renderer,
	}
}

func (h *FiltersHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.renderer.RenderPage(w, "filters.html", map[string]string{"page": "filters"})
}

// ── Filter CRUD ────────────────────────────────────────────────

// Check says whether a typed or pasted domain could be allow-listed at all:
// {domain, allowable, reason}. The Filters page's search uses it to tell
// "nothing allows this" apart from "nothing can ever allow this".
func (h *FiltersHandler) Check(w http.ResponseWriter, r *http.Request) {
	domain, err := services.CheckAllowable(r.URL.Query().Get("domain"))
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	JSON(w, http.StatusOK, map[string]any{"domain": domain, "allowable": err == nil, "reason": reason})
}

// domainHits is a filter domain as the Filters page shows it: its note and the
// allowed traffic it carried over the last 7 days.
type domainHits struct {
	ID          int64  `json:"id"`
	Domain      string `json:"domain"`
	Description string `json:"description"`
	Hits        int    `json:"hits"`
}

type filterWithDomains struct {
	models.Filter
	Domains []domainHits `json:"domains"`
}

// List returns every filter. With ?domains=1 each carries its domains and
// their 7-day hits, most-used first — everything the Filters page needs in
// one request.
func (h *FiltersHandler) List(w http.ResponseWriter, r *http.Request) {
	fs, err := h.filter.List()
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if fs == nil {
		fs = []models.Filter{}
	}
	if r.URL.Query().Get("domains") != "1" {
		JSON(w, http.StatusOK, fs)
		return
	}
	hosts := h.weekHits()
	out := make([]filterWithDomains, len(fs))
	for i, f := range fs {
		ds, err := h.filter.ListDomains(f.ID)
		if err != nil {
			JSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out[i] = filterWithDomains{Filter: f, Domains: make([]domainHits, len(ds))}
		for j, d := range ds {
			out[i].Domains[j] = domainHits{ID: d.ID, Domain: d.Domain, Description: d.Description, Hits: hitsFor(hosts, d.Domain)}
		}
		sort.SliceStable(out[i].Domains, func(a, b int) bool {
			da, db := out[i].Domains[a], out[i].Domains[b]
			if da.Hits != db.Hits {
				return da.Hits > db.Hits
			}
			return da.Domain < db.Domain
		})
	}
	JSON(w, http.StatusOK, out)
}

// weekHits is the allowed-traffic count per host over the last 7 days, cached
// for 30 s: the Filters page refreshes it, and the scan touches a week of log.
func (h *FiltersHandler) weekHits() map[string]int {
	h.hitsMu.Lock()
	defer h.hitsMu.Unlock()
	if h.hits != nil && time.Since(h.hitsAt) < 30*time.Second {
		return h.hits
	}
	m, err := h.trafficLog.AllowedByHostSince(time.Now().Add(-7 * 24 * time.Hour))
	if err != nil {
		log.Printf("[FILTERS] 7-day hits: %v", err)
		return map[string]int{}
	}
	h.hits, h.hitsAt = m, time.Now()
	return m
}

// hitsFor sums the hosts that are the domain or sit under it.
func hitsFor(hosts map[string]int, domain string) int {
	d := strings.ToLower(domain)
	n := 0
	for host, c := range hosts {
		if host == d || strings.HasSuffix(host, "."+d) {
			n += c
		}
	}
	return n
}

func (h *FiltersHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	f, err := h.filter.Get(id)
	if err != nil {
		if errors.Is(err, services.ErrFilterNotFound) {
			JSONError(w, http.StatusNotFound, "filter not found")
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, f)
}

func (h *FiltersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var f models.Filter
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id, err := h.filter.Create(f)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("filter.create", f.Name)
	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *FiltersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	var f models.Filter
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.filter.Update(id, f); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("filter.update", f.Name)
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// applyChange makes a change to what Filtered devices can reach take effect
// now, everywhere it is enforced: DNS (server= lines), the firewall (a filter's
// ports open with it), and the allow caches the SNI proxy and the traffic
// classifier would otherwise only refresh on their 30 s ticker.
func (h *FiltersHandler) applyChange() error {
	if err := h.dns.Apply(); err != nil {
		return fmt.Errorf("DNS: %w", err)
	}
	if err := h.firewall.Apply(); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	if h.trafficLog != nil {
		h.trafficLog.RefreshAllowCache()
	}
	if h.sni != nil {
		h.sni.RefreshCache()
	}
	return nil
}

// SetEnabled flips the global enable flag for a filter. Because filters
// are global, this changes the allow-list for every filtered device in
// one shot — re-apply DNS to pick up the new server= lines.
func (h *FiltersHandler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.filter.SetEnabled(id, req.Enabled); err != nil {
		if errors.Is(err, services.ErrFilterNotFound) {
			JSONError(w, http.StatusNotFound, "filter not found")
			return
		}
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("filter.set_enabled", strconv.FormatInt(id, 10)+"="+strconv.FormatBool(req.Enabled))
	// A filter may also carry UDP/TCP ports that open in lockstep with its
	// enable flag (Grok's udp/18113, Time's udp/123, Connectivity's tcp/5228,
	// Spotify's tcp/4070, …): applyChange re-applies the firewall too.
	if err := h.applyChange(); err != nil {
		JSONError(w, http.StatusInternalServerError, "saved but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *FiltersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	if err := h.filter.Delete(id); err != nil {
		switch {
		case errors.Is(err, services.ErrFilterNotFound):
			JSONError(w, http.StatusNotFound, "filter not found")
		case errors.Is(err, services.ErrSystemFilter):
			JSONError(w, http.StatusConflict, err.Error())
		default:
			JSONError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	h.audit.Log("filter.delete", strconv.FormatInt(id, 10))
	// A user filter can own ports (Spotify's tcp/4070 since v29): the firewall
	// must close them now, not on the next unrelated apply.
	if err := h.applyChange(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Per-filter domain list ─────────────────────────────────────

func (h *FiltersHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	filterID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	ds, err := h.filter.ListDomains(filterID)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ds == nil {
		ds = []models.FilterDomain{}
	}
	JSON(w, http.StatusOK, ds)
}

func (h *FiltersHandler) CreateDomain(w http.ResponseWriter, r *http.Request) {
	filterID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid filter id")
		return
	}
	var d models.FilterDomain
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// CreateDomain rejects empty descriptions and protected/ancestor names.
	id, err := h.filter.CreateDomain(filterID, d)
	if err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("filter.domain.create", d.Domain)
	if err := h.applyChange(); err != nil {
		JSONError(w, http.StatusInternalServerError, "saved but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *FiltersHandler) UpdateDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "domainID"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	var d struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.filter.UpdateDomain(id, d.Description); err != nil {
		JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log("filter.domain.update", strconv.FormatInt(id, 10))
	if err := h.dns.Apply(); err != nil {
		JSONError(w, http.StatusInternalServerError, "updated but failed to apply DNS: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *FiltersHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "domainID"), 10, 64)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "invalid domain id")
		return
	}
	if err := h.filter.DeleteDomain(id); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit.Log("filter.domain.delete", strconv.FormatInt(id, 10))
	if err := h.applyChange(); err != nil {
		JSONError(w, http.StatusInternalServerError, "deleted but failed to apply: "+err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
