package services

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

var (
	ErrFilterNotFound = errors.New("filter not found")
	ErrSystemFilter   = errors.New("system filters cannot be deleted")
)

// FilterService owns CRUD over the filter model: filters (the curated
// bundles), per-filter domain allow-lists, and the per-filter enable
// toggle. A filter with enabled=1 applies to EVERY device with
// status='filtered' — there are no per-device attachments. The SNI proxy
// reads from this service to build its global allow-list cache; the
// firewall service reads device status (via NetworkService) to classify
// forward traffic.
type FilterService struct {
	db *sql.DB
}

func NewFilterService(db *sql.DB) *FilterService {
	return &FilterService{db: db}
}

// ── Filters ────────────────────────────────────────────────────

func (s *FilterService) List() ([]models.Filter, error) {
	rows, err := s.db.Query(`
		SELECT id, name, description, is_system, enabled, grp, created_at
		FROM filters ORDER BY grp DESC, is_system DESC, name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list filters: %w", err)
	}
	defer rows.Close()

	var out []models.Filter
	for rows.Next() {
		var f models.Filter
		var sys, en int
		if err := rows.Scan(&f.ID, &f.Name, &f.Description, &sys, &en, &f.Group, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan filter: %w", err)
		}
		f.IsSystem = sys == 1
		f.Enabled = en == 1
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list filters rows: %w", err)
	}
	// Attach the port-holes each filter opens (read-only display). One bulk
	// map covers both tables — O(1) queries, not N+1.
	ports := s.loadPorts()
	for i := range out {
		out[i].Ports = ports[out[i].ID]
	}
	return out, nil
}

// loadPorts returns preset_id -> the port-holes (UDP then TCP, ascending)
// each filter opens, with their descriptions. Tolerant of a missing table or
// query error (skips that table) so the filters list never fails just because
// ports can't be read — mirrors the firewall service's defensive port reads.
func (s *FilterService) loadPorts() map[int64][]models.FilterPort {
	m := map[int64][]models.FilterPort{}
	for _, t := range []struct{ table, proto string }{
		{"filter_udp_ports", "UDP"},
		{"filter_tcp_ports", "TCP"},
	} {
		rows, err := s.db.Query("SELECT preset_id, port, description FROM " + t.table + " ORDER BY port ASC")
		if err != nil {
			continue
		}
		for rows.Next() {
			var pid int64
			var port int
			var desc string
			if err := rows.Scan(&pid, &port, &desc); err == nil {
				m[pid] = append(m[pid], models.FilterPort{Proto: t.proto, Port: port, Description: desc})
			}
		}
		rows.Close()
	}
	return m
}

func (s *FilterService) Get(id int64) (models.Filter, error) {
	var f models.Filter
	var sys, en int
	err := s.db.QueryRow(`
		SELECT id, name, description, is_system, enabled, grp, created_at
		FROM filters WHERE id = ?
	`, id).Scan(&f.ID, &f.Name, &f.Description, &sys, &en, &f.Group, &f.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrFilterNotFound
	}
	if err != nil {
		return f, fmt.Errorf("get filter %d: %w", id, err)
	}
	f.IsSystem = sys == 1
	f.Enabled = en == 1
	f.Ports = s.loadPorts()[f.ID]
	return f, nil
}

func (s *FilterService) Create(f models.Filter) (int64, error) {
	f.Name = strings.TrimSpace(f.Name)
	if !ValidPresetName(f.Name) {
		return 0, fmt.Errorf("invalid filter name: must be 1-64 chars, letters/digits/space/_/-/+/'/' only (start alphanumeric)")
	}
	// User-created filters are never system filters and start disabled
	// (the operator opts in by flipping the enable toggle).
	res, err := s.db.Exec(`
		INSERT INTO filters (name, description, is_system, enabled) VALUES (?, ?, 0, 0)
	`, f.Name, f.Description)
	if err != nil {
		return 0, fmt.Errorf("insert filter: %w", err)
	}
	return res.LastInsertId()
}

// Update edits the name and description. The Enabled flag has its own
// dedicated setter so a UI bug can't accidentally clear a live filter.
func (s *FilterService) Update(id int64, f models.Filter) error {
	f.Name = strings.TrimSpace(f.Name)
	if !ValidPresetName(f.Name) {
		return fmt.Errorf("invalid filter name")
	}
	_, err := s.db.Exec(`UPDATE filters SET name=?, description=? WHERE id=?`, f.Name, f.Description, id)
	if err != nil {
		return fmt.Errorf("update filter %d: %w", id, err)
	}
	return nil
}

// SetEnabled flips the global enable flag — when true, every domain in
// this filter applies to all filtered devices.
func (s *FilterService) SetEnabled(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	res, err := s.db.Exec(`UPDATE filters SET enabled=? WHERE id=?`, v, id)
	if err != nil {
		return fmt.Errorf("set enabled on filter %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrFilterNotFound
	}
	return nil
}

func (s *FilterService) Delete(id int64) error {
	// Guard system filters — removing seeded Tesla AP/Nav by accident
	// would silently break the curated set. System filters can be edited
	// or extended but not deleted.
	var sys int
	if err := s.db.QueryRow("SELECT is_system FROM filters WHERE id = ?", id).Scan(&sys); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFilterNotFound
		}
		return err
	}
	if sys == 1 {
		return ErrSystemFilter
	}
	_, err := s.db.Exec("DELETE FROM filters WHERE id = ?", id)
	return err
}

// ── Per-filter domain list ─────────────────────────────────────

func (s *FilterService) ListDomains(filterID int64) ([]models.FilterDomain, error) {
	rows, err := s.db.Query(`
		SELECT id, preset_id, domain, description,
		       resolved_ips, last_resolved_at, hit_count, created_at
		FROM filter_domains
		WHERE preset_id = ?
		ORDER BY domain ASC
	`, filterID)
	if err != nil {
		return nil, fmt.Errorf("list filter domains: %w", err)
	}
	defer rows.Close()

	var out []models.FilterDomain
	for rows.Next() {
		var d models.FilterDomain
		if err := rows.Scan(&d.ID, &d.FilterID, &d.Domain, &d.Description,
			&d.ResolvedIPs, &d.LastResolvedAt, &d.HitCount, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan filter domain: %w", err)
		}
		out = append(out, d)
	}
	return out, nil
}

// ErrBadDomain is the answer to anything that isn't a hostname.
var ErrBadDomain = errors.New("Enter a domain like cdn.example.com.")

// CreateDomain adds a domain to a filter; it applies whenever the filter is
// on. The note is optional. A pasted URL is accepted as its host. The
// always-blocked floor rejects known Tesla endpoints and parents broad enough
// to re-admit one, and a domain already in the filter is refused. The errors
// are written for the Filters page, which shows them as they are.
func (s *FilterService) CreateDomain(filterID int64, d models.FilterDomain) (int64, error) {
	domain := NormalizeDomain(d.Domain)
	if domain == "" {
		return 0, ErrBadDomain
	}
	if isProtectedDenied(domain) {
		return 0, fmt.Errorf("%s is always blocked. It can't be allowed.", domain)
	}
	if isProtectedAncestor(domain) {
		return 0, fmt.Errorf("%s is too broad: it would also allow always-blocked Tesla domains. Add the exact subdomain instead.", domain)
	}
	var id int64
	err := s.db.QueryRow(`
		INSERT INTO filter_domains (preset_id, domain, description)
		VALUES (?, ?, ?)
		ON CONFLICT(preset_id, domain) DO NOTHING
		RETURNING id
	`, filterID, domain, strings.TrimSpace(d.Description)).Scan(&id)
	if err == sql.ErrNoRows {
		var name string
		s.db.QueryRow(`SELECT name FROM filters WHERE id = ?`, filterID).Scan(&name)
		return 0, fmt.Errorf("%s is already in %s.", domain, name)
	}
	if err != nil {
		return 0, fmt.Errorf("add filter domain: %w", err)
	}
	return id, nil
}

// UpdateDomain sets a domain's note (optional; empty clears it).
func (s *FilterService) UpdateDomain(id int64, description string) error {
	_, err := s.db.Exec(`UPDATE filter_domains SET description = ? WHERE id = ?`, strings.TrimSpace(description), id)
	return err
}

func (s *FilterService) DeleteDomain(id int64) error {
	_, err := s.db.Exec("DELETE FROM filter_domains WHERE id = ?", id)
	return err
}
