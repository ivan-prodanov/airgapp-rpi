package models

import "time"

// Filter is a named bundle of allow-listed domains. A filter is GLOBAL:
// when its Enabled flag is true, every domain it contains applies to every
// device with status='filtered' (domains have no switch of their own). There is no per-device attachment — the operator
// toggles a filter on or off for the whole network.
//
// System filters (IsSystem=true) ship with the binary and represent
// curated, audited bundles for common services — Navigation, YouTube,
// Netflix, Disney+. They can still be edited or extended by the operator.
// User filters (IsSystem=false) are created in the UI.
type Filter struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsSystem    bool   `json:"is_system"`
	Enabled     bool   `json:"enabled"`
	// Group is an optional UI heading a filter is nested under (e.g.
	// "System" for Nav/Maps/Time/Grok/Connectivity). Empty = ungrouped.
	// Stored in the filters.grp column ("group" is a SQL reserved word).
	Group string `json:"group"`
	// Ports are the destination port-holes this filter opens for every
	// filtered device while it is enabled (filter_udp_ports /
	// filter_tcp_ports), each with its own justification. Read-only in the
	// API — seeded by migration and surfaced so the UI can list each as its
	// own row (without them, a filter with ports and no domains would
	// render empty). dst-agnostic: the DNS allow-list still gates
	// which IPs the device reaches on these ports.
	Ports     []FilterPort `json:"ports"`
	CreatedAt time.Time    `json:"created_at"`
}

// FilterPort is one port-hole a filter opens, with its justification.
// Read-only in the API (seeded by migration, not editable in the UI).
type FilterPort struct {
	Proto       string `json:"proto"` // "UDP" | "TCP"
	Port        int    `json:"port"`
	Description string `json:"description"`
}

// FilterDomain is one allow-list entry inside a filter. New rows are
// inserted disabled by default (review-then-enable). The protected-deny
// floor rejects inserts whose hostname matches a known-bad Tesla endpoint,
// and ancestor rejects refuse a broad parent whose suffix would re-admit
// one. The description column is enforced at the service layer to be
// non-empty — every entry needs a justification.
//
// The PresetID JSON field keeps its legacy name in the wire format and
// in the underlying preset_id column (renaming would force a full table
// rebuild for a cosmetic gain). It refers to filters.id.
type FilterDomain struct {
	ID             int64      `json:"id"`
	FilterID       int64      `json:"preset_id"` // legacy column name; UI calls it filter_id
	Domain         string     `json:"domain"`
	Description    string     `json:"description"`
	ResolvedIPs    string     `json:"resolved_ips"`
	LastResolvedAt *time.Time `json:"last_resolved_at,omitempty"`
	HitCount       int64      `json:"hit_count"`
	CreatedAt      time.Time  `json:"created_at"`
}
