package services

import "strings"

// protectedDeny is the immutable safety floor: Tesla endpoints that must
// NEVER be reachable — the command channel (Hermes), OTA / firmware,
// telemetry, log upload, Sentry / dashcam upload, manufacturing, and
// engineering hosts. isProtectedDenied() is consulted at THREE points —
// allow-list add (rejected), the SNI proxy (dropped), and the DNS
// generator (no server= line). A match here overrides any allow-list
// entry: deny always wins. This is a hardcoded constant, not a
// user-editable table — it cannot be misconfigured or fat-fingered away.
//
// Most entries are *apex* denials — denying a whole Tesla sub-tree (e.g.
// vn.cloud.tesla.com) catches regional and future hostname variants, not
// just the specific hosts observed so far. This matters: a Tesla in the
// EU uses hermes-stream-api.prd.eu.vn.cloud.tesla.com, which a region-
// specific exact list would miss. Roots that also serve *allowed* traffic
// (tesla.com hosts auth.tesla.com; the shared AWS S3) get specific host
// entries instead of an apex.
var protectedDeny = []string{
	// Apex denials — Tesla sub-trees with nothing legitimate underneath.
	"ap.tesla.services",     // hermes, telemetry, api-prd, x1, s3, *-eng
	"vn.tesla.services",     // telemetry, logupload, ota, firmware, diag, hypnos
	"cn.tesla.services",     // China region
	"mo.tesla.services",     // manufacturing
	"eng.go.tesla.services", // engineering nav (navsrv.eng.go.tesla.services)
	"vn.cloud.tesla.com",    // vehicle-network cloud — hermes/device/apf/assistant, every region
	"obs.tesla.com",         // Sentry / dashcam upload
	"teslamotors.com",       // mothership, firmware, toolbox, corp, remote-access-registry
	"tslans.net",            // hermes cellular fallback, factory provisioning
	"tesla-cdn.com",         // firmware / asset CDN
	"tesla-cdn.net",
	// Specific hosts under roots that also serve allowed traffic.
	"software-update.tesla.com",
	"dl.tesla.com",
	"remote-diagnostics.tesla.com",
	"github-fw.tesla.com",
	"toolbox.tesla.com",
	"epc.tesla.com",
	"parts.tesla.com",
	"tesla-hermes-snapshot.s3.us-west-2.amazonaws.com",
	"tesla-hermes-snapshot-eu.s3.eu-central-1.amazonaws.com",
	"tesla-hermes-snapshot-eng.s3.us-west-2.amazonaws.com",
	"tesla-hermes-snapshot-eng-eu.s3.eu-central-1.amazonaws.com",
}

// assistantExempt is the narrow carve-out from the vn.cloud.tesla.com apex
// deny: the Grok / in-car voice-assistant hosts. These are EXACT hostnames,
// never a suffix — so the apex keeps denying hermes/device/web/apf and any
// future regional service, and ONLY these specific assistant endpoints
// become allow-able. Audited safe: per-host leaf cert (no wildcard, no
// cross-service SAN), a disjoint ELB from hermes, VIN-mTLS + QUIC voice
// only, and it carries no log-grab/integrity-audit channel. It is opened
// via the Grok system filter, not by default.
var assistantExempt = map[string]bool{
	"assistant-api.prd.euw1.vn.cloud.tesla.com": true, // EU
	"assistant-api.prd.na.vn.cloud.tesla.com":   true, // NA
	"assistant-api.prd.cnn1.vn.cloud.tesla.cn":  true, // CN
	"assistant-api.eng.euw1.vn.cloud.tesla.com": true, // eng (unused on prod cars)
	"assistant-api.eng.na.vn.cloud.tesla.com":   true,
}

// isProtectedDenied reports whether domain is — or is a sub-domain of — a
// protected Tesla endpoint, in which case it must never be reached
// regardless of any allow-list entry. Two exemptions sit under denied
// apexes but are explicitly allowed: the connman captive-check host
// (benign, spoofed locally on :80) and the exact Grok assistant hosts.
func isProtectedDenied(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return false
	}
	if d == spoofConnManHost {
		return false
	}
	if assistantExempt[d] {
		return false
	}
	for _, p := range protectedDeny {
		if d == p || strings.HasSuffix(d, "."+p) {
			return true
		}
	}
	return false
}

// isProtectedAncestor reports whether domain is a *parent* of a protected
// endpoint — allow-listing it (a suffix match) would sweep the protected
// endpoint in. Used only as an add-time guard: it forces the operator to
// allow specific sub-domains rather than a broad parent (e.g. reject
// "go.tesla.services", which would otherwise admit "navsrv.eng.go.tesla.services").
func isProtectedAncestor(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return false
	}
	for _, p := range protectedDeny {
		if strings.HasSuffix(p, "."+d) {
			return true
		}
	}
	return false
}

// ProtectedDenyCount returns the number of entries on the protected-deny
// floor. Used by the dashboard handler so the Guardian hero displays
// "<N> endpoints sealed" without UI code needing to know the constant.
func ProtectedDenyCount() int { return len(protectedDeny) }
