package services

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Input-validation helpers. Every value that flows into nftables / dnsmasq /
// hostapd config files MUST pass one of these before being persisted or
// emitted — the config files are parsed as shell-like DSLs and a newline
// or metacharacter in a string field is a direct rule-injection vector.

var (
	presetNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _+/-]{0,63}$`)
	domainNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	portSpecRe   = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)
	macStrictRe  = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

	protocolValid = map[string]bool{
		"":     true,
		"all":  true,
		"tcp":  true,
		"udp":  true,
		"icmp": true,
	}
)

// ValidPresetName: letters, digits, space, underscore, hyphen, +, /; first
// char must be alphanumeric; 1-64 chars. Allows '+' and '/' so "Disney+"
// and "Apple TV/Music" are spellable. Blocks nft metacharacters like `]`,
// `\n`, `"`, `;`, `{`, `}`, `#` that would terminate a log prefix string.
func ValidPresetName(s string) bool {
	return presetNameRe.MatchString(s)
}

// ValidDomain: strict RFC-ish hostname check, <=253 chars. Rejects `/`,
// whitespace, `#`, and any other character that would break dnsmasq's
// `nftset=` / `address=` directives.
func ValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	return domainNameRe.MatchString(s)
}

// ValidIPv4: net.ParseIP + To4 conversion. Rejects IPv6, CIDR, and any
// string with trailing garbage like "1.2.3.4 extra".
func ValidIPv4(s string) bool {
	s = strings.TrimSpace(s)
	// A dotted quad only: ParseIP also accepts IPv4-mapped IPv6 ("::ffff:9.9.9.9"),
	// which nft refuses in an ip-family rule.
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && !strings.Contains(s, ":")
}

// ValidIPOrCIDR: a single IPv4 or a CIDR.
func ValidIPOrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return ValidIPv4(s)
}

// ValidPortSpec: single port or hyphen range, each 1-65535. Empty ok.
func ValidPortSpec(s string) bool {
	if s == "" {
		return true
	}
	return portSpecRe.MatchString(s)
}

// ValidProtocol: matches the DB CHECK on firewall_rules.protocol.
func ValidProtocol(s string) bool {
	return protocolValid[s]
}

// ValidMAC: aa:bb:cc:dd:ee:ff exactly (case-insensitive, lowercased).
func ValidMAC(s string) bool {
	return macStrictRe.MatchString(strings.ToLower(s))
}

// urlSchemeRe matches a URL scheme prefix ("https://") on a pasted address.
var urlSchemeRe = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`)

// NormalizeDomain lowercases and trims, forgives a pasted URL (drops the
// scheme, path, query, fragment and port) and a trailing dot, strips a
// leading "*." wildcard, then rejects anything that isn't a strict hostname
// (no slashes, whitespace or control chars — those would inject into the
// dnsmasq address=/server= directives we generate). Returns "" for invalid
// input; callers treat "" as "reject".
func NormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = urlSchemeRe.ReplaceAllString(d, "")
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndexByte(d, ':'); i >= 0 && i < len(d)-1 && strings.Trim(d[i+1:], "0123456789") == "" {
		d = d[:i]
	}
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	if !ValidDomain(d) {
		return ""
	}
	return d
}

// SanitizeSingleLine strips newlines, carriage returns, and any ASCII
// control character from a value that ends up on a single line of a
// config file (hostapd SSID, WPA passphrase, etc.). Does not mangle
// printable unicode.
func SanitizeSingleLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || (r >= 0 && r < 32) || r == 127 {
			return -1
		}
		return r
	}, s)
}

// SettingKeys is every setting the console may change: one list for the
// handler, the hotspot and the page.
var SettingKeys = []string{"ap_ssid", "ap_password", "ap_channel", "ap_country", "dns_upstream", "log_retention_days"}

// SettingError names the setting a value was refused for, in words the
// System page shows next to that field.
type SettingError struct{ Key, Msg string }

func (e *SettingError) Error() string { return e.Msg }

var (
	// The channels the hotspot offers: 2.4 GHz 1/6/11, 5 GHz UNII-1 36-48.
	apChannels   = map[string]bool{"1": true, "6": true, "11": true, "36": true, "40": true, "44": true, "48": true}
	countryRe    = regexp.MustCompile(`^[A-Za-z]{2}$`)
	retainDays   = map[string]bool{"7": true, "30": true, "90": true}
	settingKnown = func() map[string]bool {
		m := map[string]bool{}
		for _, k := range SettingKeys {
			m[k] = true
		}
		return m
	}()
)

// SplitUpstreams returns the resolvers in a dns_upstream value, trimmed,
// empty entries dropped.
func SplitUpstreams(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ValidateSettings checks every value before anything is saved. An empty
// ap_password means "unchanged".
func ValidateSettings(in map[string]string) error {
	unknown := []string{}
	for k := range in {
		if !settingKnown[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return &SettingError{unknown[0], fmt.Sprintf("unknown setting %q", unknown[0])}
	}
	for _, k := range SettingKeys {
		v, ok := in[k]
		if !ok {
			continue
		}
		bad := func(msg string) error { return &SettingError{k, msg} }
		switch k {
		case "ap_ssid":
			if strings.TrimSpace(v) == "" {
				return bad("Give the network a name.")
			}
			// hostapd counts bytes, not characters.
			if len(v) > 32 {
				return bad(fmt.Sprintf("Too long: %d of 32 bytes. Emoji count as 4 each.", len(v)))
			}
		case "ap_password":
			if v != "" && (len(v) < 8 || len(v) > 63) {
				return bad("The password needs 8 to 63 characters.")
			}
		case "ap_channel":
			if !apChannels[v] {
				return bad("Pick a channel the hotspot supports.")
			}
		case "ap_country":
			if !countryRe.MatchString(v) {
				return bad("Use a two-letter country code.")
			}
		case "dns_upstream":
			ups := SplitUpstreams(v)
			if len(ups) == 0 {
				return bad("Keep at least one resolver.")
			}
			for _, u := range ups {
				if !ValidIPv4(u) {
					return bad(u + " isn't an IPv4 address like 9.9.9.9.")
				}
			}
		case "log_retention_days":
			if !retainDays[v] {
				return bad("Keep traffic for 7, 30 or 90 days.")
			}
		}
	}
	return nil
}
