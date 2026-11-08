package services

import (
	"strings"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// TestGenerateConfig_V3Shape verifies the generated nftables ruleset has
// the V3 shape: the filtered device's :443 is redirected to the SNI proxy
// and :80 DNAT'd to the connman spoof; trusted devices get a forward
// accept; blocked devices get a hard drop; the forward chain is default-
// deny; and none of the removed V2 machinery (per-policy sets/chains,
// DoH set) remains. Unknown devices have no row — the default policy drop
// catches them.
func TestGenerateConfig_V3Shape(t *testing.T) {
	s := &FirewallService{cfg: config.Config{
		LANInterface: "wlan0",
		WANInterface: "eth1",
		LANGateway:   "192.168.4.1",
		SNIProxyPort: 8444,
		DNSUpstream:  "1.1.1.1,8.8.8.8",
	}}
	snap := deviceSnapshot{
		filtered: []string{"0c:29:8f:93:2a:08"}, // Tesla
		open:     []string{"aa:bb:cc:dd:ee:ff"}, // laptop
		blocked:  []string{"11:22:33:44:55:66"}, // hostile device
	}
	out := s.generateConfig(nil, snap)

	must := []string{
		`ether saddr 0c:29:8f:93:2a:08 tcp dport 443 redirect to :8444`,
		`ether saddr 0c:29:8f:93:2a:08 tcp dport 80 dnat to 192.168.4.1`,
		`ether saddr aa:bb:cc:dd:ee:ff accept`, // open passthrough
		`ether saddr 11:22:33:44:55:66 drop`,   // blocked device
		`type filter hook forward priority filter; policy drop;`,
		// Open device's DNS is DNAT'd to the upstream so it bypasses the
		// Pi's default-deny dnsmasq regardless of cached DHCP lease.
		`ether saddr aa:bb:cc:dd:ee:ff udp dport 53 dnat to 1.1.1.1:53`,
		`ether saddr aa:bb:cc:dd:ee:ff tcp dport 53 dnat to 1.1.1.1:53`,
	}
	for _, m := range must {
		if !strings.Contains(out, m) {
			t.Errorf("generated nftables config is missing:\n  %q", m)
		}
	}

	mustNot := []string{"pol_", "doh_resolvers", "@pol"}
	for _, m := range mustNot {
		if strings.Contains(out, m) {
			t.Errorf("generated config still contains a removed V2 construct: %q", m)
		}
	}

	// A filtered device must NOT have a blanket forward accept — its web
	// traffic is intercepted in prerouting, everything else is dropped.
	if strings.Contains(out, "ether saddr 0c:29:8f:93:2a:08 accept") {
		t.Errorf("filtered device must not have a forward-chain accept rule")
	}
}

// The gate's job is to prove the car's :443 still lands in the SNI proxy.
// A ruleset that kept `inet filter` but lost `ip nat` is a BYPASS, so the
// forward policy alone is not sufficient evidence.
func TestVerifyAcceptsInterceptedRuleset(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	nat := `table ip nat {
	chain prerouting {
		iifname "wlan0" ether saddr aa:bb:cc:dd:ee:ff tcp dport 443 redirect to :8444
	}
}`
	fwd := `table inet filter {
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}`
	if err := s.verifyOutput(nat, fwd, []string{"aa:bb:cc:dd:ee:ff"}); err != nil {
		t.Fatalf("a ruleset with the SNI redirect and a drop policy must verify: %v", err)
	}
}

func TestVerifyRejectsMissingSNIRedirect(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	nat := `table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
	}
}`
	fwd := `table inet filter {
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}`
	if err := s.verifyOutput(nat, fwd, []string{"aa:bb:cc:dd:ee:ff"}); err == nil {
		t.Fatal("no SNI redirect means :443 never reaches the decision — must be rejected")
	}
}

func TestVerifyRejectsAcceptPolicy(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	nat := `iifname "wlan0" ether saddr aa:bb:cc:dd:ee:ff tcp dport 443 redirect to :8444`
	fwd := `chain forward { type filter hook forward priority filter; policy accept; }`
	if err := s.verifyOutput(nat, fwd, []string{"aa:bb:cc:dd:ee:ff"}); err == nil {
		t.Fatal("an accept-policy forward chain must be rejected")
	}
}

func TestVerifyRejectsEmptyRuleset(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	if err := s.verifyOutput("", "", []string{"aa:bb:cc:dd:ee:ff"}); err == nil {
		t.Fatal("an empty ruleset must be rejected — no redirect, no forward chain, ip_forward=1")
	}
}

// THE BYPASS THIS GATE EXISTS TO CATCH: the car's row is flipped
// filtered→open (operator slip, restored DB) while some other device keeps a
// redirect. A chain-wide "is there a redirect anywhere" check goes green while
// the car has a blanket forward accept and DNS DNAT'd past the SNI proxy.
func TestVerifyRejectsWhenOneFilteredDeviceHasNoRedirect(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	// Only the laptop is intercepted; the car (0c:…) is not.
	nat := `table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "wlan0" ether saddr aa:bb:cc:dd:ee:ff tcp dport 80 dnat to 192.168.4.1
		iifname "wlan0" ether saddr aa:bb:cc:dd:ee:ff tcp dport 443 redirect to :8444
	}
}`
	fwd := `chain forward { type filter hook forward priority filter; policy drop; }`

	err := s.verifyOutput(nat, fwd, []string{"aa:bb:cc:dd:ee:ff", "0c:29:8f:93:2a:08"})
	if err == nil {
		t.Fatal("LEAK: a filtered device with no :443 redirect must fail the gate")
	}
	if !strings.Contains(err.Error(), "0c:29:8f:93:2a:08") {
		t.Fatalf("the error must name the uncovered device, got: %v", err)
	}

	// Same ruleset, both devices covered → passes.
	nat += "\n" + `		iifname "wlan0" ether saddr 0c:29:8f:93:2a:08 tcp dport 443 redirect to :8444`
	if err := s.verifyOutput(nat, fwd, []string{"aa:bb:cc:dd:ee:ff", "0c:29:8f:93:2a:08"}); err != nil {
		t.Fatalf("every filtered device covered must verify: %v", err)
	}
}

// The redirect must be bound to the device on ONE line. A MAC mentioned on a
// :80 DNAT line plus a redirect for somebody else on another line is not
// evidence that THIS device's :443 is intercepted.
func TestVerifyRejectsRedirectOnADifferentLineThanTheMAC(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	nat := `table ip nat {
	chain prerouting {
		iifname "wlan0" ether saddr 0c:29:8f:93:2a:08 tcp dport 80 dnat to 192.168.4.1
		iifname "wlan0" ether saddr aa:bb:cc:dd:ee:ff tcp dport 443 redirect to :8444
	}
}`
	fwd := `chain forward { type filter hook forward priority filter; policy drop; }`
	if err := s.verifyOutput(nat, fwd, []string{"0c:29:8f:93:2a:08"}); err == nil {
		t.Fatal("a redirect on another device's line must not vouch for this one")
	}
}

// An empty filtered list means nothing is intercepted at all. On a
// single-car Pi that IS the "car got moved to open" state, so it must refuse
// rather than pass vacuously.
func TestVerifyRefusesWhenNothingIsFiltered(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	nat := `iifname "wlan0" ether saddr aa:bb:cc:dd:ee:ff tcp dport 443 redirect to :8444`
	fwd := `chain forward { type filter hook forward priority filter; policy drop; }`
	err := s.verifyOutput(nat, fwd, nil)
	if err == nil {
		t.Fatal("no filtered device means nothing is intercepted — the gate must refuse, not pass")
	}
	if !strings.Contains(err.Error(), "filtered") {
		t.Fatalf("the error must say why (nothing is filtered), got: %v", err)
	}
}

// nft renders MACs lowercase; the devices table may hold them uppercase. If
// the comparison were case-sensitive the gate would never match and the
// feature would brick itself shut.
func TestVerifyIsMACCaseInsensitive(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	nat := `iifname "wlan0" ether saddr 0c:29:8f:93:2a:08 tcp dport 443 redirect to :8444`
	fwd := `chain forward { type filter hook forward priority filter; policy drop; }`
	if err := s.verifyOutput(nat, fwd, []string{"0C:29:8F:93:2A:08"}); err != nil {
		t.Fatalf("an uppercase DB MAC must match nft's lowercase render: %v", err)
	}
}

// loadDeviceSnapshot is the other half of that normalisation: an uppercase
// row must reach verifyOutput lowercased.
func TestLoadDeviceSnapshotLowercasesMACs(t *testing.T) {
	db := memDB(t)
	mustExec(t, db, `INSERT INTO devices (mac_address, status) VALUES ('0C:29:8F:93:2A:08','filtered')`)
	s := NewFirewallService(db, executor.New(true), config.Config{SNIProxyPort: 8444})

	snap, err := s.loadDeviceSnapshot()
	if err != nil {
		t.Fatalf("loadDeviceSnapshot: %v", err)
	}
	if len(snap.filtered) != 1 || snap.filtered[0] != "0c:29:8f:93:2a:08" {
		t.Fatalf("filtered = %v, want [0c:29:8f:93:2a:08]", snap.filtered)
	}
}

// Round-trip: what generateConfig emits must satisfy verifyOutput. This
// cannot catch nft-renderer drift (nft re-prints the ruleset in its own
// form), but it permanently pins GENERATOR-versus-VERIFIER drift — change the
// emitted rule shape and this fails here, not on a Pi at 2am.
func TestGeneratedConfigSatisfiesVerify(t *testing.T) {
	s := &FirewallService{cfg: config.Config{
		LANInterface: "wlan0",
		WANInterface: "eth1",
		LANGateway:   "192.168.4.1",
		SNIProxyPort: 8444,
		DNSUpstream:  "1.1.1.1",
	}}
	mac := "0c:29:8f:93:2a:08"
	conf := s.generateConfig(nil, deviceSnapshot{filtered: []string{mac}})

	// Feed each half to the verifier the way `nft list chain` would.
	natPart, fwdPart, found := strings.Cut(conf, "chain forward")
	if !found {
		t.Fatal("generated config has no forward chain")
	}
	if err := s.verifyOutput(natPart, fwdPart, []string{mac}); err != nil {
		t.Fatalf("the config we generate must satisfy the gate we verify with: %v", err)
	}
}

func TestVerifyReadsFromNft(t *testing.T) {
	// DryRun Run() returns an empty Result, i.e. no listing at all — exactly
	// the "ruleset is not loaded" case.
	db := memDB(t)
	mustExec(t, db, `INSERT INTO devices (mac_address, status) VALUES ('0c:29:8f:93:2a:08','filtered')`)
	exec := executor.New(true)
	s := NewFirewallService(db, exec, config.Config{SNIProxyPort: 8444})
	if err := s.Verify(); err == nil {
		t.Fatal("Verify must fail when nft returns nothing")
	}
	// Both listings must be numeric — never service names or resolved hosts.
	for _, cmd := range exec.Recorded() {
		if strings.HasPrefix(cmd, "nft ") && !strings.HasPrefix(cmd, "nft -nn ") {
			t.Fatalf("nft listing must pass -nn, got %q", cmd)
		}
	}
}

// Fix 2: The substring match "443" also matches "8443" (the admin UI port),
// which is not the SNI proxy (8444). The gate must not be fooled by that.
func TestVerifyRejects8443AsNotThe443Redirect(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	nat := `table ip nat {
	chain prerouting {
		iifname "wlan0" ether saddr 0c:29:8f:93:2a:08 tcp dport 8443 redirect to :8444
	}
}`
	fwd := `chain forward { type filter hook forward priority filter; policy drop; }`
	if err := s.verifyOutput(nat, fwd, []string{"0c:29:8f:93:2a:08"}); err == nil {
		t.Fatal("a redirect on the admin UI port (8443) must not satisfy the gate for port 443")
	}
}

// Fix 3: An empty MAC in the filtered list should fail the gate, not skip it.
// For a function whose job is to refuse, a malformed input must be a refusal.
func TestVerifyRejectsEmptyMAC(t *testing.T) {
	s := &FirewallService{cfg: config.Config{SNIProxyPort: 8444}}
	nat := `iifname "wlan0" ether saddr 0c:29:8f:93:2a:08 tcp dport 443 redirect to :8444`
	fwd := `chain forward { type filter hook forward priority filter; policy drop; }`
	err := s.verifyOutput(nat, fwd, []string{"   "})
	if err == nil {
		t.Fatal("an empty or whitespace MAC must be rejected as malformed")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("the error must indicate the list is malformed, got: %v", err)
	}
}

// TestGenerateConfig_FilterPorts verifies the car's non-HTTPS port-holes —
// QUIC/UDP 443, STUN/UDP 19302 and FCM/TCP 5228 (Connectivity since v29) and
// the Spotify access point TCP 4070 (Spotify) — open in the forward chain for
// the FILTERED car, keyed on the device's status, never a hardcoded MAC; for
// nobody when nothing is filtered; and only while their filter is on.
func TestGenerateConfig_FilterPorts(t *testing.T) {
	db := memDB(t) // every migration: Connectivity and Spotify on, with their ports
	s := &FirewallService{db: db, cfg: config.Config{
		LANInterface: "wlan0",
		WANInterface: "wlan1",
		LANGateway:   "192.168.4.1",
		SNIProxyPort: 8444,
		DNSUpstream:  "1.1.1.1",
	}}
	// A neutral fixture MAC — the whole point is that the port-holes key on
	// the device's 'filtered' status, not on any particular car's address.
	const mac = "aa:bb:cc:00:00:01"
	out := s.generateConfig(nil, deviceSnapshot{filtered: []string{mac}})

	for _, want := range []string{
		"ether saddr " + mac + " udp dport 443 ct state new log prefix \"[NETFILTER-ACCEPT] \" accept",
		"ether saddr " + mac + " udp dport 19302 ct state new log prefix \"[NETFILTER-ACCEPT] \" accept",
		"ether saddr " + mac + " tcp dport 5228 ct state new log prefix \"[NETFILTER-ACCEPT] \" accept",
		"ether saddr " + mac + " tcp dport 4070 ct state new log prefix \"[NETFILTER-ACCEPT] \" accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("forward chain missing port-hole:\n  %s", want)
		}
	}

	// A port opens exactly when its filter is on: Spotify off closes 4070,
	// Connectivity's ports stay.
	if _, err := db.Exec(`UPDATE filters SET enabled = 0 WHERE name = 'Spotify'`); err != nil {
		t.Fatal(err)
	}
	off := s.generateConfig(nil, deviceSnapshot{filtered: []string{mac}})
	if strings.Contains(off, "tcp dport 4070 ct state new") || !strings.Contains(off, "udp dport 443 ct state new") {
		t.Errorf("with Spotify off: 4070 open=%v, 443 open=%v; want closed, open",
			strings.Contains(off, "tcp dport 4070 ct state new"), strings.Contains(off, "udp dport 443 ct state new"))
	}

	// Car-agnostic + default-deny preserved: with no filtered device, none of
	// the port-holes render.
	none := s.generateConfig(nil, deviceSnapshot{})
	for _, absent := range []string{
		"udp dport 443 ct state new",
		"udp dport 19302 ct state new",
		"tcp dport 5228 ct state new",
		"tcp dport 4070 ct state new",
	} {
		if strings.Contains(none, absent) {
			t.Errorf("port-hole %q opened with no filtered device (must be car-only)", absent)
		}
	}
}

// An Open device's DNS is redirected to the first resolver saved in settings.
func TestFirewallOpenDNATUsesSettingsUpstream(t *testing.T) {
	db := memDB(t)
	mustExec(t, db, `INSERT INTO settings (key, value) VALUES ('dns_upstream','9.9.9.9') ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
	s := &FirewallService{db: db, cfg: config.Config{LANInterface: "wlan0", WANInterface: "eth1", LANGateway: "192.168.4.1", SNIProxyPort: 8444, DNSUpstream: "1.1.1.1"}}
	out := s.generateConfig(nil, deviceSnapshot{open: []string{"aa:bb:cc:dd:ee:ff"}})
	if !strings.Contains(out, "dnat to 9.9.9.9") || strings.Contains(out, "dnat to 1.1.1.1") {
		t.Fatalf("Open DNAT does not use the settings upstream:\n%s", out)
	}
}
