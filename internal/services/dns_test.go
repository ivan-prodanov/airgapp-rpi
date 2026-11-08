package services

import (
	"strings"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// TestBuildDNSConfig verifies the default-deny dnsmasq config: everything
// is sinkholed; only allow-listed domains get a server= line; connman is
// always resolvable; and a protected endpoint never gets a server= line
// even when it sneaks into the allow list.
func TestBuildDNSConfig(t *testing.T) {
	out := buildDNSConfig(
		[]string{"1.1.1.1"},
		[]string{"auth.tesla.com", "hermes-prd.ap.tesla.services", "maps-eu-prd.go.tesla.services"},
		[]string{"aa:bb:cc:dd:ee:ff"},
	)

	must := []string{
		"address=/#/0.0.0.0\n", // 0.0.0.0 sinkhole — NXDOMAIN destabilised the Tesla's
		//                         connman state in Tier-4; 0.0.0.0 keeps it settled.
		//                         server=/<specific>/ overrides correctly beat the # wildcard.
		"server=/auth.tesla.com/1.1.1.1",
		"server=/maps-eu-prd.go.tesla.services/1.1.1.1",
		"server=/connman.vn.tesla.services/1.1.1.1",
		"dhcp-host=aa:bb:cc:dd:ee:ff,set:open",
		"dhcp-option=tag:open,6,1.1.1.1",
	}
	for _, m := range must {
		if !strings.Contains(out, m) {
			t.Errorf("buildDNSConfig output is missing: %q", m)
		}
	}

	// A protected endpoint must NEVER get a resolvable server= line — it
	// stays sinkholed by address=/#/ even though it slipped into the allow
	// list passed in (defensive: the floor must hold at the DNS layer too).
	if strings.Contains(out, "server=/hermes-prd.ap.tesla.services/") {
		t.Errorf("protected endpoint got a resolvable server= line — DNS leak")
	}
}

// TestAllowedDomainsExcludesDisabled — a disabled filter_domain must not
// reach the DNS config (it is inert until enabled); the filter as a
// whole must also be enabled, otherwise its rows stay off-list.
// A domain is in the DNS allow-list exactly when its filter is on — there is
// no per-domain switch.
func TestAllowedDomainsFollowFilter(t *testing.T) {
	db := memDB(t)
	fID := freshFilter(t, db, "TestFilter") // freshFilter creates with enabled=1
	mustExec(t, db, `INSERT INTO filter_domains (preset_id, domain) VALUES (?,'live.example.com')`, fID)

	s := NewDNSService(db, executor.New(true), config.Config{DNSUpstream: "1.1.1.1"})
	has := func() bool {
		got, err := s.allowedDomains()
		if err != nil {
			t.Fatalf("allowedDomains: %v", err)
		}
		for _, d := range got {
			if d == "live.example.com" {
				return true
			}
		}
		return false
	}
	if !has() {
		t.Error("domain of an enabled filter missing from allowedDomains")
	}
	mustExec(t, db, `UPDATE filters SET enabled=0 WHERE id=?`, fID)
	if has() {
		t.Error("domain leaked while its filter is off")
	}
}

// The resolvers saved on the System page are the ones dnsmasq uses, for allowed
// domains and for the DNS handed to Open devices.
func TestDNSUpstreamFromSettings(t *testing.T) {
	db := memDB(t)
	fID := freshFilter(t, db, "TestFilter")
	mustExec(t, db, `INSERT INTO filter_domains (preset_id, domain) VALUES (?,'live.example.com')`, fID)
	mustExec(t, db, `INSERT INTO devices (mac_address, status) VALUES ('aa:bb:cc:dd:ee:01','open')`)
	mustExec(t, db, `INSERT INTO settings (key, value) VALUES ('dns_upstream','9.9.9.9,149.112.112.112') ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
	s := NewDNSService(db, executor.New(true), config.Config{DNSUpstream: "1.1.1.1"})
	conf, err := s.config()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server=/live.example.com/9.9.9.9", "server=/live.example.com/149.112.112.112", "dhcp-option=tag:open,6,9.9.9.9,149.112.112.112"} {
		if !strings.Contains(conf, want) {
			t.Errorf("config lacks %q", want)
		}
	}
	if strings.Contains(conf, "1.1.1.1") {
		t.Error("config still uses the config-file upstream")
	}
}

// A setting with nothing usable in it never reaches dnsmasq: the config file's
// upstreams stand in.
func TestDNSUpstreamFallsBack(t *testing.T) {
	db := memDB(t)
	mustExec(t, db, `INSERT INTO settings (key, value) VALUES ('dns_upstream','not-an-ip, ') ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
	if got := upstreamsFrom(db, "1.1.1.1,8.8.8.8"); strings.Join(got, ",") != "1.1.1.1,8.8.8.8" {
		t.Fatalf("upstreams %v, want the fallback", got)
	}
	mustExec(t, db, `UPDATE settings SET value = '9.9.9.9,bogus' WHERE key = 'dns_upstream'`)
	if got := upstreamsFrom(db, "1.1.1.1"); strings.Join(got, ",") != "9.9.9.9" {
		t.Fatalf("upstreams %v, want the valid entry only", got)
	}
	if got := upstreamsFrom(nil, ""); strings.Join(got, ",") != "1.1.1.1" {
		t.Fatalf("upstreams %v, want the last-resort default", got)
	}
}

// The enrol host resolves to the intercepted public address, and every other
// record type for it gets an empty answer (NODATA) instead of REFUSED.
func TestEnrolHostDNS(t *testing.T) {
	db := memDB(t)
	s := NewDNSService(db, executor.New(true), config.Config{DNSUpstream: "1.1.1.1", LANGateway: "192.168.4.1", EnrolHost: "airgapp.me", EnrolAddr: "203.0.113.80"})
	conf, err := s.config()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"address=/airgapp.me/203.0.113.80", "local=/airgapp.me/"} {
		if !strings.Contains(conf, want) {
			t.Errorf("config lacks %q", want)
		}
	}
	if strings.Contains(conf, "address=/airgapp.me/192.168.4.1") {
		t.Error("enrol host still answers the private address")
	}
}
