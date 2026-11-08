package services

import (
	"crypto/tls"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// airgapp.net, typed in the car, opens the console. The car isn't on the tailnet,
// so on the hotspot the Pi answers its own tailnet name with an address it
// intercepts and hands that traffic to Tailscale on the Pi, which holds the real
// certificate. A made-up tailnet for the tests:
var testTailnet = Tailnet{Host: "pi.tail1234.ts.net", IPv4: "100.101.102.103"}

func consoleCfg() config.Config {
	return config.Config{
		LANInterface: "wlan0", WANInterface: "eth1", LANGateway: "192.168.4.1", SNIProxyPort: 8444, DNSUpstream: "1.1.1.1",
		EnrolHost: "airgapp.me", EnrolAddr: "203.0.113.80", ConsoleHost: "airgapp.net", TailnetAddr: "203.0.113.81",
		ListenAddr: ":8443", UseTLS: true,
	}
}

// Only a signed-in Tailscale with a usable name and address gives the hotspot a tailnet.
func TestTailnetFromStatus(t *testing.T) {
	st := RemoteStatus{Authenticated: true, TailnetHostname: "pi.tail1234.ts.net", TailnetIPv4: "100.101.102.103"}
	if got := TailnetFrom(st); got != testTailnet {
		t.Fatalf("signed in: %+v", got)
	}
	st.Authenticated = false
	if got := TailnetFrom(st); got != (Tailnet{}) {
		t.Fatalf("signed out: %+v", got)
	}
	st.Authenticated, st.TailnetIPv4 = true, "not-an-address"
	if got := TailnetFrom(st); got != (Tailnet{}) {
		t.Fatalf("no usable address: %+v", got)
	}
}

// airgapp.net shares the enrol host's intercepted address. The tailnet name
// answers the tailnet address once Tailscale is known, and not before.
func TestConsoleHostAndTailnetDNS(t *testing.T) {
	s := NewDNSService(memDB(t), executor.New(true), consoleCfg())
	conf, err := s.config()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"address=/airgapp.net/203.0.113.80", "local=/airgapp.net/"} {
		if !strings.Contains(conf, want) {
			t.Errorf("config lacks %q", want)
		}
	}
	if strings.Contains(conf, "ts.net") {
		t.Fatal("a tailnet name before Tailscale is known")
	}
	s.SetTailnet(testTailnet)
	if conf, err = s.config(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"address=/pi.tail1234.ts.net/203.0.113.81", "local=/pi.tail1234.ts.net/"} {
		if !strings.Contains(conf, want) {
			t.Errorf("config lacks %q", want)
		}
	}
}

// The tailnet address forwards the console's port and the /api/ble Funnel port
// to Tailscale on the Pi, ahead of the per-device rules (a filtered device's
// :443 would otherwise go to the SNI proxy), and the input chain lets them in.
func TestTailnetAddrForwardsToTailscale(t *testing.T) {
	s := &FirewallService{cfg: consoleCfg()}
	snap := deviceSnapshot{filtered: []string{"0c:29:8f:93:2a:08"}}
	if out := s.generateConfig(nil, snap); strings.Contains(out, "203.0.113.81") || strings.Contains(out, "100.101.102.103") {
		t.Fatalf("rules for a tailnet that isn't known yet:\n%s", out)
	}
	s.SetTailnet(testTailnet)
	out := s.generateConfig(nil, snap)
	first := strings.Index(out, "ether saddr 0c:29:8f:93:2a:08")
	for _, port := range []int{443, 10000} {
		rule := fmt.Sprintf(`iifname "wlan0" ip daddr 203.0.113.81 tcp dport %d dnat to 100.101.102.103:%d`, port, port)
		if i := strings.Index(out, rule); i < 0 || i > first {
			t.Fatalf("want %q ahead of the per-device rules:\n%s", rule, out)
		}
		accept := fmt.Sprintf(`iifname "wlan0" ip daddr 100.101.102.103 tcp dport %d accept`, port)
		if !strings.Contains(out, accept) {
			t.Fatalf("input chain lacks %q:\n%s", accept, out)
		}
	}
}

// airgapp.net alone (no enrol page configured) still intercepts the shared address.
func TestConsoleHostAloneInterceptsEnrolAddr(t *testing.T) {
	cfg := consoleCfg()
	cfg.EnrolHost = ""
	out := (&FirewallService{cfg: cfg}).generateConfig(nil, deviceSnapshot{})
	for _, port := range []int{80, 443} {
		rule := fmt.Sprintf(`iifname "wlan0" ip daddr 203.0.113.80 tcp dport %d dnat to 192.168.4.1:%d`, port, port)
		if !strings.Contains(out, rule) {
			t.Fatalf("want %q:\n%s", rule, out)
		}
	}
}

// Open devices use public DNS: their queries for airgapp.net and for the Pi's
// tailnet name go to the Pi's dnsmasq, ahead of the upstream rule.
func TestOpenDeviceConsoleAndTailnetDNS(t *testing.T) {
	s := &FirewallService{cfg: consoleCfg()}
	s.SetTailnet(testTailnet)
	out := s.generateConfig(nil, deviceSnapshot{open: []string{"aa:bb:cc:dd:ee:ff"}})
	upstream := strings.Index(out, `iifname "wlan0" ether saddr aa:bb:cc:dd:ee:ff udp dport 53 dnat to 1.1.1.1:53`)
	for _, host := range []string{"airgapp.net", "pi.tail1234.ts.net"} {
		m, ok := dnsQNameMatch(host)
		if !ok {
			t.Fatalf("%s: no match", host)
		}
		rule := `iifname "wlan0" ether saddr aa:bb:cc:dd:ee:ff udp dport 53 ` + m + ` dnat to 192.168.4.1:53`
		if i := strings.Index(out, rule); i < 0 || upstream < 0 || i > upstream {
			t.Fatalf("want the %s rule before the upstream rule:\n%s", host, out)
		}
	}
}

// Typed in the car, airgapp.net lands on the console: Tailscale's address for it
// when the tailnet is known (the real certificate), the Pi's own console
// address when it isn't. Every other host still gets the captive-check spoof.
func TestConsoleHostRedirects(t *testing.T) {
	s := NewSpoofService(consoleCfg(), nil)
	get := func(host string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handle(rec, httptest.NewRequest("GET", "http://"+host+"/some/path", nil))
		return rec
	}
	if rec := get("airgapp.net"); rec.Code != 302 || rec.Header().Get("Location") != "https://192.168.4.1:8443/" {
		t.Fatalf("no tailnet: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	s.SetTailnet(testTailnet)
	if rec := get("airgapp.net"); rec.Code != 302 || rec.Header().Get("Location") != "https://pi.tail1234.ts.net:10000/" {
		t.Fatalf("tailnet: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(spoofConnManHost); rec.Code != 200 || rec.Header().Get("Location") != "" {
		t.Fatalf("captive check: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// https://airgapp.net fails the handshake at once, so the browser falls back to http://.
func TestSpoofTLSRefusesConsoleHost(t *testing.T) {
	s := NewSpoofService(consoleCfg(), nil)
	cert, err := selfSignedCert(spoofConnManHost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.tlsConfig(cert).GetCertificate(&tls.ClientHelloInfo{ServerName: "airgapp.net"}); err == nil {
		t.Fatal("handshake for the console host should be refused")
	}
}

// The watcher applies a change of tailnet once, ignores a repeat, and applies
// signing out too (the hotspot stops pointing at a tailnet that is gone).
func TestTailnetSyncAppliesChangesOnly(t *testing.T) {
	var applied []Tailnet
	w := &tailnetSync{apply: func(t Tailnet) { applied = append(applied, t) }}
	for _, t := range []Tailnet{{}, testTailnet, testTailnet, {}} {
		w.observe(t)
	}
	if len(applied) != 2 || applied[0] != testTailnet || applied[1] != (Tailnet{}) {
		t.Fatalf("applied %+v", applied)
	}
}
