package services

import (
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
)

// ── fixtures ───────────────────────────────────────────────────

// blockedSamples are Tesla endpoints that must NEVER be reachable. It
// deliberately includes EU-region Hermes hostnames that the old aus07
// v10 block-list never had — the apex-based protected-deny floor must
// still catch them.
var blockedSamples = []string{
	"hermes-prd.ap.tesla.services",
	"hermes-stream-api.prd.eu.vn.cloud.tesla.com",
	"hermes-api.prd.eu.vn.cloud.tesla.com",
	"hermes-prd1.i.tslans.net",
	"device-api.prd.eu.vn.cloud.tesla.com",
	// NOTE: assistant-api.prd.*.vn.cloud.tesla.com is DELIBERATELY allow-able
	// now (the Grok carve-out — see protected.go assistantExempt and
	// protected_carveout_test.go). It is voice/QUIC only, disjoint ELB from
	// hermes, per-host cert, no log-grab. The apex still denies everything
	// else under vn.cloud.tesla.com, which the samples below assert.
	"telemetry-prd.ap.tesla.services",
	"telemetry-prd.vn.tesla.services",
	"logupload-prod.vn.tesla.services",
	"mothership.vn.teslamotors.com",
	"firmware-ota.vn.teslamotors.com",
	"navsrv.eng.go.tesla.services",
	"x3-prod.obs.tesla.com",
	"api-prd.ap.tesla.services",
	"ota.vn.tesla.services",
	"software-update.tesla.com",
	"dl.tesla.com",
	"tesla-cdn.com",
	"toolbox.teslamotors.com",
}

// legitAllowed is a realistic Tesla allow-list (Fix 1 applied — specific
// go.tesla.services sub-domains, no bare parent).
var legitAllowed = []string{
	"auth.tesla.com",
	"managed-charging.sn.tesla.services",
	"maps.googleapis.com",
	"maps-eu-prd.go.tesla.services",
	"apmv3.go.tesla.services",
}

// ── ClientHello generation ─────────────────────────────────────

// clientHello generates a real TLS ClientHello record for serverName
// ("" = no SNI) by starting a handshake against an in-memory pipe.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	go func() {
		cfg := &tls.Config{InsecureSkipVerify: true}
		if serverName != "" {
			cfg.ServerName = serverName
		}
		_ = tls.Client(c1, cfg).Handshake()
		c1.Close()
	}()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, err := c2.Read(buf)
	c2.Close()
	if err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	return buf[:n]
}

// ── parseSNI ───────────────────────────────────────────────────

func TestParseSNI(t *testing.T) {
	rec := clientHello(t, "daws.tesla.services")
	if len(rec) < 6 || rec[0] != 0x16 {
		t.Fatalf("not a TLS handshake record")
	}
	if got := parseSNI(rec[5:]); got != "daws.tesla.services" {
		t.Errorf("parseSNI = %q, want daws.tesla.services", got)
	}
}

func TestParseSNINone(t *testing.T) {
	rec := clientHello(t, "")
	if got := parseSNI(rec[5:]); got != "" {
		t.Errorf("parseSNI with no SNI = %q, want empty", got)
	}
}

func TestParseSNIGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x01}, {0x01, 0, 0, 0xff}, {0x16, 0x03}} {
		if got := parseSNI(b); got != "" {
			t.Errorf("parseSNI(%v) = %q, want empty", b, got)
		}
	}
}

// ── matchSNI / sniAllowed ──────────────────────────────────────

func TestMatchSNI(t *testing.T) {
	allow := []string{"tesla.services", "auth.tesla.com"}
	cases := []struct {
		sni  string
		want bool
	}{
		{"daws.tesla.services", true},
		{"tesla.services", true},
		{"auth.tesla.com", true},
		{"evil-tesla.services", false}, // not a subdomain — must not match
		{"", false},
	}
	for _, c := range cases {
		if got := matchSNI(c.sni, allow); got != c.want {
			t.Errorf("matchSNI(%q) = %v, want %v", c.sni, got, c.want)
		}
	}
	if matchSNI("anything.com", []string{""}) {
		t.Errorf("matchSNI must ignore an empty allow-list entry")
	}
}

// TestSNIAllowed_Exhaustive — with a realistic allow-list, every blocked
// sample is denied and every legitimate domain is allowed.
func TestSNIAllowed_Exhaustive(t *testing.T) {
	for _, d := range blockedSamples {
		if sniAllowed(d, legitAllowed) {
			t.Errorf("BLOCKED endpoint reachable: sniAllowed(%q) = true", d)
		}
	}
	for _, d := range legitAllowed {
		if !sniAllowed(d, legitAllowed) {
			t.Errorf("ALLOWED domain not reachable: sniAllowed(%q) = false", d)
		}
	}
}

// TestProtectedDenyFloor — even a catastrophically broad allow-list
// cannot reach a protected Tesla endpoint. This is the structural proof
// that a misconfigured allow-list cannot open the door.
func TestProtectedDenyFloor(t *testing.T) {
	catastrophic := []string{"tesla.services", "teslamotors.com", "tesla.com", "cloud.tesla.com", "com", "net", ""}
	for _, d := range blockedSamples {
		if sniAllowed(d, catastrophic) {
			t.Errorf("protected-deny floor BREACHED: sniAllowed(%q, catastrophic allow-list) = true", d)
		}
	}
}

// ── handle(): the proxy must never dial out for a denied SNI ────

// driveHandle runs s.handle on a loopback connection (RemoteAddr =
// 127.0.0.1) fed the given ClientHello bytes, and returns once handle
// finishes.
func driveHandle(t *testing.T, s *SNIProxyService, hello []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			s.handle(conn)
		}
		close(done)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = c.Write(hello)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handle did not finish")
	}
	c.Close()
}

func TestSNIProxy_BlockedNeverDials(t *testing.T) {
	db := memDB(t)
	cases := []struct {
		name     string
		hello    []byte
		wantDial string // "" = dialer must NOT be called
	}{
		{"allowed", clientHello(t, "auth.tesla.com"), "auth.tesla.com:443"},
		{"blocked-protected", clientHello(t, "hermes-prd.ap.tesla.services"), ""},
		{"blocked-eu-hermes", clientHello(t, "hermes-stream-api.prd.eu.vn.cloud.tesla.com"), ""},
		{"not-allow-listed", clientHello(t, "example.com"), ""},
		{"no-sni", clientHello(t, ""), ""},
		{"garbage", []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var dialedAddr string
			s := &SNIProxyService{
				trafficLog: NewTrafficLogService(db),
				// 127.0.0.1 is the loopback RemoteAddr driveHandle produces;
				// the live lease table resolves it to a filtered device's MAC.
				suffixes: legitAllowed,
				filtered: map[string]bool{"0C:29:8F:93:2A:08": true},
				leases: func() map[string][]string {
					return map[string][]string{"0C:29:8F:93:2A:08": {"127.0.0.1"}}
				},
				dial: func(network, addr string) (net.Conn, error) {
					dialedAddr = addr
					return nil, errStubDialer
				},
			}
			driveHandle(t, s, c.hello)
			if dialedAddr != c.wantDial {
				t.Errorf("dialer called with %q, want %q", dialedAddr, c.wantDial)
			}
		})
	}
}

var errStubDialer = errors.New("stub dialer: no real upstream in test")

// ── RefreshCache: global suffixes + filtered-MAC set ───────────

func TestRefreshCache_FilteredSetAndSuffixes(t *testing.T) {
	db := memDB(t)

	// A filtered device's MAC enters the filtered set; an open device's does
	// not (its :443 is never redirected to the proxy).
	mustExec(t, db, `INSERT INTO devices (mac_address, ip_address, status) VALUES ('AA:BB:CC:00:00:01','10.0.0.10','filtered')`)
	mustExec(t, db, `INSERT INTO devices (mac_address, ip_address, status) VALUES ('AA:BB:CC:00:00:02','10.0.0.20','open')`)

	// Custom filter enabled with one live + one staged domain.
	mustExec(t, db, `INSERT INTO filters (name, description, is_system, enabled) VALUES ('FilterTest','','0','1')`)
	var fID int64
	if err := db.QueryRow(`SELECT id FROM filters WHERE name='FilterTest'`).Scan(&fID); err != nil {
		t.Fatalf("get filter id: %v", err)
	}
	mustExec(t, db, `INSERT INTO filter_domains (preset_id, domain, enabled) VALUES (?, 'auth.tesla.com', 1)`, fID)
	mustExec(t, db, `INSERT INTO filter_domains (preset_id, domain, enabled) VALUES (?, 'staged.example.com', 0)`, fID)

	// Seeded system filters ship enabled; disable them so the cache holds
	// only our injected domain.
	mustExec(t, db, `UPDATE filters SET enabled=0 WHERE is_system=1`)

	s := NewSNIProxyService(config.Config{}, db, NewTrafficLogService(db))
	s.RefreshCache()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.filtered["AA:BB:CC:00:00:01"] {
		t.Error("filtered device MAC missing from the filtered set")
	}
	if s.filtered["AA:BB:CC:00:00:02"] {
		t.Error("open device MAC must not be in the filtered set")
	}
	if len(s.suffixes) != 1 || s.suffixes[0] != "auth.tesla.com" {
		t.Errorf("suffixes = %v, want [auth.tesla.com] (disabled domain excluded)", s.suffixes)
	}
}

// seedFilteredCar registers the car as a filtered device whose RECORDED ip is
// stale — the exact state a wake-up produces, and the state that dropped 341
// of the car's own allow-listed requests in 24h on-car.
func seedFilteredCar(t *testing.T, db *sql.DB, recordedIP string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO devices (mac_address, ip_address, hostname, status)
		VALUES ('0C:29:8F:93:2A:08', ?, 'tesla', 'filtered')`, recordedIP)
	id := freshFilter(t, db, "TestLeaseAllowList")
	mustExec(t, db, `INSERT INTO filter_domains (preset_id, domain, enabled)
		VALUES (?, 'tile.googleapis.com', 1)`, id)
}

// ── clientMAC: live IP→MAC resolution at connection time ───────

// The lease table is written at DHCP-ACK, before the client can route a
// packet — so it maps a freshly-reassociated IP to its MAC immediately.
func TestClientMAC_ResolvesFromLiveLease(t *testing.T) {
	s := &SNIProxyService{
		leases: func() map[string][]string {
			return map[string][]string{"0C:29:8F:93:2A:08": {"192.168.4.237"}}
		},
	}
	if got := s.clientMAC("192.168.4.237"); got != "0C:29:8F:93:2A:08" {
		t.Errorf("clientMAC = %q, want the car MAC", got)
	}
}

// ARP is the fallback: the kernel populates an entry the instant the client
// sends a packet, and the client just opened this very connection.
func TestClientMAC_FallsBackToARP(t *testing.T) {
	s := &SNIProxyService{
		leases: func() map[string][]string { return nil },
		arp:    func() map[string]string { return map[string]string{"192.168.4.237": "0C:29:8F:93:2A:08"} },
	}
	if got := s.clientMAC("192.168.4.237"); got != "0C:29:8F:93:2A:08" {
		t.Errorf("clientMAC via ARP = %q, want the car MAC", got)
	}
}

func TestClientMAC_UnknownIP(t *testing.T) {
	s := &SNIProxyService{
		leases: func() map[string][]string { return nil },
		arp:    func() map[string]string { return nil },
	}
	if got := s.clientMAC("192.168.4.99"); got != "" {
		t.Errorf("clientMAC unknown = %q, want empty", got)
	}
}

func TestARPByIP(t *testing.T) {
	const data = `IP address       HW type     Flags       HW address            Mask     Device
192.168.4.237    0x1         0x2         0c:29:8f:93:2a:08     *        wlan0
192.168.4.9      0x1         0x0         00:00:00:00:00:00     *        wlan0
10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
`
	got := arpByIP(strings.NewReader(data), "wlan0")
	if got["192.168.4.237"] != "0C:29:8F:93:2A:08" {
		t.Errorf("want car MAC for .237, got %q", got["192.168.4.237"])
	}
	if _, ok := got["192.168.4.9"]; ok {
		t.Error("incomplete (Flags=0x0) entry must be dropped")
	}
	if _, ok := got["10.0.0.1"]; ok {
		t.Error("entry on a different interface must be excluded")
	}
}

// ── policyFor: the connection-time allow decision ──────────────

// THE FIX, end to end: the car is filtered, its devices row IP is STALE, and it
// is really on a brand-new leased IP. Keying the decision on the MAC resolved
// live at connection time — not on the 30s-lagged devices.ip_address — means
// its own allow-listed traffic is no longer dropped during the reassociation
// window. Before this, a map miss made the device unknown and sniAllowed never
// ran.
func TestPolicyFor_RecognisesFilteredDeviceByLiveMAC(t *testing.T) {
	db := memDB(t)
	seedFilteredCar(t, db, "192.168.4.236") // stale on purpose

	s := NewSNIProxyService(config.Config{}, db, nil)
	s.leases = func() map[string][]string {
		return map[string][]string{"0C:29:8F:93:2A:08": {"192.168.4.238"}} // real current IP
	}
	s.RefreshCache()

	suffixes, filtered := s.policyFor("192.168.4.238")
	if !filtered {
		t.Fatal("car on its real leased IP was not recognised — its own allow-listed traffic would be dropped")
	}
	if !sniAllowed("tile.googleapis.com", suffixes) {
		t.Error("allow-listed SNI rejected for the car")
	}
}

// An IP that resolves to no filtered MAC stays unrecognised — fail-closed.
func TestPolicyFor_UnknownIPIsNotFiltered(t *testing.T) {
	db := memDB(t)
	seedFilteredCar(t, db, "192.168.4.236")

	s := NewSNIProxyService(config.Config{}, db, nil)
	s.leases = func() map[string][]string {
		return map[string][]string{"0C:29:8F:93:2A:08": {"192.168.4.238"}}
	}
	s.arp = func() map[string]string { return nil }
	s.RefreshCache()

	if _, filtered := s.policyFor("192.168.4.99"); filtered {
		t.Error("an IP that maps to no filtered device was treated as filtered")
	}
}

// An 'open' device must never be recognised as filtered, even if its traffic
// reaches the proxy (defense in depth; its :443 is not redirected here).
func TestPolicyFor_NonFilteredMACDenied(t *testing.T) {
	db := memDB(t)
	seedFilteredCar(t, db, "192.168.4.236")
	mustExec(t, db, `INSERT INTO devices (mac_address, ip_address, status) VALUES ('AA:BB:CC:00:00:02','10.0.0.20','open')`)

	s := NewSNIProxyService(config.Config{}, db, nil)
	s.leases = func() map[string][]string {
		return map[string][]string{"AA:BB:CC:00:00:02": {"10.0.0.20"}}
	}
	s.RefreshCache()

	if _, filtered := s.policyFor("10.0.0.20"); filtered {
		t.Error("an 'open' device must not be recognised as filtered by the SNI proxy")
	}
}

// THE INVARIANT, preserved after the MAC re-key: the allow list is GLOBAL —
// every filtered device resolves to the very same suffix slice. There is no
// per-device privilege a wrong MAC/IP could escalate into; a mismatch can only
// cause a wrongful DENY, never a wrongful ALLOW. policies /
// policy_allowed_domains / device_policies exist in the schema but no service
// reads them; switch per-device lists on and this test must be confronted.
func TestPolicyFor_AllFilteredDevicesShareOneList(t *testing.T) {
	db := memDB(t)
	seedFilteredCar(t, db, "192.168.4.236")
	mustExec(t, db, `INSERT INTO devices (mac_address, ip_address, hostname, status)
		VALUES ('AA:BB:CC:DD:EE:FF', '192.168.4.150', 'other', 'filtered')`)

	s := NewSNIProxyService(config.Config{}, db, nil)
	s.leases = func() map[string][]string {
		return map[string][]string{
			"0C:29:8F:93:2A:08": {"192.168.4.238"},
			"AA:BB:CC:DD:EE:FF": {"192.168.4.150"},
		}
	}
	s.RefreshCache()

	a, fa := s.policyFor("192.168.4.238")
	b, fb := s.policyFor("192.168.4.150")
	if !fa || !fb {
		t.Fatal("both filtered devices must be recognised")
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("PER-DEVICE ALLOW LISTS DETECTED: %v vs %v.\n"+
			"Re-keying by MAC must still serve ONE global list; if lists are now "+
			"per-device, a MAC/IP mismatch can grant the WRONG list.", a, b)
	}
}

// ── LogSNIEvent source tag ─────────────────────────────────────

// The SNI proxy stamps its own source so a TLS verdict is never confused with a
// plain nftables forward-chain drop (both once shared source='forward').
func TestLogSNIEvent_TagsSourceSNIProxy(t *testing.T) {
	db := memDB(t)
	tl := NewTrafficLogService(db)
	tl.LogSNIEvent("192.168.4.237", "mtalk.google.com", false)

	var source, protocol string
	if err := db.QueryRow(`SELECT source, protocol FROM query_log WHERE domain='mtalk.google.com'`).Scan(&source, &protocol); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if source != "sniproxy" {
		t.Errorf("source = %q, want sniproxy (distinct from forward-chain drops)", source)
	}
	if protocol != "TLS" {
		t.Errorf("protocol = %q, want TLS", protocol)
	}
}
