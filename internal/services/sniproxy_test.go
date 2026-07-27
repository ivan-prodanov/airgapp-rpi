package services

import (
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"reflect"
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
				// 127.0.0.1 is the loopback RemoteAddr driveHandle produces.
				allow: map[string][]string{"127.0.0.1": legitAllowed},
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

// ── RefreshCache classification ────────────────────────────────

func TestSNIProxy_CacheClassification(t *testing.T) {
	db := memDB(t)

	// A filtered device gets the global allow-list; an open device must
	// be absent from the cache entirely (its :443 is never redirected).
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

	// Seeded system filters ship enabled (Tesla AP/Nav has 3 audited
	// domains since v18, Maps & Time has 5). For this test, disable any
	// system filter so the cache contains only our injected domain.
	mustExec(t, db, `UPDATE filters SET enabled=0 WHERE is_system=1`)

	s := NewSNIProxyService(config.Config{}, db, NewTrafficLogService(db))
	s.RefreshCache()

	got := s.allow["10.0.0.10"]
	if len(got) != 1 || got[0] != "auth.tesla.com" {
		t.Errorf("filtered device cache = %v, want [auth.tesla.com] (disabled domain must be excluded)", got)
	}
	if _, ok := s.allow["10.0.0.20"]; ok {
		t.Errorf("open device must be absent from the SNI allow-list cache")
	}
}

// leaseFixture returns a lease table in the shape captured from the Pi:
// one MAC holding several simultaneously-valid leases.
func leaseFixture() map[string][]string {
	return map[string][]string{
		"0C:29:8F:93:2A:08": {"192.168.4.238", "192.168.4.236", "192.168.4.237"},
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

// THE REPRO, end to end: the car is really on .238, the devices row still says
// .236, and tile.googleapis.com is explicitly allow-listed. Before the lease
// lookup this dropped, because a map miss makes `known` false and sniAllowed
// never runs.
func TestRefreshCache_RecognisesADeviceOnAnyLeasedIP(t *testing.T) {
	db := memDB(t)
	seedFilteredCar(t, db, "192.168.4.236") // stale on purpose

	s := NewSNIProxyService(config.Config{}, db, nil)
	s.leases = leaseFixture
	s.RefreshCache()

	suffixes, known := s.allowedSuffixes("192.168.4.238")
	if !known {
		t.Fatal("car on its real leased IP was not recognised — its own allow-listed traffic would be dropped")
	}
	if !sniAllowed("tile.googleapis.com", suffixes) {
		t.Error("allow-listed SNI rejected for the car")
	}
}

// An address the car does NOT hold must stay unknown. Pins that the fix widens
// recognition to the device's own leases and nothing further.
func TestRefreshCache_DoesNotRecogniseAnUnleasedIP(t *testing.T) {
	db := memDB(t)
	seedFilteredCar(t, db, "192.168.4.236")

	s := NewSNIProxyService(config.Config{}, db, nil)
	s.leases = leaseFixture
	s.RefreshCache()

	if _, known := s.allowedSuffixes("192.168.4.99"); known {
		t.Error("an IP the car never held was recognised")
	}
}

// THE INVARIANT that makes keying this map by IP safe at all.
//
// Every entry must resolve to the SAME suffix list. That is why an IP mix-up
// can only ever cause a wrongful DENY and never a wrongful ALLOW: there is no
// per-device privilege for a mismatched IP to escalate into.
//
// The schema already contains the design that would break this —
// policies / policy_allowed_domains / device_policies exist but no service
// reads them today. If per-device allow lists are ever switched on, this test
// fails, and whoever does it has to confront the fact that they have just
// turned this lookup into a privilege boundary.
func TestRefreshCache_AllFilteredDevicesShareOneList(t *testing.T) {
	db := memDB(t)
	seedFilteredCar(t, db, "192.168.4.236")
	mustExec(t, db, `INSERT INTO devices (mac_address, ip_address, hostname, status)
		VALUES ('AA:BB:CC:DD:EE:FF', '192.168.4.150', 'other', 'filtered')`)

	s := NewSNIProxyService(config.Config{}, db, nil)
	s.leases = leaseFixture
	s.RefreshCache()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.allow) < 2 {
		t.Fatalf("expected entries for both filtered devices, got %d", len(s.allow))
	}
	var first []string
	for ip, got := range s.allow {
		if first == nil {
			first = got
			continue
		}
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("PER-DEVICE ALLOW LISTS DETECTED at %s: %v vs %v.\n"+
				"Keying this map by IP is only safe while every filtered device shares one list. "+
				"If lists are now per-device, an IP mismatch can grant the WRONG list — "+
				"re-key the map by MAC before shipping this.", ip, got, first)
		}
	}
}
