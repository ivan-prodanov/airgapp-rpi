package services

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
)

// SNIProxyService is the transparent TLS-SNI gate. A filtered device's
// outbound tcp/443 is REDIRECTed here by nftables; the proxy reads the
// cleartext SNI from the ClientHello, checks the requested hostname
// against the device's policy allow-list, and either splices the
// connection straight through to that host (raw byte copy — no
// decryption, TLS pinning untouched) or drops it.
//
// Filtering by the hostname the car actually asked for — instead of by a
// shared IP — closes the co-hosted-service leak of the old IP-set model:
// allowing daws.tesla.services permits only that SNI, not whatever else
// Tesla co-hosts on the same CloudFront/AWS address.
type SNIProxyService struct {
	cfg        config.Config
	db         *sql.DB
	trafficLog *TrafficLogService

	// dial opens the upstream connection for an allowed SNI. It is a
	// field so a test can inject a fake and assert it is NEVER called for
	// a protected-denied or non-allow-listed SNI.
	dial func(network, addr string) (net.Conn, error)

	// leases returns every IP dnsmasq currently has leased, keyed by
	// upper-case MAC. A field for the same reason dial is: tests inject a
	// fixture instead of writing to /var/lib.
	leases func() map[string][]string

	// arp returns the live IP→MAC map (upper-case MAC) from the kernel ARP
	// table, restricted to the LAN interface — the fallback resolver for a
	// client not yet in the lease table. Injectable for the same reason.
	arp func() map[string]string

	mu       sync.RWMutex
	suffixes []string        // GLOBAL allow-list, shared by every filtered device
	filtered map[string]bool // upper-case MAC -> is a status='filtered' device
}

func NewSNIProxyService(cfg config.Config, db *sql.DB, trafficLog *TrafficLogService) *SNIProxyService {
	return &SNIProxyService{
		cfg:        cfg,
		db:         db,
		trafficLog: trafficLog,
		filtered:   map[string]bool{},
		dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 10*time.Second)
		},
		leases: currentLeasedIPsByMAC,
		arp:    func() map[string]string { return currentARPByIP(cfg.LANInterface) },
	}
}

// RefreshCache rebuilds the two things the connection-time allow decision
// needs: the GLOBAL allow-list (the union of filter_domains.enabled=1 across
// every filter with its own enabled=1 toggle) and the set of status='filtered'
// device MACs.
//
// It deliberately does NOT snapshot IP→device membership. That is resolved live
// per connection from the lease/ARP tables (see clientMAC), so a device that
// reassociated onto a new address seconds ago is recognised immediately — the
// IP no longer has to wait up to a minute for the 30s device-scan to land in a
// cache before its own allow-listed traffic stops being hard-denied. (Measured
// on-car under the old IP-snapshot model: 341 drops vs 412 allows in 24h.)
// open / blocked / unknown devices are simply absent from the filtered set:
// their :443 is never redirected here, or is dropped at the forward chain.
func (s *SNIProxyService) RefreshCache() {
	suffRows, err := s.db.Query(`
		SELECT DISTINCT fd.domain
		FROM filter_domains fd
		JOIN filters f ON f.id = fd.preset_id
		WHERE fd.enabled = 1 AND f.enabled = 1
	`)
	if err != nil {
		log.Printf("[SNI] refresh: list domains: %v", err)
		return
	}
	defer suffRows.Close()

	var suffixes []string
	for suffRows.Next() {
		var dom string
		if err := suffRows.Scan(&dom); err != nil {
			log.Printf("[SNI] refresh scan domain: %v", err)
			continue
		}
		dom = strings.ToLower(strings.TrimSpace(dom))
		if dom != "" {
			suffixes = append(suffixes, dom)
		}
	}

	macRows, err := s.db.Query(`SELECT mac_address FROM devices WHERE status = 'filtered'`)
	if err != nil {
		log.Printf("[SNI] refresh: list filtered devices: %v", err)
		return
	}
	defer macRows.Close()

	filtered := make(map[string]bool)
	for macRows.Next() {
		var mac string
		if err := macRows.Scan(&mac); err != nil {
			log.Printf("[SNI] refresh scan device: %v", err)
			continue
		}
		if mac = strings.ToUpper(strings.TrimSpace(mac)); mac != "" {
			filtered[mac] = true
		}
	}

	s.mu.Lock()
	s.suffixes = suffixes
	s.filtered = filtered
	s.mu.Unlock()
}

// clientMAC resolves a client IP to its upper-case MAC at connection time,
// reading the live lease and ARP tables rather than any periodic snapshot.
// dnsmasq writes the lease at DHCP-ACK (before the client can route a packet),
// and the kernel holds an ARP entry for any host that just sent us one — so a
// freshly-reassociated client is resolvable the instant it connects. Returns ""
// if neither source knows the IP.
func (s *SNIProxyService) clientMAC(clientIP string) string {
	if s.leases != nil {
		for mac, ips := range s.leases() {
			for _, ip := range ips {
				if ip == clientIP {
					return strings.ToUpper(strings.TrimSpace(mac))
				}
			}
		}
	}
	if s.arp != nil {
		if mac, ok := s.arp()[clientIP]; ok {
			return strings.ToUpper(strings.TrimSpace(mac))
		}
	}
	return ""
}

// policyFor returns the global allow-list and whether clientIP belongs to a
// filtered device. A client that resolves to no filtered MAC gets (nil, false)
// — a hard deny, fail-closed.
func (s *SNIProxyService) policyFor(clientIP string) (suffixes []string, filtered bool) {
	mac := s.clientMAC(clientIP)
	if mac == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.suffixes, s.filtered[mac]
}

// matchSNI reports whether sni equals or is a subdomain of any suffix.
func matchSNI(sni string, suffixes []string) bool {
	sni = strings.ToLower(strings.TrimSpace(sni))
	if sni == "" {
		return false
	}
	for _, suf := range suffixes {
		if suf == "" {
			continue
		}
		if sni == suf || strings.HasSuffix(sni, "."+suf) {
			return true
		}
	}
	return false
}

// sniAllowed is the full allow decision for one connection: the SNI must
// not be on the protected-deny floor AND must match the device's
// allow-list. The protected-deny check is first and overrides everything
// — so even a catastrophically broad allow-list cannot reach a protected
// Tesla endpoint.
func sniAllowed(sni string, suffixes []string) bool {
	if isProtectedDenied(sni) {
		return false
	}
	return matchSNI(sni, suffixes)
}

// ListenAndServe binds cfg.SNIProxyPort and serves redirected :443
// connections. Blocks; intended to run in its own goroutine.
func (s *SNIProxyService) ListenAndServe() error {
	s.RefreshCache()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			s.RefreshCache()
		}
	}()

	addr := fmt.Sprintf(":%d", s.cfg.SNIProxyPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("sni proxy listen %s: %w", addr, err)
	}
	log.Printf("[SNI] transparent SNI proxy listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[SNI] accept: %v", err)
			continue
		}
		go s.handle(conn)
	}
}

func (s *SNIProxyService) handle(client net.Conn) {
	defer client.Close()
	// A malformed connection must never crash the daemon.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[SNI] panic in connection handler: %v", r)
		}
	}()
	clientIP, _, _ := net.SplitHostPort(client.RemoteAddr().String())

	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, sni, err := readClientHello(client)
	if err != nil {
		log.Printf("[SNI] %s: read ClientHello: %v", clientIP, err)
		return
	}
	client.SetReadDeadline(time.Time{})

	suffixes, filtered := s.policyFor(clientIP)
	allowed := filtered && sniAllowed(sni, suffixes)

	if !allowed {
		shown := sni
		if shown == "" {
			shown = "(no SNI)"
		}
		log.Printf("[SNI-DROP] client=%s sni=%s", clientIP, shown)
		s.trafficLog.LogSNIEvent(clientIP, sni, false)
		return
	}

	// Re-resolve and dial the requested hostname. We don't need the
	// car's original destination IP — the SNI hostname is the security
	// boundary, and the car's end-to-end TLS (incl. cert pinning) is to
	// that hostname regardless of which of its IPs we connect to.
	upstream, err := s.dial("tcp", net.JoinHostPort(sni, "443"))
	if err != nil {
		log.Printf("[SNI] %s: dial %s: %v", clientIP, sni, err)
		s.trafficLog.LogSNIEvent(clientIP, sni, false)
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(hello); err != nil {
		log.Printf("[SNI] %s: replay ClientHello to %s: %v", clientIP, sni, err)
		return
	}
	log.Printf("[SNI-ALLOW] client=%s sni=%s", clientIP, sni)
	s.trafficLog.LogSNIEvent(clientIP, sni, true)

	// Splice — raw bidirectional copy, no decryption.
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// readClientHello reads the first TLS record from conn and returns its
// raw bytes (to replay to the upstream) plus the SNI hostname parsed from
// the ClientHello (empty if absent).
func readClientHello(conn net.Conn) (raw []byte, sni string, err error) {
	header := make([]byte, 5)
	if _, err = io.ReadFull(conn, header); err != nil {
		return nil, "", err
	}
	if header[0] != 0x16 { // TLS handshake content type
		return nil, "", fmt.Errorf("not a TLS handshake (content type 0x%02x)", header[0])
	}
	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen <= 0 || recLen > 16384 {
		return nil, "", fmt.Errorf("bad TLS record length %d", recLen)
	}
	body := make([]byte, recLen)
	if _, err = io.ReadFull(conn, body); err != nil {
		return nil, "", err
	}
	return append(header, body...), parseSNI(body), nil
}

// parseSNI extracts the host_name from a TLS ClientHello handshake
// message (b starts at the handshake header). Returns "" if there is no
// server_name extension. Defensive against truncation at every step.
func parseSNI(b []byte) string {
	if len(b) < 4 || b[0] != 0x01 { // 0x01 = ClientHello
		return ""
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if len(b) > hsLen {
		b = b[:hsLen]
	}
	if len(b) < 34 { // version(2) + random(32)
		return ""
	}
	b = b[34:]

	if len(b) < 1 { // session_id length
		return ""
	}
	sidLen := int(b[0])
	if len(b) < 1+sidLen {
		return ""
	}
	b = b[1+sidLen:]

	if len(b) < 2 { // cipher_suites length
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+csLen {
		return ""
	}
	b = b[2+csLen:]

	if len(b) < 1 { // compression_methods length
		return ""
	}
	cmLen := int(b[0])
	if len(b) < 1+cmLen {
		return ""
	}
	b = b[1+cmLen:]

	if len(b) < 2 { // extensions length
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) > extLen {
		b = b[:extLen]
	}

	for len(b) >= 4 {
		extType := binary.BigEndian.Uint16(b[:2])
		extDataLen := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+extDataLen {
			return ""
		}
		extData := b[4 : 4+extDataLen]
		b = b[4+extDataLen:]
		if extType != 0x0000 { // server_name
			continue
		}
		if len(extData) < 2 {
			return ""
		}
		listLen := int(binary.BigEndian.Uint16(extData[:2]))
		list := extData[2:]
		if len(list) > listLen {
			list = list[:listLen]
		}
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:3]))
			if len(list) < 3+nameLen {
				return ""
			}
			if nameType == 0x00 { // host_name
				return strings.ToLower(string(list[3 : 3+nameLen]))
			}
			list = list[3+nameLen:]
		}
		return ""
	}
	return ""
}
