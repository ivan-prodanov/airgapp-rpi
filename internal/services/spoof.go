package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// Tesla MCU3 polls connman.vn.tesla.services as its captive-portal /
// connectivity probe and declares the WiFi link "online" only when it
// gets a 200 with these headers. Packet capture confirmed the probe is
// plain HTTP on tcp/80.
//
// The Tesla refuses to connect to a private (RFC1918) IP for the check —
// a check domain resolving to a private address is the fingerprint of
// DNS hijacking, which connman's captive-portal detector rejects before
// it ever opens a socket. So we do NOT hijack DNS. connman resolves to
// its real public CloudFront IP (which the Tesla connects to happily),
// and the firewall's nat prerouting chain transparently DNATs that :80
// connection to this responder. See FirewallService.generateConfig.
const (
	spoofConnManHost = "connman.vn.tesla.services"
	// Legacy DNS-hijack override written by earlier versions. Removed on
	// startup — hijacking connman to the Pi's private IP tripped the
	// Tesla's captive-portal detector and the car never connected.
	spoofDnsmasqPath = "/etc/dnsmasq.d/netfilter-spoof.conf"
)

// Keys are the EXACT case the Tesla connman expects (capital M in
// "ConnMan"), matching the proven tesla-android reference config. They
// are written via direct map assignment in handle() — not Header.Set,
// which would canonicalise "X-ConnMan-Status" down to "X-Connman-Status"
// and (connman matches case-sensitively) make the car flag a captive
// portal.
var spoofConnManHeaders = map[string]string{
	"X-ConnMan-Status": "online",
	"X-Cache":          "Hit from cloudfront",
}

// enrolTokenTTL is the claim window for a self-service airgapp.me enrol code:
// scan + first-use within this long or it lapses (see TeslaTokenService.Validate).
const enrolTokenTTL = 10 * time.Minute

// SpoofService runs the captive-check responder (Tesla connman) on :80/:443,
// and — when enrol deps are wired via SetEnrolDeps — also vhosts the
// self-service enrol-QR page on the same :80 listener under the EnrolHost
// (airgapp.me). The Tesla's :80 traffic is steered here by a firewall DNAT rule;
// a LAN device typing http://airgapp.me/ reaches the same listener by its real
// gateway IP, and the Host header picks the branch.
type SpoofService struct {
	cfg  config.Config
	exec *executor.Executor

	// Enrol deps, injected by SetEnrolDeps (nil until then → the airgapp.me
	// vhost is simply off and every request gets the connman spoof).
	webFS  fs.FS
	tokens *TeslaTokenService
	remote *RemoteService

	// The Pi's tailnet (WatchTailnet): where ConsoleHost redirects to.
	mu      sync.RWMutex
	tailnet Tailnet
}

// SetTailnet records the Pi's tailnet: ConsoleHost then redirects to the
// console as Tailscale serves it.
func (s *SpoofService) SetTailnet(t Tailnet) {
	s.mu.Lock()
	s.tailnet = t
	s.mu.Unlock()
}

// consoleURL is where ConsoleHost sends the car: the console under the Pi's
// tailnet name (real certificate) when Tailscale is signed in, else the Pi's
// own console address on the hotspot.
func (s *SpoofService) consoleURL() string {
	s.mu.RLock()
	t := s.tailnet
	s.mu.RUnlock()
	if t.Known() {
		return t.ConsoleURL()
	}
	scheme, port := "http", ""
	if s.cfg.UseTLS {
		scheme = "https"
	}
	if _, p, err := net.SplitHostPort(s.cfg.ListenAddr); err == nil && p != "" &&
		!(scheme == "http" && p == "80") && !(scheme == "https" && p == "443") {
		port = ":" + p
	}
	return scheme + "://" + s.cfg.LANGateway + port + "/"
}

func NewSpoofService(cfg config.Config, exec *executor.Executor) *SpoofService {
	return &SpoofService{cfg: cfg, exec: exec}
}

// SetEnrolDeps turns on the airgapp.me enrol vhost. Separate from the
// constructor because the web embed FS lives in main and the token/remote
// services are built alongside this one. Safe to leave uncalled — without it
// the :80 listener is the plain connman spoof it always was.
func (s *SpoofService) SetEnrolDeps(webFS fs.FS, tokens *TeslaTokenService, remote *RemoteService) {
	s.webFS = webFS
	s.tokens = tokens
	s.remote = remote
}

// enrolEnabled reports whether the airgapp.me vhost is wired and configured.
func (s *SpoofService) enrolEnabled() bool {
	return s.cfg.EnrolHost != "" && s.webFS != nil && s.tokens != nil && s.remote != nil
}

// EnsureNoDnsmasqHijack removes the legacy address= override if present.
// The connman spoof now relies on transparent DNAT (firewall prerouting),
// which requires connman.vn.tesla.services to resolve to its real public
// IP — the Tesla will not connect to a private address for its check.
// Idempotent: a no-op once the file is gone.
func (s *SpoofService) EnsureNoDnsmasqHijack() error {
	if _, err := os.Stat(spoofDnsmasqPath); err != nil {
		return nil // already absent
	}
	if err := os.Remove(spoofDnsmasqPath); err != nil {
		return fmt.Errorf("remove stale spoof override %s: %w", spoofDnsmasqPath, err)
	}
	if _, err := s.exec.Run("systemctl", "restart", "dnsmasq"); err != nil {
		return fmt.Errorf("restart dnsmasq after removing spoof override: %w", err)
	}
	log.Printf("[SPOOF] removed legacy DNS hijack %s; connman resolves to its real IP now", spoofDnsmasqPath)
	return nil
}

// newServer builds the shared http.Server (same handler + timeouts) for
// both the plain-HTTP and HTTPS listeners.
func (s *SpoofService) newServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

// ListenAndServe binds tcp/80 on cfg.LANGateway — the DNAT target for the
// Tesla's connman probe. Blocks; intended to run in its own goroutine.
func (s *SpoofService) ListenAndServe() error {
	addr := net.JoinHostPort(s.cfg.LANGateway, "80")
	log.Printf("[SPOOF] captive-check responder listening on http://%s (host %s)", addr, spoofConnManHost)
	return s.newServer(addr).ListenAndServe()
}

// ListenAndServeTLS binds tcp/443 with a self-signed cert. connman's probe
// is HTTP, so this is a belt-and-braces listener for the case a firmware
// revision switches to HTTPS. Blocks; intended to run in its own goroutine.
func (s *SpoofService) ListenAndServeTLS() error {
	cert, err := selfSignedCert(spoofConnManHost)
	if err != nil {
		return fmt.Errorf("generate spoof TLS cert: %w", err)
	}
	addr := net.JoinHostPort(s.cfg.LANGateway, "443")
	srv := s.newServer(addr)
	srv.TLSConfig = s.tlsConfig(cert)
	log.Printf("[SPOOF] captive-check TLS responder listening on https://%s (host %s)", addr, spoofConnManHost)
	return srv.ListenAndServeTLS("", "")
}

// tlsConfig serves the captive-check cert to everything except the enrol
// and console hosts: the enrol page is plain HTTP, and a browser trying https:// first
// should fail the handshake and fall back to http:// at once rather than
// show a warning for the wrong certificate.
func (s *SpoofService) tlsConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			for _, host := range []string{s.cfg.EnrolHost, s.cfg.ConsoleHost} {
				if host != "" && strings.EqualFold(hello.ServerName, host) {
					return nil, fmt.Errorf("%s is plain HTTP only", host)
				}
			}
			return &cert, nil
		},
	}
}

// selfSignedCert builds an in-memory self-signed certificate for host.
// Regenerated on every boot — connman doesn't pin our cert.
func selfSignedCert(host string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// handle answers every request on the spoof listeners with the connman
// "online" 200. tcp/80 + tcp/443 on the Pi exist solely for this spoof,
// so the response is unconditional. Host + scheme are logged so a real
// Tesla probe shows up in the journal as evidence.
func (s *SpoofService) handle(w http.ResponseWriter, r *http.Request) {
	// Enrol vhost (EnrolHost) — plain HTTP only (no cert), matched by Host header.
	// Everything else, and ALL :443 traffic, falls through to the connman spoof.
	// Console host — typed in the car: a redirect to the console.
	if r.TLS == nil && s.cfg.ConsoleHost != "" && strings.EqualFold(hostWithoutPort(r.Host), s.cfg.ConsoleHost) {
		to := s.consoleURL()
		log.Printf("[SPOOF] %s → %s (client=%s)", s.cfg.ConsoleHost, to, r.RemoteAddr)
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	if r.TLS == nil && s.enrolEnabled() && hostWithoutPort(r.Host) == s.cfg.EnrolHost {
		s.handleEnrol(w, r)
		return
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// Direct map assignment bypasses Go's MIME canonicalisation so the
	// keys go out on the wire with their literal case (X-ConnMan-Status).
	hdr := w.Header()
	for k, v := range spoofConnManHeaders {
		hdr[k] = []string{v}
	}
	w.WriteHeader(http.StatusOK)
	log.Printf("[SPOOF] %s %s://%s%s → 200 (client=%s)", r.Method, scheme, r.Host, r.URL.Path, r.RemoteAddr)
}

// hostWithoutPort strips a trailing :port from a request Host so "airgapp.me"
// and "airgapp.me:80" both match the configured EnrolHost.
func hostWithoutPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// handleEnrol routes the enrol vhost (EnrolHost): the QR page, its script, the
// Airgapp mark drawn in the middle of the QR, and the unauthenticated
// token-issue endpoint. All LAN-only (only the Pi answers the
// enrol host, and :80 is wlan0-bound), which is the whole security premise: a relay
// token can't command the car without the car separately authorising the key.
func (s *SpoofService) handleEnrol(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/index.html"):
		s.serveEnrolAsset(w, "static/enrol/airgapp.html", "text/html; charset=utf-8")
	case r.Method == http.MethodGet && r.URL.Path == "/qrcode.min.js":
		s.serveEnrolAsset(w, "static/js/qrcode.min.js", "application/javascript")
	case r.Method == http.MethodGet && r.URL.Path == "/airgapp-icon.png":
		s.serveEnrolAsset(w, "static/img/airgapp-icon.png", "image/png")
	case r.Method == http.MethodPost && r.URL.Path == "/issue":
		s.handleEnrolIssue(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveEnrolAsset writes an embedded web asset with an explicit content type.
func (s *SpoofService) serveEnrolAsset(w http.ResponseWriter, fsPath, contentType string) {
	data, err := fs.ReadFile(s.webFS, fsPath)
	if err != nil {
		log.Printf("[ENROL] missing asset %s: %v", fsPath, err)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// handleEnrolIssue mints a fresh, short-lived enrol token and returns the
// airgapp://enrol deep link as JSON for the page to render as a QR. No auth:
// anyone on the LAN may mint one, by design — see handleEnrol.
func (s *SpoofService) handleEnrolIssue(w http.ResponseWriter, r *http.Request) {
	enrolURL, ttlSec, err := s.buildEnrolURL(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		log.Printf("[ENROL] issue failed (client=%s): %v", r.RemoteAddr, err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	log.Printf("[ENROL] issued self-service enrol token (ttl=%ds, client=%s)", ttlSec, r.RemoteAddr)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enrol_url":      enrolURL,
		"expires_in_sec": ttlSec,
	})
}

// buildEnrolURL resolves the relay's reachable base URL (the public Funnel URL
// when exposed, else the tailnet hostname), mints a claim-windowed token, and
// assembles the airgapp://enrol?api=…&token=… deep link the app parses.
func (s *SpoofService) buildEnrolURL(ctx context.Context) (string, int, error) {
	st, err := s.remote.Status(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("relay status unavailable: %w", err)
	}
	base := st.BLEFunnelURL
	if base == "" {
		if st.TailnetHostname == "" {
			return "", 0, errors.New("relay is not reachable yet — connect Tailscale (and expose /api/ble via Funnel for phones that aren't on the tailnet)")
		}
		base = "https://" + st.TailnetHostname + "/api/ble"
	}

	label := s.cfg.EnrolHost + " " + time.Now().Format("2006-01-02 15:04")
	issued, err := s.tokens.IssueEphemeral(label, enrolTokenTTL)
	if err != nil {
		return "", 0, fmt.Errorf("issue token: %w", err)
	}

	q := url.Values{}
	q.Set("api", base) // full https URL incl. /api/ble; percent-encoded by Encode
	q.Set("token", issued.Plain)
	return "airgapp://enrol?" + q.Encode(), int(enrolTokenTTL.Seconds()), nil
}
