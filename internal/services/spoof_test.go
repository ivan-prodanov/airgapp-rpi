package services

import (
	"bytes"
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/web"
)

// The enrol page is plain HTTP. A browser tries https:// first; refusing the
// handshake for the enrol host makes it fall back to http:// at once,
// instead of showing a certificate warning for the captive-check cert.
func TestSpoofTLSRefusesEnrolHost(t *testing.T) {
	s := NewSpoofService(config.Config{EnrolHost: "airgapp.me"}, nil)
	cert, err := selfSignedCert(spoofConnManHost)
	if err != nil {
		t.Fatal(err)
	}
	c := s.tlsConfig(cert)
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "airgapp.me"}); err == nil {
		t.Fatal("handshake for the enrol host should be refused")
	}
	for _, name := range []string{spoofConnManHost, ""} {
		if got, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: name}); err != nil || got == nil {
			t.Fatalf("%q: %v", name, err)
		}
	}
}

// The enrol page's QR carries the Airgapp mark in the middle, like System →
// Users; the vhost serves that icon, and only on the enrol host.
func TestEnrolServesIcon(t *testing.T) {
	s := NewSpoofService(config.Config{EnrolHost: "airgapp.me"}, nil)
	s.SetEnrolDeps(web.Content, &TeslaTokenService{}, NewRemoteService())
	get := func(host, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://"+host+path, nil)
		rec := httptest.NewRecorder()
		s.handle(rec, req)
		return rec
	}
	rec := get("airgapp.me", "/airgapp-icon.png")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(rec.Body.Bytes(), []byte("\x89PNG")) {
		t.Fatalf("icon: %d %q %d bytes", rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
	}
	if other := get("connman.vn.tesla.services", "/airgapp-icon.png"); other.Body.Len() != 0 {
		t.Fatalf("icon served off the enrol host: %d bytes", other.Body.Len())
	}
}
