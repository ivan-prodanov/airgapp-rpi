package services

import (
	"crypto/tls"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
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
