package config

import "testing"

// The enrol page lives at a real-looking name: browsers treat a typed
// "air.gapp" (no such top-level domain) as a search, not an address.
func TestDefaultsEnrolHost(t *testing.T) {
	if got := Defaults().EnrolHost; got != "airgapp.me" {
		t.Fatalf("EnrolHost = %q, want airgapp.me", got)
	}
}

// The enrol host answers with a public-looking address the Pi intercepts: the
// car's browser won't connect to a private one (192.168.4.1). TEST-NET-3 is
// never routed on the internet, so off the hotspot it goes nowhere.
func TestDefaultsEnrolAddr(t *testing.T) {
	if got := Defaults().EnrolAddr; got != "203.0.113.80" {
		t.Fatalf("EnrolAddr = %q, want 203.0.113.80", got)
	}
}
