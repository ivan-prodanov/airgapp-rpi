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

// Typed in the car, airgapp.net opens the console; the Pi's own tailnet name
// answers a second intercepted address, so its :443/:10000 can reach Tailscale.
func TestDefaultsConsoleHostAndTailnetAddr(t *testing.T) {
	d := Defaults()
	if d.ConsoleHost != "airgapp.net" || d.TailnetAddr != "203.0.113.81" {
		t.Fatalf("ConsoleHost = %q, TailnetAddr = %q", d.ConsoleHost, d.TailnetAddr)
	}
	if d.TailnetAddr == d.EnrolAddr {
		t.Fatal("the tailnet address must differ from the enrol address: their :443 go to different places")
	}
}
