package config

import "testing"

// The enrol page lives at a real-looking name: browsers treat a typed
// "air.gapp" (no such top-level domain) as a search, not an address.
func TestDefaultsEnrolHost(t *testing.T) {
	if got := Defaults().EnrolHost; got != "airgapp.me" {
		t.Fatalf("EnrolHost = %q, want airgapp.me", got)
	}
}
