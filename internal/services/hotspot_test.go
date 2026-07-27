package services

import (
	"fmt"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

func TestSetEnabledRunsSystemctl(t *testing.T) {
	exec := executor.New(true) // DryRun: records, does not execute
	s := NewHotspotService(nil, exec)

	if err := s.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}

	got := exec.Recorded()
	want := []string{"systemctl stop hostapd", "systemctl start hostapd"}
	if len(got) != len(want) {
		t.Fatalf("recorded = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("recorded = %v, want %v", got, want)
		}
	}
}

// SetEnabled must never touch hostapd.conf — that is the whole reason it is
// separate from Apply.
func TestSetEnabledNeverRestartsOrRewrites(t *testing.T) {
	exec := executor.New(true)
	s := NewHotspotService(nil, exec)
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	for _, cmd := range exec.Recorded() {
		if cmd == "systemctl restart hostapd" {
			t.Fatal("SetEnabled must not restart hostapd — that is Apply's job")
		}
	}
}

func TestSetEnabledRefusesToStartWhenFirewallUnverified(t *testing.T) {
	exec := executor.New(true)
	s := NewHotspotService(nil, exec)
	s.SetFirewallGate(
		func() error { return fmt.Errorf("forward chain missing") },
		func() error { return nil }, // apply "succeeds" but verify still fails
	)

	err := s.SetEnabled(true)
	if err == nil {
		t.Fatal("SetEnabled(true) must fail when the firewall cannot be verified")
	}
	for _, cmd := range exec.Recorded() {
		if cmd == "systemctl start hostapd" {
			t.Fatal("LEAK: hostapd was started over an unverified firewall")
		}
	}
}

func TestSetEnabledStartsWhenGatePasses(t *testing.T) {
	exec := executor.New(true)
	s := NewHotspotService(nil, exec)
	s.SetFirewallGate(func() error { return nil }, func() error { return nil })

	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	found := false
	for _, cmd := range exec.Recorded() {
		if cmd == "systemctl start hostapd" {
			found = true
		}
	}
	if !found {
		t.Fatal("a verified firewall must allow the AP up")
	}
}

// Taking the AP DOWN is always safe and must never be gated — otherwise a
// firewall fault would leave the car online, the exact inverse of the point.
func TestSetEnabledDownIsNeverGated(t *testing.T) {
	exec := executor.New(true)
	s := NewHotspotService(nil, exec)
	s.SetFirewallGate(func() error { return fmt.Errorf("broken") }, func() error { return fmt.Errorf("broken") })

	if err := s.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false) must never be blocked by the gate: %v", err)
	}
	found := false
	for _, cmd := range exec.Recorded() {
		if cmd == "systemctl stop hostapd" {
			found = true
		}
	}
	if !found {
		t.Fatal("stop must still have run")
	}
}
