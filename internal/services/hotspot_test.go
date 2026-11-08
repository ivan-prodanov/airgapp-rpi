package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// passingGate installs a gate that verifies clean, for the tests whose
// subject is the systemctl call rather than the gate itself. A HotspotService
// with NO gate now refuses to raise the AP at all — see
// TestSetEnabledRefusesToStartWithNoGateInstalled.
func passingGate(s *HotspotService) {
	s.SetFirewallGate(func() error { return nil }, func() error { return nil })
}

func TestSetEnabledRunsSystemctl(t *testing.T) {
	exec := executor.New(true) // DryRun: records, does not execute
	s := NewHotspotService(nil, exec)
	passingGate(s)

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
	passingGate(s)
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

// A HotspotService with no gate wired must NOT be treated as "nothing to
// check" — that fail-open default is how a second construction site silently
// raises an ungated AP. Lowering, though, stays ungated even here.
func TestSetEnabledRefusesToStartWithNoGateInstalled(t *testing.T) {
	exec := executor.New(true)
	s := NewHotspotService(nil, exec) // no SetFirewallGate call

	err := s.SetEnabled(true)
	if err == nil {
		t.Fatal("a HotspotService with no firewall gate must refuse to raise the AP")
	}
	if !strings.Contains(err.Error(), "gate") {
		t.Fatalf("the error must name the missing gate, got: %v", err)
	}
	for _, cmd := range exec.Recorded() {
		if cmd == "systemctl start hostapd" {
			t.Fatal("LEAK: hostapd was started with no firewall gate installed")
		}
	}

	// ...but taking it down must still work with no gate at all.
	if err := s.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false) must never be gated: %v", err)
	}
	found := false
	for _, cmd := range exec.Recorded() {
		if cmd == "systemctl stop hostapd" {
			found = true
		}
	}
	if !found {
		t.Fatal("stop must still have run with no gate installed")
	}
}

// The self-heal path end to end: verify fails, apply repairs the ruleset, the
// second verify passes, and only then does the AP come up.
func TestSetEnabledSelfHealsThenStarts(t *testing.T) {
	exec := executor.New(true)
	s := NewHotspotService(nil, exec)

	applied := 0
	verifies := 0
	s.SetFirewallGate(
		func() error {
			verifies++
			if applied == 0 {
				return fmt.Errorf("forward chain missing")
			}
			return nil
		},
		func() error { applied++; return nil },
	)

	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("a firewall repaired by reapply must allow the AP up: %v", err)
	}
	if applied != 1 {
		t.Fatalf("applyFirewall ran %d times, want 1", applied)
	}
	if verifies != 2 {
		t.Fatalf("verifyFirewall ran %d times, want 2 (before and after the reapply)", verifies)
	}
	found := false
	for _, cmd := range exec.Recorded() {
		if cmd == "systemctl start hostapd" {
			found = true
		}
	}
	if !found {
		t.Fatal("the AP must come up once the reapply satisfies the gate")
	}
}

// When the reapply itself fails, the operator needs to see THAT — it is
// usually the real cause. Reporting only the (downstream) verify failure
// hides it.
func TestSetEnabledReportsBothVerifyAndApplyFailures(t *testing.T) {
	exec := executor.New(true)
	s := NewHotspotService(nil, exec)
	s.SetFirewallGate(
		func() error { return fmt.Errorf("forward chain missing") },
		func() error { return fmt.Errorf("nft -f exited 1") },
	)

	err := s.SetEnabled(true)
	if err == nil {
		t.Fatal("SetEnabled(true) must fail when the firewall cannot be verified")
	}
	if !strings.Contains(err.Error(), "forward chain missing") {
		t.Fatalf("error must carry the verify failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "nft -f exited 1") {
		t.Fatalf("error must carry the apply failure too, got: %v", err)
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

// hostapd.conf holds the WPA passphrase: only root may read it, including
// when the file already exists with a looser mode.
func TestHotspotConfMode0600(t *testing.T) {
	db := migratedDB(t)
	mustExec(t, db, `INSERT INTO settings (key, value) VALUES ('ap_ssid','Airgapp'),('ap_password','longenough'),('ap_channel','36')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
	s := NewHotspotService(db, executor.New(true))
	s.confPath = filepath.Join(t.TempDir(), "hostapd.conf")
	if err := os.WriteFile(s.confPath, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fi, err := os.Stat(s.confPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("hostapd.conf mode %v, want 0600", fi.Mode().Perm())
	}
}
