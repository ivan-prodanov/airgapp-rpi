package services

import (
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
