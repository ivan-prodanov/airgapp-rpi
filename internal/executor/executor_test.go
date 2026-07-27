package executor

import (
	"strconv"
	"testing"
)

// TestRecordedReturnsDefensiveCopy verifies that Recorded() returns a copy,
// not a reference to the internal slice.
func TestRecordedReturnsDefensiveCopy(t *testing.T) {
	exec := New(true) // DryRun: records commands
	exec.Run("echo", "hello")

	recorded1 := exec.Recorded()
	if len(recorded1) != 1 {
		t.Fatalf("first Recorded() returned %d commands, want 1", len(recorded1))
	}

	// Mutate the returned slice
	recorded1[0] = "mutated"

	// Fetch again and verify the internal state was not affected
	recorded2 := exec.Recorded()
	if recorded2[0] != "echo hello" {
		t.Fatalf("second Recorded() returned %q, want 'echo hello' (internal state was mutated)", recorded2[0])
	}
}

// The finding this pins: recording was gated to DryRun to stop unbounded
// growth in production — but dry_run is a persistent key in config.yaml, not a
// test-only flag, so a daemon left in dry-run (exactly what someone debugging
// would set) grew the slice forever. The bound has to be a real bound.
//
// It also asserts the ORDER that survives: oldest-to-newest within the kept
// window, because service tests index into Recorded() positionally.
func TestRecordedIsBoundedAndKeepsTheMostRecent(t *testing.T) {
	exec := New(true)

	const over = maxRecorded + 50
	for i := 0; i < over; i++ {
		exec.Run("echo", strconv.Itoa(i))
	}

	got := exec.Recorded()
	if len(got) != maxRecorded {
		t.Fatalf("Recorded() returned %d commands after %d runs, want the ring bound %d", len(got), over, maxRecorded)
	}
	// The window kept must be the LAST maxRecorded, still oldest-to-newest.
	for i, cmd := range got {
		want := "echo " + strconv.Itoa(over-maxRecorded+i)
		if cmd != want {
			t.Fatalf("Recorded()[%d] = %q, want %q — the ring must keep the most recent entries in call order", i, cmd, want)
		}
	}
}

// TestNonDryRunExecutorRecordsNothing verifies that non-DryRun executors
// do not record any commands.
func TestNonDryRunExecutorRecordsNothing(t *testing.T) {
	exec := New(false) // DryRun: false, does not record
	exec.Run("true")

	recorded := exec.Recorded()
	if len(recorded) != 0 {
		t.Fatalf("non-DryRun executor recorded %d commands, want 0: %v", len(recorded), recorded)
	}
}
