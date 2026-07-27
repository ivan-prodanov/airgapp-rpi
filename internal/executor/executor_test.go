package executor

import (
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
