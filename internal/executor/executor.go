package executor

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Executor struct {
	DryRun  bool
	Timeout time.Duration

	mu       sync.Mutex
	recorded []string
}

func New(dryRun bool) *Executor {
	return &Executor{
		DryRun:  dryRun,
		Timeout: 30 * time.Second,
	}
}

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// maxRecorded bounds the recording ring. Gating recording to DryRun was meant
// to stop unbounded growth in production, but dry_run is a persistent key in
// config.yaml, not a test-only flag — a daemon left in dry-run is exactly the
// configuration someone would choose to watch this thing behave, and it would
// then grow ~4 strings every 10s forever on a Raspberry Pi. So the bound has
// to be a real one, not a mode. 256 is far above what any test inspects
// (a handful) and small enough to be irrelevant to RSS.
const maxRecorded = 256

// record keeps the most recent maxRecorded invocations so service tests can
// assert on what was run rather than on a bare nil error.
//
// DryRun ONLY. This Executor is a process-lifetime singleton shared by every
// service (cmd/netfilterd/main.go constructs exactly one), and the real path
// already logs each command to journald via the [EXEC] line, so nothing is
// lost by not recording there.
func (e *Executor) record(cmdStr string) {
	if !e.DryRun {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.recorded = append(e.recorded, cmdStr)
	if len(e.recorded) > maxRecorded {
		// Drop from the FRONT, so what survives is the most recent window and
		// the order stays oldest-to-newest — Recorded()'s existing contract,
		// which several service tests index into positionally. Re-slicing walks
		// the backing array forward until append exhausts its capacity and
		// reallocates, which caps the array at O(maxRecorded) rather than
		// letting it grow with the number of commands ever run.
		e.recorded = e.recorded[len(e.recorded)-maxRecorded:]
	}
}

// Recorded returns a copy of every command this Executor has been asked to run.
func (e *Executor) Recorded() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.recorded...)
}

func (e *Executor) Run(name string, args ...string) (Result, error) {
	cmdStr := name + " " + strings.Join(args, " ")
	e.record(cmdStr)

	if e.DryRun {
		log.Printf("[DRY-RUN] %s", cmdStr)
		return Result{}, nil
	}

	log.Printf("[EXEC] %s", cmdStr)

	ctx, cancel := context.WithTimeout(context.Background(), e.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		return result, fmt.Errorf("exec %s: %w (stderr: %s)", cmdStr, err, stderr.String())
	}

	return result, nil
}

func (e *Executor) RunShell(script string) (Result, error) {
	return e.Run("sh", "-c", script)
}
