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

// record keeps every invocation so service tests can assert on what was run
// rather than on a bare nil error. Always on — the slice is tiny and only ever
// grows within a single test or a single ApplyAll.
func (e *Executor) record(cmdStr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.recorded = append(e.recorded, cmdStr)
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
