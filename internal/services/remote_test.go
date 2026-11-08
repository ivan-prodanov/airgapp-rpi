package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for parseServeStatus — the JSON-shape detector for Tailscale
// Funnel-on-/api/ble. The CLI output here mirrors what `tailscale serve
// status --json` returns on Tailscale 1.50+; if the shape ever
// changes upstream, these tests will catch the regression before the
// /remote-access UI silently stops detecting the Funnel state.

const sampleFunnelOn = `{
  "Web": {
    "pi.tail1234.ts.net:443": {
      "Handlers": {
        "/api/ble": {
          "Proxy": "https+insecure://localhost:8443"
        }
      }
    }
  },
  "AllowFunnel": {
    "pi.tail1234.ts.net:443": true
  }
}`

const sampleServeOnlyNoFunnel = `{
  "Web": {
    "pi.tail1234.ts.net:443": {
      "Handlers": {
        "/api/ble": {
          "Proxy": "https+insecure://localhost:8443"
        }
      }
    }
  },
  "AllowFunnel": {}
}`

const sampleWrongPath = `{
  "Web": {
    "pi.tail1234.ts.net:443": {
      "Handlers": {
        "/something-else": {
          "Proxy": "http://localhost:3000"
        }
      }
    }
  },
  "AllowFunnel": {
    "pi.tail1234.ts.net:443": true
  }
}`

const sampleEmpty = `{}`

func TestParseServeStatus_FunnelOn(t *testing.T) {
	on, url := parseServeStatus([]byte(sampleFunnelOn), "pi.tail1234.ts.net")
	if !on {
		t.Errorf("expected funnel on, got off")
	}
	if want := "https://pi.tail1234.ts.net/api/ble"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
}

func TestParseServeStatus_ServeOnlyIsNotFunnel(t *testing.T) {
	// A serve handler without AllowFunnel=true means tailnet-only, not
	// public. We must report off — the toggle's whole point is public
	// exposure.
	on, url := parseServeStatus([]byte(sampleServeOnlyNoFunnel), "pi.tail1234.ts.net")
	if on {
		t.Errorf("serve-only should not count as funnel")
	}
	if url != "" {
		t.Errorf("url should be empty when off, got %q", url)
	}
}

func TestParseServeStatus_WrongPathIsIgnored(t *testing.T) {
	on, _ := parseServeStatus([]byte(sampleWrongPath), "pi.tail1234.ts.net")
	if on {
		t.Errorf("handler on a different path should not match /api/ble")
	}
}

func TestParseServeStatus_EmptyConfig(t *testing.T) {
	on, _ := parseServeStatus([]byte(sampleEmpty), "pi.tail1234.ts.net")
	if on {
		t.Errorf("empty serve config should be off")
	}
}

func TestParseServeStatus_GarbageJSON(t *testing.T) {
	on, _ := parseServeStatus([]byte("not json"), "pi.tail1234.ts.net")
	if on {
		t.Errorf("garbage JSON should default to off (silent)")
	}
}

// fakeTailscale puts a `tailscale` on PATH that records its arguments.
func fakeTailscale(t *testing.T) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "tailscale"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// Airgapp access (the /api/ble Funnel) is always on: signing in turns it on.
func TestRemoteUp_EnablesFunnel(t *testing.T) {
	logPath := fakeTailscale(t)
	s := NewRemoteService()
	if err := s.Up(context.Background(), "tskey-auth-example"); err != nil {
		t.Fatalf("Up: %v", err)
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "funnel --bg --set-path=/api/ble https+insecure://localhost:8443") {
		t.Fatalf("Up didn't enable the Funnel; calls:\n%s", b)
	}
}

// fakeTailscaleScript puts a `tailscale` on PATH running the given shell body.
func fakeTailscaleScript(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tailscale"), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// With Funnel not enabled for the tailnet, `tailscale funnel` waits for the
// operator indefinitely. Turning it on is bounded, and the reason (with the
// link to enable it) is kept for the System page.
func TestEnableFunnel_BoundedAndReported(t *testing.T) {
	saved := funnelTimeout
	funnelTimeout = 1500 * time.Millisecond // a fresh executable can take a few hundred ms to start (macOS scans it)
	t.Cleanup(func() { funnelTimeout = saved })
	fakeTailscaleScript(t, `case "$1" in funnel) echo "Funnel is not enabled on your tailnet."; echo "To enable, visit:"; echo; echo "         https://login.tailscale.com/f/funnel?node=abc123"; exec sleep 30;; esac
exit 0
`)
	s := NewRemoteService()
	start := time.Now()
	if err := s.EnableBLEFunnel(context.Background()); err == nil {
		t.Fatal("want an error when Funnel can't turn on")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("EnableBLEFunnel took %v: not bounded", d)
	}
	if got := s.FunnelError(); got != "Funnel isn't enabled for this tailnet. Turn it on at https://login.tailscale.com/f/funnel?node=abc123, then retry." {
		t.Fatalf("FunnelError = %q", got)
	}
	// Signing in still succeeds, in bounded time, with the reason kept.
	start = time.Now()
	if err := s.Up(context.Background(), "tskey-auth-example"); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second || s.FunnelError() == "" {
		t.Fatalf("Up took %v, FunnelError %q", d, s.FunnelError())
	}
	// Once it works, the reason clears.
	fakeTailscaleScript(t, "exit 0\n")
	if err := s.EnableBLEFunnel(context.Background()); err != nil || s.FunnelError() != "" {
		t.Fatalf("after success: err %v, FunnelError %q", err, s.FunnelError())
	}
}
