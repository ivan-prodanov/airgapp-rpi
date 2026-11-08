package services

import (
	"net"
	"testing"
	"time"
)

// An allow-listed connection whose site doesn't answer was logged "blocked", so
// a Tailscale relay that timed out (derp24c, 2,088 times) read as blocked while
// its filter said allowed. It is its own verdict: "unreachable" — the gate let
// it through; the far end never answered.
func TestSNIProxy_UnansweredIsNotBlocked(t *testing.T) {
	db := memDB(t)
	s := &SNIProxyService{
		trafficLog: NewTrafficLogService(db),
		suffixes:   legitAllowed,
		filtered:   map[string]bool{"0C:29:8F:93:2A:08": true},
		leases: func() map[string][]string {
			return map[string][]string{"0C:29:8F:93:2A:08": {"127.0.0.1"}}
		},
		dial: func(network, addr string) (net.Conn, error) { return nil, errStubDialer },
	}
	driveHandle(t, s, clientHello(t, "auth.tesla.com")) // allow-listed; the dial fails
	driveHandle(t, s, clientHello(t, "example.com"))    // not allow-listed
	for domain, want := range map[string]string{"auth.tesla.com": "unreachable", "example.com": "blocked"} {
		var got string
		if err := db.QueryRow(`SELECT action FROM query_log WHERE domain = ?`, domain).Scan(&got); err != nil {
			t.Fatalf("%s: %v", domain, err)
		}
		if got != want {
			t.Errorf("%s logged %q, want %q", domain, got, want)
		}
	}
}

// Where the question is "did the gate let it through", an unanswered connection
// counts as allowed; it is never counted as blocked. In the log it has its own
// chip (All · Allowed · Blocked · No answer), each chip showing only its verdict.
func TestUnreachableCountsAsAllowed(t *testing.T) {
	db := memDB(t)
	tl := NewTrafficLogService(db)
	since := time.Now().Add(-time.Minute)
	tl.LogSNIEvent("192.168.4.50", "a.example.com", true)
	tl.LogSNIEvent("192.168.4.50", "b.example.com", false)
	tl.LogSNIUnreachable("192.168.4.50", "c.example.com")

	if blocked, allowed := tl.ClassCountsSince("", "192.168.4.50", since); blocked != 1 || allowed != 2 {
		t.Errorf("counts: blocked %d allowed %d, want 1 and 2", blocked, allowed)
	}
	hosts, err := tl.RecentHosts("", "192.168.4.50", since, 10)
	if err != nil {
		t.Fatal(err)
	}
	crossed := map[string]bool{}
	for _, h := range hosts {
		crossed[h.Domain] = h.Crossed
	}
	if c, ok := crossed["c.example.com"]; !ok || !c {
		t.Errorf("the unanswered host should cross the gate: %+v", hosts)
	}
	for outcome, want := range map[string]bool{"unreachable": true, "allowed": false, "blocked": false} {
		entries, _, err := tl.Feed(FeedFilter{Outcome: outcome})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range entries {
			found = found || e.Domain == "c.example.com"
		}
		if found != want {
			t.Errorf("the %q chip shows the unanswered row: %v, want %v", outcome, found, want)
		}
	}
}
