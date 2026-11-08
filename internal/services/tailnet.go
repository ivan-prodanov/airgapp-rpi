package services

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"
)

// Tailnet is the Pi's own place on its tailnet, as the hotspot needs it: the
// name Tailscale serves the console and the /api/ble Funnel under (with a real
// certificate), and the 100.x address those listeners are bound to. The zero
// value means Tailscale isn't signed in.
//
// The car isn't on the tailnet, and on the hotspot that name would resolve to
// Tailscale's Funnel servers, which carry only /api/ble. So the Pi answers its
// own name with ConsoleHost's sibling, TailnetAddr, and forwards the served
// ports to these listeners: the car gets the same console, under the same
// name and certificate, as a laptop on the tailnet.
type Tailnet struct {
	Host string
	IPv4 string
}

// Known reports whether there is a tailnet to point the hotspot at.
func (t Tailnet) Known() bool { return t.Host != "" && ValidIPv4(t.IPv4) }

// ConsoleURL is the console as the tailnet serves it.
func (t Tailnet) ConsoleURL() string { return "https://" + t.Host + ":" + adminServePort + "/" }

// tailnetPorts are the ports Tailscale serves under the Pi's name: the /api/ble
// Funnel on 443 (EnableBLEFunnel) and the tailnet-only console on
// adminServePort (EnsureAdminServe).
func tailnetPorts() []int {
	console, _ := strconv.Atoi(adminServePort)
	return []int{443, console}
}

// TailnetFrom reads the Pi's tailnet from Tailscale's status: nothing unless it
// is signed in with a usable name and address.
func TailnetFrom(st RemoteStatus) Tailnet {
	t := Tailnet{Host: strings.ToLower(strings.TrimSpace(st.TailnetHostname)), IPv4: st.TailnetIPv4}
	if !st.Authenticated || !ValidDomain(t.Host) || !t.Known() {
		return Tailnet{}
	}
	return t
}

// tailnetSync applies a change of tailnet once: Tailscale's status is read
// every minute, and the DNS and firewall are only rewritten when it changed.
type tailnetSync struct {
	last  Tailnet
	apply func(Tailnet)
}

func (w *tailnetSync) observe(t Tailnet) {
	if t == w.last {
		return
	}
	w.last = t
	w.apply(t)
}

// WatchTailnet keeps the hotspot pointed at the Pi's tailnet: on boot
// Tailscale may come up after the first DNS and firewall apply, and a sign-in,
// sign-out or new address changes where the Pi's name should lead. A failed
// status read keeps what was applied (tailscaled restarting isn't a sign-out).
func (s *Services) WatchTailnet(ctx context.Context, every time.Duration) {
	w := &tailnetSync{apply: s.applyTailnet}
	for {
		readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		st, err := s.Remote.Status(readCtx)
		cancel()
		if err == nil {
			w.observe(TailnetFrom(st))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func (s *Services) applyTailnet(t Tailnet) {
	if t.Known() {
		log.Printf("[TAILNET] on the hotspot, %s now leads to Tailscale on the Pi (%s)", t.Host, t.IPv4)
	} else {
		log.Printf("[TAILNET] Tailscale is signed out: %s leads to the Pi's own console", s.cfg.ConsoleHost)
	}
	s.Spoof.SetTailnet(t)
	s.DNS.SetTailnet(t)
	s.Firewall.SetTailnet(t)
	s.TrafficLog.SetLocalNames(localNames(s.cfg.EnrolHost, s.cfg.ConsoleHost, t.Host))
	if err := s.Firewall.Apply(); err != nil {
		log.Printf("[TAILNET] firewall apply failed: %v", err)
	}
	if err := s.DNS.Apply(); err != nil {
		log.Printf("[TAILNET] DNS apply failed: %v", err)
	}
}

// localNames are the names the Pi answers itself on the hotspot, so the traffic
// log shows them as resolved rather than blocked.
func localNames(names ...string) []string {
	var out []string
	for _, n := range names {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}
