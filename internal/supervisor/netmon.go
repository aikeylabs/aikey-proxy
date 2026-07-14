// netmon.go — Stage 2 of control-plane self-heal: PROACTIVE host-network-change
// detection (dependency-free).
//
// Stage 1 (selfheal.go) recovers AFTER a control-plane call fails. This monitor
// recovers the moment the host's addresses change (WiFi switch, interface up/down,
// USB/phone tether plug) — the exact events that leave a long-lived process's
// direct client stalled with "no route to host". On a change it rebuilds the
// control-plane client so the next poll/writeback already dials clean, instead of
// burning a failure + waiting the 60s poll cadence.
//
// WHY a poll-a-fingerprint approach (not OS route/netlink events): a fingerprint
// of net.Interfaces() is pure Go stdlib and identical on macOS/Linux/Windows, so
// it needs NO cgo and NO third-party dependency. The reference event-driven
// implementation (Tailscale's tailscale.com/net/netmon: PF_ROUTE / netlink /
// NotifyAddrChange) reacts faster and catches pure default-route changes with
// unchanged IPs, but adds a heavy dependency; it's a drop-in upgrade if ever
// needed (swap fingerprint-poll for an event channel — same onChange callback).
package supervisor

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

const netChangePollInterval = 20 * time.Second

// interfaceFingerprint is a cheap, order-stable signature of the host's usable
// network addresses (up, non-loopback, global-unicast). It flips exactly when
// the set of interface IPs changes — the trigger for control-plane staleness.
func interfaceFingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var ips []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() {
				ips = append(ips, ipn.IP.String())
			}
		}
	}
	sort.Strings(ips)
	return strings.Join(ips, ",")
}

// changeDetector holds the last-seen fingerprint. The FIRST observation only
// primes the baseline (no change reported), so a fresh monitor never fires on
// startup. Pulled out of the loop so the flip logic is deterministically testable
// without a ticker/clock.
type changeDetector struct {
	primed bool
	last   string
}

// observe records cur and reports whether it differs from the previously-seen
// value, plus the previous value (for from→to logging). First call primes the
// baseline and returns (false, "").
func (d *changeDetector) observe(cur string) (changed bool, prev string) {
	if !d.primed {
		d.primed, d.last = true, cur
		return false, ""
	}
	if cur != d.last {
		prev, d.last = d.last, cur
		return true, prev
	}
	return false, d.last
}

// watchNetworkChanges polls `fingerprint` every `interval` and invokes onChange
// each time it flips. fingerprint/onChange are injected so tests drive it without
// real interfaces; production passes interfaceFingerprint.
func watchNetworkChanges(ctx context.Context, interval time.Duration, fingerprint func() string, onChange func(old, cur string)) {
	var det changeDetector
	det.observe(fingerprint()) // prime baseline; never fire on start
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := fingerprint()
			if changed, prev := det.observe(cur); changed {
				onChange(prev, cur)
			}
		}
	}
}

// onNetworkChange is the production reaction to a detected host network change:
// rebuild EVERY registered control-plane client (so all rails dial clean, not just
// group-runtime) and reset the self-heal streak (the change is a fresh start).
// Named (not an inline closure) so integration tests drive the REAL callback.
func onNetworkChange(old, cur string) {
	n := httpx.RebuildAllControlPlane()
	controlPlaneHeal.onPollOK()
	slog.Info("host network change detected; rebuilt control-plane clients",
		"event.name", observability.EventProxyControlPlaneNetChange,
		"from", old, "to", cur, "clients_rebuilt", n)
}

// runNetChangeMonitor is the production loop.
func runNetChangeMonitor(ctx context.Context) {
	watchNetworkChanges(ctx, netChangePollInterval, interfaceFingerprint, onNetworkChange)
}
