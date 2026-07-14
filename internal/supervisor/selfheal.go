// selfheal.go — control-plane self-healing after a host NETWORK CHANGE.
//
// PROBLEM (2026-07-01, field-diagnosed): the aikey-proxy is a long-running
// daemon. When the host network changes UNDER a running proxy — a WiFi switch,
// an interface IP change, or a VPN/proxy (e.g. Clash TUN) starting up AFTER the
// proxy — the proxy's outbound control-plane calls to the LAN team-master can get
// stuck failing with "no route to host" / EHOSTUNREACH, and STAY stuck until the
// PROCESS is restarted. A freshly-launched process (curl) reaches the same master
// fine, which proves the stale state is process-scoped, not a real outage.
//
// INDUSTRY-ALIGNED FIX (deep-research 2026-07-01): production network daemons
// (Tailscale's link monitor + socket rebind is the reference) recover by
// (1) REBUILDING their client/transport on a network change, and (2) keeping a
// service-manager RESTART as a guarded backstop. Crucially, Go's
// Transport.CloseIdleConnections() alone does NOT reliably clear the stale state
// (golang/go#23427), so we rebuild a FRESH *http.Client (new dialer + empty pool)
// rather than just closing idle conns.
//
// This file implements the failure-triggered tier (Stage 1): on a routing-layer
// error to master we (Tier1) swap in a fresh control-plane client, and if that
// still doesn't clear it AND a fresh out-of-process probe proves master is
// actually reachable (i.e. WE are the stale one, not the network), we (Tier3)
// exit non-zero so launchd/systemd relaunches a clean process — guarded by a
// cooldown + a circuit breaker so a genuine outage can't cause a restart storm.
//
// MAIN-LINK SAFETY: this is control-plane only. It never touches the request
// forwarding path, and Tier3 only fires when master is confirmed reachable, so a
// real upstream/GFW outage (which the env proxy egress handles) can't trip it.
package supervisor

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
)

// isNetChangeDialErr reports whether err is a routing-layer dial failure of the
// kind a host network change produces — "no route to host" (EHOSTUNREACH),
// "network is unreachable" (ENETUNREACH), or "network is down" (ENETDOWN). These
// are the errno's the kernel returns when a long-running process's routing/source
// state has gone stale relative to the current interfaces.
//
// WHY string-match as well as errors.Is: syscall errno constants are defined
// per-GOOS (Windows uses WSAE* values), so a portable classifier can't rely on
// errors.Is(err, syscall.EHOSTUNREACH) alone on every platform. We check the
// unix errno's where they exist (cheap, exact) AND fall back to the stable
// error-string tails Go formats them into, which are identical across platforms.
func isNetChangeDialErr(err error) bool {
	if err == nil {
		return false
	}
	// Only dial-time failures qualify — a mid-stream reset is a different animal
	// (a fresh client wouldn't necessarily help there). net.OpError{Op:"dial"}
	// wraps the syscall error for connect() failures.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op != "dial" {
		return false
	}
	if errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no route to host") ||
		strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "host is unreachable") ||
		strings.Contains(s, "network is down")
}

// controlPlaneHealer holds the cooldown + circuit-breaker state that decides
// whether a persistent no-route condition should escalate to a process restart.
// It is intentionally tiny and pure (no I/O): callers feed it "we just hit a
// net-change error and a fresh probe says master IS reachable" and it answers
// whether to restart now, applying:
//
//   - cooldown: at most one restart per restartCooldown (a fresh process needs
//     time to re-establish; back-to-back restarts help nothing).
//   - circuit breaker: at most restartBudget restarts per breakerWindow; once
//     tripped it stops restarting and the caller logs loudly, so a mis-detection
//     or a genuinely broken host can't spin the process forever
//     (systemd StartLimitBurst analogue; Azure retry-storm antipattern).
//
// `now` and `exit` are injected so the decision + effect are unit-testable
// without a clock or an actual os.Exit.
type controlPlaneHealer struct {
	mu          sync.Mutex
	restarts    []time.Time // timestamps of restarts inside the current window
	last        time.Time   // last restart (for cooldown)
	consecutive int         // consecutive poll cycles failing with a net-change error

	// tunables (vars-in-struct so tests can shrink them)
	threshold int // escalate to a restart only after this many consecutive failures
	cooldown  time.Duration
	window    time.Duration
	budget    int

	now   func() time.Time
	exit  func(code int)
	probe func(masterURL string) bool // "is master reachable from a FRESH client?"
}

func newControlPlaneHealer() *controlPlaneHealer {
	return &controlPlaneHealer{
		threshold: 3, // ~3 poll cycles (~3 min) stuck before we consider a restart
		cooldown:  2 * time.Minute,
		window:    30 * time.Minute,
		budget:    4,
		now:       time.Now,
		// Production: request a GRACEFUL restart — main() runs the same
		// srv.Shutdown + sup.Shutdown drain path as SIGTERM, then exits non-zero
		// so launchd KeepAlive{SuccessfulExit:false} / systemd Restart=on-failure
		// relaunch a clean process. In-flight forwarded requests drain first
		// (up to the 30s/streaming timeout) instead of being cut. The `code` arg
		// is ignored here (main owns the non-zero exit); tests inject their own
		// exit to assert the decision without draining.
		exit:  func(int) { requestGracefulRestart() },
		probe: func(masterURL string) bool { return masterReachableFresh(defaultGroupRuntimeClient(), masterURL) },
	}
}

// restartRequestCh carries a graceful-self-restart request from the control-plane
// healer to main(). Buffered + non-blocking send so repeated requests (a stuck
// streak firing every poll) coalesce into one; the cooldown in shouldRestart also
// prevents re-signalling within the window.
var restartRequestCh = make(chan struct{}, 1)

// RestartRequested is selected by main() alongside the OS signal channel: it runs
// the SAME graceful drain as SIGTERM, then exits non-zero to trigger a relaunch.
func (s *Supervisor) RestartRequested() <-chan struct{} { return restartRequestCh }

// requestGracefulRestart asks main() to drain + relaunch. Idempotent.
func requestGracefulRestart() {
	select {
	case restartRequestCh <- struct{}{}:
	default:
	}
}

// controlPlaneHeal is the process-wide healer driven by the group-runtime poll
// (the steady 60s heartbeat). The writeback path only does the cheap Tier-1
// client rebuild; escalation to a restart is owned here so a 6-try writeback
// burst can't inflate the counter.
var controlPlaneHeal = newControlPlaneHealer()

// onPollOK resets the consecutive-failure counter after any successful poll.
func (h *controlPlaneHealer) onPollOK() {
	h.mu.Lock()
	h.consecutive = 0
	h.mu.Unlock()
}

// onPollNetChange handles a routing-layer poll failure: it always rebuilds the
// shared client (Tier1), and once we've failed `threshold` consecutive poll
// cycles it escalates — but ONLY if a FRESH client can reach master (proving the
// staleness is ours, not a real outage) AND the cooldown/budget allow — by
// exiting non-zero so the service manager relaunches a clean process (Tier3).
// Returns the decision (for logging + tests); callers log with their vocabulary.
func (h *controlPlaneHealer) onPollNetChange(masterURL string) restartDecision {
	httpx.RebuildAllControlPlane() // Tier1: always cheap + safe
	h.mu.Lock()
	h.consecutive++
	n := h.consecutive
	h.mu.Unlock()
	if n < h.threshold {
		return restartSkipCooldown // not escalating yet (reuse enum: "not now")
	}
	// Tier3 gate: is it US (stale) or the network (real outage)? A fresh client
	// reaching master means we're the stale one → a restart will clear it.
	if !h.probe(masterURL) {
		return restartSkipCooldown // genuine outage — never restart into a dead net
	}
	d := h.shouldRestart()
	if d == restartNow {
		h.exitNow()
	}
	return d
}

// restartDecision is the outcome of asking the healer to escalate. It's returned
// (instead of restarting inline) so the caller can log the reason with its own
// event vocabulary before the process goes down.
type restartDecision int

const (
	restartSkipCooldown restartDecision = iota // too soon since the last restart
	restartSkipBreaker                         // budget exhausted — stop restarting, log loudly
	restartNow                                 // clear to restart
)

// shouldRestart records the intent and returns whether a restart is warranted
// right now. The caller must have already confirmed (out-of-process) that master
// is reachable — this method only enforces the rate limits. On restartNow it
// stamps the clock (so the cooldown starts) but does NOT exit; call exitNow to
// actually go down, keeping "decide" and "act" separable for logging + tests.
func (h *controlPlaneHealer) shouldRestart() restartDecision {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.now()
	if !h.last.IsZero() && t.Sub(h.last) < h.cooldown {
		return restartSkipCooldown
	}
	// prune restarts older than the window, then check the budget
	cut := t.Add(-h.window)
	kept := h.restarts[:0]
	for _, r := range h.restarts {
		if r.After(cut) {
			kept = append(kept, r)
		}
	}
	h.restarts = kept
	if len(h.restarts) >= h.budget {
		return restartSkipBreaker
	}
	h.restarts = append(h.restarts, t)
	h.last = t
	return restartNow
}

// exitNow performs the actual restart (via the injected exit). Split from
// shouldRestart so the caller can log first and tests can assert the code.
func (h *controlPlaneHealer) exitNow() { h.exit(75) } // EX_TEMPFAIL

// masterReachableFresh probes masterURL from a BRAND-NEW *http.Client (fresh
// transport + dialer + empty pool). It is the "is it US or the network?" check:
// if this fresh client reaches master while the long-lived control-plane client
// keeps getting no-route, the staleness is ours and a restart will clear it; if
// this ALSO fails, it's a real outage and we must NOT restart.
//
// NOTE (honest): a fresh client in the SAME process is a weaker signal than a
// fresh PROCESS — if the staleness turns out to be process-global rather than
// transport-local, this probe could also succeed-or-fail with the live client.
// It is still the best in-process discriminator available and errs safe: any
// probe error (including net-change errors) returns false → we do NOT restart.
func masterReachableFresh(client *http.Client, masterURL string) bool {
	req, err := http.NewRequest(http.MethodHead, strings.TrimRight(masterURL, "/")+"/", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	// Any HTTP response (even 404/405) proves the TCP+routing path is alive.
	return true
}
