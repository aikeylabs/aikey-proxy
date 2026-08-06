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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
)

// Winsock error codes for the routing-layer failures a host network change
// produces on Windows. These are NOT reachable through the stdlib's
// syscall.EHOSTUNREACH / ENETUNREACH / ENETDOWN: on Windows those three are
// SYNTHETIC constants (syscall/zerrors_windows.go defines them as
// APPLICATION_ERROR offsets so that portable Go code still compiles), and the
// Windows socket stack never returns them. A real failed connect() surfaces as
// syscall.Errno holding the raw WSA value below, which equals none of them —
// which is exactly why the pre-2026-08-04 classifier could not fire on Windows
// at all (see the doc on isNetChangeDialErr).
//
// Declared here as plain numbers rather than pulling in
// golang.org/x/sys/windows: these are frozen Winsock ABI values documented by
// Microsoft (WSAENETDOWN/WSAENETUNREACH/WSAEHOSTUNREACH), and a whole extra
// dependency for three integers is a worse trade than a comment that names
// them.
const (
	wsaeNetDown     = syscall.Errno(10050) // WSAENETDOWN
	wsaeNetUnreach  = syscall.Errno(10051) // WSAENETUNREACH
	wsaeHostUnreach = syscall.Errno(10065) // WSAEHOSTUNREACH
)

// isNetChangeErrnoFor reports whether err carries a routing-layer errno for the
// given GOOS. Split out (and parameterised on goos rather than reading
// runtime.GOOS directly) so the Windows branch is exercisable from a test on
// any host — the Windows-only bug this function exists to fix was invisible
// precisely because nothing could test the Windows path off Windows.
func isNetChangeErrnoFor(goos string, err error) bool {
	// Unix errno's. On Windows these are the synthetic constants described
	// above; keeping the check unconditional is harmless (nothing produces
	// them there) and keeps the Unix path byte-for-byte what it was.
	if errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) {
		return true
	}
	if goos != "windows" {
		return false
	}
	// Windows: compare the raw WSA value. Guarded by goos because these
	// numbers mean unrelated things in the Unix errno space.
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case wsaeNetDown, wsaeNetUnreach, wsaeHostUnreach:
			return true
		}
	}
	return false
}

// isNetChangeDialErr reports whether err is a routing-layer dial failure of the
// kind a host network change produces — "no route to host" (EHOSTUNREACH /
// WSAEHOSTUNREACH), "network is unreachable" (ENETUNREACH / WSAENETUNREACH), or
// "network is down" (ENETDOWN / WSAENETDOWN). These are the errno's the kernel
// returns when a long-running process's routing/source state has gone stale
// relative to the current interfaces.
//
// WHY errno-first, string-second (corrected 2026-08-04): the previous version
// claimed the error-string tails Go formats these into were "identical across
// platforms". They are not. Windows renders them via FormatMessage as "A socket
// operation was attempted to an unreachable host/network" and "A socket
// operation encountered a dead network" — matching none of the Unix tails — and
// errors.Is against the stdlib constants fails there too (see the WSA block
// above). The net effect was that Tier1 client-rebuild and Tier3 self-restart
// were unreachable on Windows, the platform most of the field reports come
// from. Both halves are now platform-aware.
//
// The errno comparison is the load-bearing one; the string fallback is a
// best-effort backstop only. It cannot be relied on for Windows in particular,
// because FormatMessage returns LOCALIZED text — a Chinese or German Windows
// yields a message none of these substrings match. Anything that must work
// off-English has to come from the numeric path.
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
	if isNetChangeErrnoFor(runtime.GOOS, err) {
		return true
	}
	s := strings.ToLower(err.Error())
	return containsAny(s,
		// Unix / Go-formatted tails.
		"no route to host",
		"network is unreachable",
		"host is unreachable",
		"network is down",
		// Windows FormatMessage texts (English only — see the doc above).
		// Matched on their distinctive tails so the leading "A socket
		// operation..." boilerplate can't drift the match.
		"unreachable host",
		"unreachable network",
		"dead network",
	)
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
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

	// supervised: does exiting non-zero actually get us relaunched here?
	// False on Windows — see selfRestartIsSupervised. Injected (not read
	// from runtime.GOOS inline) so both answers are testable on any host.
	supervised bool
}

func newControlPlaneHealer() *controlPlaneHealer {
	return &controlPlaneHealer{
		threshold:  3, // ~3 poll cycles (~3 min) stuck before we consider a restart
		cooldown:   2 * time.Minute,
		window:     30 * time.Minute,
		budget:     4,
		supervised: selfRestartIsSupervised(runtime.GOOS),
		now:        time.Now,
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

// selfRestartIsSupervised reports whether exiting non-zero will actually get
// this process relaunched on the given GOOS.
//
// Tier3's entire premise is "exit and let the service manager bring us back":
// launchd `KeepAlive{SuccessfulExit:false}` and systemd `Restart=on-failure`
// both do exactly that. **Windows has no equivalent in our install.** The proxy
// is normally spawned detached by `aikey proxy start`, which exits immediately
// and supervises nothing; the installer's `AikeyProxy` ScheduledTask relaunches
// at most 3 times and, in its own words, "with RestartCount exhausted it stays
// dead". So on Windows an exit(75) is not a restart — it is an outage.
//
// This mattered the moment isNetChangeDialErr was fixed (2026-08-04). While the
// classifier could never fire on Windows, Tier3 was unreachable there and the
// missing supervisor was harmless. Making the classifier work would otherwise
// have ARMED a suicide path on the one platform that cannot recover from it —
// trading a self-healer that did nothing for one that ends the session. Tier1
// (rebuild the client in-process) is the part that actually clears the stale
// transport in the reference design, and it still runs everywhere.
func selfRestartIsSupervised(goos string) bool { return goos != "windows" }

// onPollNetChange handles a routing-layer poll failure: it always rebuilds the
// shared client (Tier1), and once we've failed `threshold` consecutive poll
// cycles it escalates — but ONLY if a FRESH client can reach master (proving the
// staleness is ours, not a real outage), the platform actually relaunches an
// exited process, AND the cooldown/budget allow — by exiting non-zero so the
// service manager relaunches a clean process (Tier3).
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
	// Tier3 gate: would exiting actually bring us back? On an unsupervised
	// platform it would not, so we stop at Tier1 and let the caller say so.
	if !h.supervised {
		return restartSkipUnsupervised
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
	// restartSkipUnsupervised: this platform does not relaunch an exited
	// process, so exiting would be an outage rather than a heal. Tier1 has
	// already run; the caller should log that manual intervention may be
	// needed instead of pretending a restart happened.
	restartSkipUnsupervised
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
