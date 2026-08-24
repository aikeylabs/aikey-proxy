// railset.go — the SyncRail framework: ONE declarative driver for every
// control-plane sync rail (master-poll loop) in the proxy.
//
// WHY (2026-07-03 incident, bugfix 2026-07-03-routing-override-rail-silent-stall.md):
// the proxy grew six hand-written "pull from master" loops whose behaviors
// drifted apart — the routing-override and group-runtime polls built their
// team credential ONCE at goroutine start (baking a possibly-stale control URL
// into the refresh path) and early-returned FOREVER on any startup precondition
// miss, all silently. A server IP drift then starved both rails for 7+ hours
// with zero logs while the resolver kept demanding login for an account the
// engine had routed the seat away from.
//
// The framework inverts every "evaluate once at start" into "evaluate every
// cycle" and centralizes the failure-visibility rules so a rail cannot opt out:
//   - gate / generation / credential / control URL: re-checked each cycle
//   - failure: counted per rail; OK → STALE (3) → OFFLINE (20) transitions log
//     with the underlying error; recovery logs the outage duration
//   - state affects VISIBILITY ONLY (/status, statusline): the data path keeps
//     serving last-known caches and retries never stop (offline-first, owner
//     decision 2026-07-03 — OFFLINE is a label, not a terminal state)
//
// Design doc: update/20260703-控制面同步框架SyncRail-技术方案.md.
// Phase 1 rails: routing_override, group_runtime. quota/compliance/audit stay
// on their legacy loops until Phase 2 (scope fidelity — do not migrate here).
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// State thresholds (§2.3): consecutive failures before the rail is announced
// STALE (first WARN) and OFFLINE (ERROR + /status red). Centralized so every
// rail escalates identically; tune here, not per rail.
const (
	railStaleAfterFailures   = 3
	railOfflineAfterFailures = 20
	// railReWarnEveryFailures re-emits the offline WARN once an hour (60 × 60s
	// cycles) so a long outage stays visible in logs without per-cycle spam.
	railReWarnEveryFailures = 60
)

// cliTokenRefreshPath is the control-service token-refresh endpoint, appended
// to the CURRENT control URL when (re)building the team credential. Deriving it
// here — instead of trusting the refresh_url baked into aikey-proxy.yaml at
// process start — is the core incident fix: the yaml value goes stale when the
// server address changes while the proxy is running.
const cliTokenRefreshPath = "/v1/auth/cli/token/refresh"

// railState is the §2.3 visibility state machine. It never gates serving.
type railState int32

const (
	railInit railState = iota
	railOK
	railStale
	railOffline
	// railNeedsReauth is a REFUSED state: the control plane did not fail, it
	// said no. Retrying every cycle cannot change that answer, so the rail backs
	// off to an hourly re-probe.
	//
	// 🔴 The name is now WIDER than "re-auth" and deliberately not renamed yet:
	// it is already a wire value in /status (control_plane_sync.<rail>.state),
	// so renaming is a contract change. Read it as "refused", not as "the user
	// must log in" — on the route where this actually fires today, logging in
	// changes nothing (control-master router.go:869 registers
	// GET /v1/fallback-policy with no auth middleware while the handler reads
	// JWT claims, so the refusal is constant and credential-independent).
	//
	// 🔴 WHY THIS STATE EXISTS (2026-08-22). Live finding on a developer
	// machine: GET <control>/v1/fallback-policy answered
	// 403 {"error":"BIZ_AUTH_TOKEN_REVOKED"} and this rail retried it every
	// cycle for FORTY-EIGHT DAYS — 180 consecutive failures at the moment it
	// was noticed. (⚠️ 2026-08-22 correction: the 466 MB log on that machine was NOT this rail. observe() rate-limits to one line per 60 failures, which cannot reach that size; the bulk was a per-second "authentication failed: missing virtual key" from a leaked test proxy. The rail's defect — retrying a deterministic refusal forever — is real and unchanged; only the log-size attribution was wrong.)
	// The
	// machine kept serving traffic the whole time (rails never gate serving,
	// by design and correctly), so nothing else showed a symptom.
	//
	// The bug was treating a DETERMINISTIC REFUSAL as a transient outage. The
	// existing states all mean "the control plane is unreachable-ish, keep
	// trying"; there was no way to say "it answered, and the answer is no".
	railNeedsReauth
)

func (s railState) String() string {
	switch s {
	case railOK:
		return "ok"
	case railStale:
		return "stale"
	case railOffline:
		return "offline"
	case railNeedsReauth:
		return "needs_reauth"
	default:
		return "init"
	}
}

// railSpec declares one control-plane sync rail (§3.1). Everything else —
// ticker, credential, state machine, logging, /status — is the framework's.
type railSpec struct {
	// name keys the /status entry and the goroutine label. Keep the historical
	// poll names (e.g. "routing_override") so dashboards/log filters carry over.
	name     string
	interval time.Duration
	// needsTeamJWT: true → the framework resolves a Bearer via the shared
	// teamCredentialSource each cycle and skips the cycle (counted as failure,
	// visible) when auth fails. false → sync receives bearer "".
	needsTeamJWT bool
	// gate: local preconditions (feature flag, "this vault has group VKs", …),
	// re-evaluated EVERY cycle. false → the cycle is skipped WITHOUT touching
	// the failure counter (a personal install without group VKs is idle, not
	// broken). The generation is the CURRENT one (re-loaded each cycle).
	gate func(gen *generation) bool
	// hydrate, when non-nil, runs once before the first cycle to preload the
	// rail's last-known persisted state (survives restarts, §5.3). Best-effort.
	hydrate func(gen *generation)
	// sync performs one pull+apply. A nil error is a success (state → OK) —
	// including "fetched, nothing changed". Any error is counted and surfaces
	// in transition logs and /status last_error.
	sync func(ctx context.Context, gen *generation, masterURL, bearer string) error
}

// RailSyncStatus is one rail's /status snapshot entry (§3.3). Exported so the
// cmd layer can hand it to the admin handler (same wiring shape as
// PoolCooldownSnapshot → PoolRoutingHealth).
type RailSyncStatus struct {
	State               string `json:"state"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastSuccessAt       int64  `json:"last_success_at,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	// Attempted distinguishes "never had anything to do" (gate always false —
	// omitted from /status) from "tried and is in trouble".
	Attempted bool `json:"-"`
}

// railRunner is the per-rail runtime: counters + state, guarded by mu (written
// only by the rail's own goroutine; read by the /status snapshot).
type railRunner struct {
	spec railSpec

	// terminalSkips counts cycles skipped since the last re-probe of a refused
	// rail. See terminalReprobeEveryCycles for why a refusal is not final.
	terminalSkips int

	mu            sync.Mutex
	state         railState
	failures      int
	lastSuccessAt int64
	lastError     string
	attempted     bool
	failedSince   int64 // unix of the first failure in the current streak (recovery log)

	// nil = fire-and-forget; non-nil receives the outcome of the specifically
	// requested cycle. A buffered result channel lets the rail finish even when
	// the waiting HTTP request has already timed out.
	kick chan chan railCycleResult
}

type railCycleResult struct {
	attempted bool
	err       error
}

// railSet drives all declared rails. One goroutine per rail (GoSafe/Isolated —
// a panic in one rail never touches the data path or sibling rails).
type railSet struct {
	rails []*railRunner
}

func newRailSet(specs ...railSpec) *railSet {
	rs := &railSet{}
	for _, sp := range specs {
		rs.rails = append(rs.rails, &railRunner{spec: sp, kick: make(chan chan railCycleResult, 1)})
	}
	return rs
}

// start launches every rail loop. Called once from supervisor.New.
func (rs *railSet) start(s *Supervisor) {
	for _, r := range rs.rails {
		runner := r
		observability.GoSafe("supervisor."+runner.spec.name+"_poll", observability.Isolated, func() {
			runner.loop(s)
		})
	}
}

// kickAll nudges every rail to run a cycle NOW (non-blocking; a rail already
// mid-cycle coalesces the nudge via the buffered channel). Used by Reload so a
// control-URL change converges in seconds instead of one poll interval.
func (rs *railSet) kickAll() {
	for _, r := range rs.rails {
		select {
		case r.kick <- nil:
		default:
		}
	}
}

// kickAndWait schedules one named rail and waits for that cycle to complete.
// A caller-supplied timeout keeps the user path bounded; the background rail
// continues retrying normally after a timeout or failed cycle.
func (rs *railSet) kickAndWait(ctx context.Context, name string) error {
	for _, r := range rs.rails {
		if r.spec.name != name {
			continue
		}
		done := make(chan railCycleResult, 1)
		select {
		case r.kick <- done:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case result := <-done:
			if !result.attempted {
				return errors.New("sync rail did not run because its local readiness gate was not satisfied: " + name)
			}
			return result.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return errors.New("sync rail not found: " + name)
}

// snapshot returns the /status view. Rails that never had anything to do
// (gate never passed) are omitted so personal installs don't render noise.
func (rs *railSet) snapshot() map[string]RailSyncStatus {
	out := make(map[string]RailSyncStatus, len(rs.rails))
	for _, r := range rs.rails {
		r.mu.Lock()
		if r.attempted {
			out[r.spec.name] = RailSyncStatus{
				State:               r.state.String(),
				ConsecutiveFailures: r.failures,
				LastSuccessAt:       r.lastSuccessAt,
				LastError:           r.lastError,
				Attempted:           true,
			}
		}
		r.mu.Unlock()
	}
	return out
}

// railHealthFor returns one rail's (state, failingSeconds) — the resolver's
// truthful-wording input (§5.4): a stale/offline routing rail means the local
// pick may contradict the engine, so the 401 must not blindly demand a login.
// Unknown rail / unwired railset → ("init", 0), treated as healthy.
func (s *Supervisor) railHealthFor(name string) (string, int64) {
	if s.railset == nil {
		return railInit.String(), 0
	}
	for _, r := range s.railset.rails {
		if r.spec.name != name {
			continue
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		secs := int64(0)
		if r.failedSince > 0 {
			secs = time.Now().Unix() - r.failedSince
		}
		return r.state.String(), secs
	}
	return railInit.String(), 0
}

// ControlPlaneSyncSnapshot returns each attempted rail's visibility state for
// the admin /status surface (§3.3) and the statusline sync-health file. Rails
// that never had anything to do (gate never passed) are omitted so personal
// installs render no noise. nil-safe on a not-yet-wired railset.
func (s *Supervisor) ControlPlaneSyncSnapshot() map[string]RailSyncStatus {
	if s.railset == nil {
		return nil
	}
	return s.railset.snapshot()
}

// loop is the rail's lifetime: hydrate once, then cycle on ticker/kick until
// the supervisor context ends. Every cycle re-derives gen/gate/URL/credential —
// nothing is baked at start (the incident's root cause).
func (r *railRunner) loop(s *Supervisor) {
	if r.spec.hydrate != nil {
		if gen := s.active.Load(); gen != nil && gen.vault != nil {
			r.spec.hydrate(gen)
		}
	}
	r.cycle(s)
	ticker := time.NewTicker(r.spec.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			r.cycle(s)
		case done := <-r.kick:
			result := r.cycle(s)
			if done != nil {
				done <- result
				close(done)
			}
		}
	}
}

var (
	errRailNoGeneration = errors.New("no active generation/vault yet")
	errRailNoControlURL = errors.New("control panel URL not configured")
)

// errRailCredentialRevoked marks a sync failure the control plane will give the
// SAME answer to forever. Rails wrap their terminal refusals in it (see
// syncFallbackPolicy); everything else stays retryable.
//
// 🔴 Only genuinely terminal conditions belong here. A 401 is NOT one — a
// bearer can expire and be refreshed on the next cycle, which is exactly what
// teamCred does. A 5xx is not one either. Revocation is, because it is a
// decision the control plane recorded, not a state it is recovering from.
var errRailCredentialRevoked = errors.New("team credential revoked by the control plane")

// terminalReprobeEveryCycles re-asks a refused rail about once an hour (60 × the
// 60s cycle). Not "never again", and the difference is the whole point.
//
// 🔴 WHY IT MUST RE-PROBE (2026-08-22, found while writing the E2E for this very
// fix). The control plane's 403 does NOT mean what its error code says.
// handler_fallback_policy.go:155 answers BIZ_AUTH_TOKEN_REVOKED for EVERY org
// resolution failure — no credential, bad credential, expired credential, and
// `err != nil`, which includes a transient database error. So a one-second
// blip is indistinguishable, on the wire, from a permanent revocation.
//
// Stopping forever on that signal would convert a blip into a rail that never
// recovers until someone re-logs in — and re-logging in does not fix a database
// blip. Re-probing hourly keeps the log quiet (the harm being bounded: repeated
// identical lines) while letting a wrongly-classified failure heal itself.
//
// Revisit when the control plane can distinguish the four cases; then, and only
// then, a true terminal state may stop for good.
const terminalReprobeEveryCycles = 60

// isTerminal reports whether this rail is in its refused state AND is not due
// for its periodic re-probe.
func (r *railRunner) isTerminal() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != railNeedsReauth {
		return false
	}
	r.terminalSkips++
	if r.terminalSkips >= terminalReprobeEveryCycles {
		r.terminalSkips = 0
		return false // let this cycle through: the refusal may have been transient
	}
	return true
}

func (r *railRunner) cycle(s *Supervisor) railCycleResult {
	// 🔴 STOP POLLING once refused. Before this check the rail re-asked a
	// question it already had a permanent answer to, once per cycle, forever
	// (48 days of identical log lines on the machine where this was
	// found). Recovery is `aikey login`, which mints a fresh credential and
	// reloads the supervisor — rebuilding these runners, so this state does not
	// need its own reset path.
	if r.isTerminal() {
		return railCycleResult{}
	}
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		// Local not-ready (mid-reload window / early start): neither success nor
		// failure — the master isn't being blamed for a local swap.
		return railCycleResult{}
	}
	if r.spec.gate != nil && !r.spec.gate(gen) {
		return railCycleResult{} // idle by design (feature off / nothing local to sync) — not a failure
	}
	masterURL := readControlPanelURL()
	if masterURL == "" {
		// A team rail with local work but no control URL is a real broken state
		// (e.g. config wiped) — count it so it surfaces, don't silently idle.
		r.finish(s, errRailNoControlURL)
		return railCycleResult{attempted: true, err: errRailNoControlURL}
	}
	bearer := ""
	if r.spec.needsTeamJWT {
		b, err := s.teamCred.bearer(s.ctx, gen.vault, masterURL)
		if err != nil {
			r.finish(s, err)
			return railCycleResult{attempted: true, err: err}
		}
		bearer = b
	}
	err := r.spec.sync(s.ctx, gen, masterURL, bearer)
	r.finish(s, err)
	return railCycleResult{attempted: true, err: err}
}

// finish records the cycle outcome and, on a state TRANSITION, refreshes the
// statusline sync-health bypass file (§5.5) — written outside the rail mutex
// (writeSyncHealth snapshots every rail).
func (r *railRunner) finish(s *Supervisor, err error) {
	if r.observe(err) && s.railset != nil {
		s.railset.writeSyncHealth()
	}
}

// observe feeds one cycle outcome into the state machine and emits the
// transition logs (§2.3). Mandatory-WARN rule: every fallback-to-last-known
// path lands here — a rail can no longer fail silently. Returns true when the
// visibility STATE changed (the caller then refreshes the sync-health file).
func (r *railRunner) observe(err error) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempted = true
	now := time.Now().Unix()
	if err == nil {
		prev := r.state
		outageSecs := int64(0)
		if r.failedSince > 0 {
			outageSecs = now - r.failedSince
		}
		r.state, r.failures, r.lastError, r.failedSince = railOK, 0, "", 0
		r.terminalSkips = 0
		r.lastSuccessAt = now
		if prev == railStale || prev == railOffline {
			slog.Info("control-plane sync rail recovered",
				"event.name", observability.EventProxySyncRailRecovered,
				"rail", r.spec.name, "outage_seconds", outageSecs)
		}
		return prev != railOK
	}
	r.failures++
	r.lastError = err.Error()
	if r.failedSince == 0 {
		r.failedSince = now
	}
	if errors.Is(err, errRailCredentialRevoked) {
		// ERROR, not WARN, and said ONCE: a terminal refusal is not a blip that
		// deserves an hourly reminder — it is a thing an operator must act on.
		// The state is what carries it from here on (/status → CLI → panel).
		if r.state != railNeedsReauth {
			r.state = railNeedsReauth
			// 🔴 DO NOT tell the operator to run `aikey login` here (2026-08-22).
			// The control plane's BIZ_AUTH_TOKEN_REVOKED does not mean what it
			// says on this route: GET /v1/fallback-policy is registered with NO
			// auth middleware (control-master router.go:869) while its handler
			// resolves the org from JWT claims, so the claims are always empty
			// and the refusal is CONSTANT — verified live, a forged bearer gets
			// the identical 403. Re-logging in cannot fix a handler that never
			// reads the credential; that advice would send every affected
			// operator down a dead end. State the observation, not a remedy we
			// cannot stand behind.
			slog.Error("control-plane sync rail stopped — the control plane refused this machine and will keep refusing; serving built-in defaults. Check the control plane's logs for this route before changing anything locally",
				"event.name", observability.EventProxySyncRailOffline,
				"rail", r.spec.name, "consecutive_failures", r.failures, "error", r.lastError)
			return true
		}
		return false
	}
	switch {
	case r.failures == railStaleAfterFailures:
		r.state = railStale
		slog.Warn("control-plane sync rail is stale — serving last-known data, retrying every cycle",
			"event.name", observability.EventProxySyncRailStale,
			"rail", r.spec.name, "consecutive_failures", r.failures, "error", r.lastError)
		return true
	case r.failures == railOfflineAfterFailures:
		r.state = railOffline
		slog.Error("control-plane sync rail is offline — serving last-known data, retrying every cycle (will not give up)",
			"event.name", observability.EventProxySyncRailOffline,
			"rail", r.spec.name, "consecutive_failures", r.failures, "error", r.lastError)
		return true
	case r.state == railOffline && r.failures%railReWarnEveryFailures == 0:
		slog.Warn("control-plane sync rail still offline",
			"event.name", observability.EventProxySyncRailOffline,
			"rail", r.spec.name, "consecutive_failures", r.failures, "error", r.lastError)
	}
	return false
}

// ── statusline sync-health bypass file (§5.5) ───────────────────────────────

// syncHealthFilename is the statusline's zero-RPC view of degraded rails —
// same ownership pattern as the group-login state file (one concern, one file,
// one writer; the writer here is the SUPERVISOR's rail framework, transitions
// only, so the hot path never touches it). Cross-repo contract with
// aikey-cli commands_statusline.rs — change shapes together.
const syncHealthFilename = "sync-health.json"

type syncHealthRail struct {
	State string `json:"state"`
	// FailedSince (unix seconds) lets the reader render a LIVE outage duration
	// without the writer re-writing the file every cycle.
	FailedSince int64 `json:"failed_since"`
}

type syncHealthBody struct {
	Rails     map[string]syncHealthRail `json:"rails"`
	WrittenAt int64                     `json:"written_at"` // unix millis
}

func syncHealthPath() (string, error) {
	if dir := os.Getenv("AIKEY_RUN_DIR"); dir != "" {
		return filepath.Join(dir, syncHealthFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aikey", "run", syncHealthFilename), nil
}

// writeSyncHealth snapshots the degraded rails into the bypass file, or removes
// the file when every rail is healthy (statusline recovery is automatic).
// Called on state TRANSITIONS only (never per-cycle) and outside rail mutexes.
// Best-effort with a WARN on failure — a silently missing statusline hint is a
// debugging trap (same rule as the group-login state file).
func (rs *railSet) writeSyncHealth() {
	degraded := map[string]syncHealthRail{}
	for _, r := range rs.rails {
		r.mu.Lock()
		if r.state == railStale || r.state == railOffline {
			degraded[r.spec.name] = syncHealthRail{State: r.state.String(), FailedSince: r.failedSince}
		}
		r.mu.Unlock()
	}
	path, err := syncHealthPath()
	if err == nil {
		if len(degraded) == 0 {
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				err = rmErr
			}
		} else {
			err = func() error {
				if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
					return mkErr
				}
				data, mErr := json.Marshal(syncHealthBody{Rails: degraded, WrittenAt: time.Now().UnixMilli()})
				if mErr != nil {
					return mErr
				}
				tmp := path + ".tmp"
				if wErr := os.WriteFile(tmp, data, 0o600); wErr != nil {
					return wErr
				}
				return os.Rename(tmp, path)
			}()
		}
	}
	if err != nil {
		slog.Warn("sync-health state file update failed — statusline may show a stale sync warning",
			"event.name", observability.EventProxySyncHealthFileFailed, "error", err.Error())
	}
}

// ── shared team credential source (§3.2) ────────────────────────────────────

// teamCredentialSource builds the team account-JWT on demand and rebuilds it
// whenever the control URL changes, a refresh fails, or a Reload invalidates it
// — the per-cycle inversion of the old "build once at poll start" pattern.
//
// The refresh URL is DERIVED from the current control URL (cliTokenRefreshPath)
// and the refresh_token is read from the vault at build time; the yaml
// collector_credentials bundle (loaded once at process start) is deliberately
// not consulted — it is exactly the stale-URL source the incident exposed.
type teamCredentialSource struct {
	mu       sync.Mutex
	cred     *events.RefreshableJWT
	builtURL string
}

var errRailNoTeamCredential = errors.New("no team credential in vault (not logged in?)")

// bearer returns a valid team Bearer for masterURL, (re)building the underlying
// credential when needed. A refresh failure drops the credential so the next
// cycle rebuilds from the CURRENT vault refresh_token + control URL.
// vaultReader is the minimal contract (refreshTokenSource) so tests stub it.
func (c *teamCredentialSource) bearer(ctx context.Context, vaultReader refreshTokenSource, masterURL string) (string, error) {
	c.mu.Lock()
	if c.cred == nil || c.builtURL != masterURL {
		refreshToken, err := vaultReader.GetPlatformRefreshToken()
		if err != nil || refreshToken == "" {
			c.mu.Unlock()
			if err != nil {
				return "", err
			}
			return "", errRailNoTeamCredential
		}
		if c.cred != nil && c.builtURL != masterURL {
			slog.Info("control-plane sync: team credential rebuilt for new control URL",
				"event.name", observability.EventProxySyncCredentialRebuilt,
				"old_url", c.builtURL, "new_url", masterURL)
		}
		// Zero ExpiresAt → the first Bearer() refreshes immediately against the
		// derived URL, minting a fresh access token. PersistFn nil on purpose
		// (same trust boundary as buildCollectorCredentials: the proxy never
		// writes user.yaml).
		c.cred = &events.RefreshableJWT{
			RefreshToken: refreshToken,
			RefreshURL:   masterURL + cliTokenRefreshPath,
		}
		c.builtURL = masterURL
	}
	cred := c.cred
	c.mu.Unlock()

	b, err := cred.Bearer(ctx)
	if err != nil {
		// Drop so the next cycle rebuilds (fresh vault refresh_token + URL) —
		// a rotated refresh_token or moved server heals within one cycle.
		c.mu.Lock()
		if c.cred == cred {
			c.cred = nil
		}
		c.mu.Unlock()
		return "", err
	}
	return b, nil
}

// invalidate drops the cached credential; the next cycle rebuilds from the
// current vault + control URL. Called by Reload (settings/set-url convergence).
func (c *teamCredentialSource) invalidate() {
	c.mu.Lock()
	c.cred, c.builtURL = nil, ""
	c.mu.Unlock()
}
