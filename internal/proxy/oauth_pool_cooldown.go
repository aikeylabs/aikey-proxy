// oauth_pool_cooldown.go — N8c: reactive pool-account fallback.
//
// N8a already does PRE-request avoidance (skips accounts the delivered material
// marks exhausted). N8c adds the REACTIVE layer: when a chosen account's UPSTREAM
// response says the account is broken (401) or its window is used up (a real
// exhaustion 429), cool it down so the resolver's `skip` set routes subsequent
// requests around it. The failing request still returns its status to the client
// — in-request retry (no client-visible failure) is the heavier N9 work.
//
// 429 discrimination (minimal, research-backed; full 三分类 is N9): a 429 WITH a
// rate-limit signal (anthropic-ratelimit-* / Retry-After) is a real quota/limit
// → cool down. A 429 WITHOUT those headers is Anthropic's WAF business-rejection
// (the request persona is wrong, NOT the account's fault) → do NOT cool down,
// or we'd waste a good account. Same signature the OAuth-inject research uses.
package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

const (
	// poolCooldownDefault is used when the upstream gives no Retry-After hint.
	// Short enough to recover soon after a 5h window resets, long enough to not
	// hammer a broken account every few seconds.
	poolCooldownDefault = 5 * time.Minute
	// poolCooldownMax caps a server-provided Retry-After so a hostile/huge value
	// can't lock an account out for an unreasonable time.
	poolCooldownMax = 1 * time.Hour
	// poolCooldown429NoReset is the SHORT cool for a 429 that proves limiting
	// (evidence present) but carries NO reset time from any source — the
	// transient per-minute rate-limit class (R4: 限流→短退避, never the 5-min
	// exhaustion treatment; over-cooling pulled a good account for 5min and
	// scattered its cache). sub2api's analogous fallback is 5s; ours is a bit
	// longer to avoid hammering. Structural default, tunable.
	poolCooldown429NoReset = 30 * time.Second

	// poolCooldown529Overload (P0-B, 2026-07-19): a 529 is the upstream's OWN
	// "this lane is overloaded" signal — semantically overload, NOT rate-limit,
	// so it gets its own (short) cooldown instead of the 429 treatment. Routing
	// the next requests elsewhere for a couple of minutes is exactly the load
	// shedding the upstream asked for. sub2api ships 10min (configurable); ours
	// starts shorter — overload recovers faster than a quota window, and an
	// over-long cool idles pool capacity. Structural default, tunable.
	poolCooldown529Overload = 2 * time.Minute

	// serverErrStreakThreshold / serverErrCooldown (P0-B): generic 5xx and
	// transport-level failures cool an account only after CONSECUTIVE repeats —
	// a single transient 502 must not pull a good account (sub2api marks nothing
	// on 5xx; we need the streak because we have no EWMA soft-scoring and sticky
	// binding otherwise re-sends every next request into the same broken
	// account, burning one wasted in-request-failover attempt per request).
	// Success resets the streak. In-memory only (transient by nature — a
	// restart legitimately starts a fresh streak).
	serverErrStreakThreshold = 3
	serverErrCooldown        = 60 * time.Second
)

// poolCooldownStore holds a per-account "avoid until" time. Concurrency-safe.
// Bounded by the number of distinct pool accounts; lapsed entries are dropped
// lazily on read.
type poolCooldownStore struct {
	mu  sync.Mutex
	m   map[string]time.Time // accountID → avoid-until (whole account)
	now func() time.Time     // injectable clock (tests)
	// serverErrStreak counts CONSECUTIVE 5xx/transport failures per account
	// (P0-B); reset by any success. Deliberately NOT persisted — a streak is a
	// live-liveness observation, not durable state.
	serverErrStreak map[string]int
	// tierM holds MODEL-TIER-scoped cooldowns (P1-C): "accountID|tierKey" →
	// avoid-until. A tier entry excludes the account ONLY for requests whose
	// model maps into that tier (skipSetFor); every other model keeps serving —
	// a Fable weekly-window exhaustion must not block Sonnet traffic.
	tierM map[string]time.Time
}

func tierCooldownKey(accountID, tierKey string) string { return accountID + "|" + tierKey }

func newPoolCooldownStore() *poolCooldownStore {
	s := &poolCooldownStore{m: make(map[string]time.Time), now: time.Now,
		serverErrStreak: make(map[string]int), tierM: make(map[string]time.Time)}
	// Cross-restart persistence (2026-07-04 self-heal, §S4): without it a proxy
	// restart forgot every cooldown and could immediately route traffic back
	// onto an account that just 401'd / rate-limited. STRICTLY an enhancement,
	// never a dependency (owner constraint): a missing/corrupt/unreadable file
	// falls back to an empty store and the main link proceeds untouched.
	s.hydrateFromFile()
	return s
}

// ── cross-restart persistence (bypass state file, §S4 2026-07-04) ───────────
// Same ownership pattern as sync-health.json / group-login-required.json:
// one concern, one file, one writer (this store). Writes happen on mark()
// (rare — an upstream 401/exhaustion) and are atomic (temp+rename). Reads
// happen ONCE at construction. Every failure path is best-effort:
// write → WARN and keep serving; read → empty store (fallback, never blocks).

const poolCooldownFilename = "pool-cooldown.json"

type poolCooldownFileBody struct {
	// Accounts maps accountID → avoid-until unix seconds (only unexpired ones).
	Accounts  map[string]int64 `json:"accounts"`
	WrittenAt int64            `json:"written_at"` // unix millis
	// TierAccounts maps "accountID|tierKey" → avoid-until unix seconds (P1-C
	// model-tier cooldowns; a Fable weekly window spans days, so surviving a
	// restart matters even more than for the short account-level cools).
	// Additive field: older proxies ignore it, older files parse without it.
	TierAccounts map[string]int64 `json:"tier_accounts,omitempty"`
}

func poolCooldownPath() (string, error) {
	if dir := os.Getenv("AIKEY_RUN_DIR"); dir != "" {
		return filepath.Join(dir, poolCooldownFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aikey", "run", poolCooldownFilename), nil
}

// hydrateFromFile preloads unexpired cooldowns from the state file. Fallback
// by design: any error (missing file, bad JSON, unreadable) leaves the store
// empty — the data path never depends on this file.
func (s *poolCooldownStore) hydrateFromFile() {
	path, err := poolCooldownPath()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return // missing or unreadable → empty store (fallback)
	}
	var body poolCooldownFileBody
	if json.Unmarshal(raw, &body) != nil {
		return // corrupt → empty store (fallback); next mark() overwrites it
	}
	now := s.now()
	loaded := 0
	for id, untilUnix := range body.Accounts {
		until := time.Unix(untilUnix, 0)
		if id != "" && now.Before(until) {
			s.m[id] = until
			loaded++
		}
	}
	for key, untilUnix := range body.TierAccounts {
		until := time.Unix(untilUnix, 0)
		if key != "" && now.Before(until) {
			s.tierM[key] = until
			loaded++
		}
	}
	if loaded > 0 {
		slog.Info("pool cooldowns hydrated from state file (survive restart)",
			"event.name", observability.EventProxyGroupAccountCooldown, "accounts", loaded)
	}
}

// persistLocked mirrors the current unexpired cooldowns to the state file
// (s.mu held by the caller). Empty set removes the file. Best-effort: a
// failure is WARN-logged and never surfaces to the request path.
func (s *poolCooldownStore) persistLocked() {
	path, err := poolCooldownPath()
	if err != nil {
		return
	}
	now := s.now()
	accounts := make(map[string]int64, len(s.m))
	for id, until := range s.m {
		if now.Before(until) {
			accounts[id] = until.Unix()
		}
	}
	var tierAccounts map[string]int64
	for key, until := range s.tierM {
		if now.Before(until) {
			if tierAccounts == nil {
				tierAccounts = make(map[string]int64, len(s.tierM))
			}
			tierAccounts[key] = until.Unix()
		}
	}
	if len(accounts) == 0 && len(tierAccounts) == 0 {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			slog.Warn("pool cooldown state file remove failed",
				"event.name", observability.EventProxyGroupAccountCooldown, "error", rmErr.Error())
		}
		return
	}
	err = func() error {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return mkErr
		}
		data, mErr := json.Marshal(poolCooldownFileBody{Accounts: accounts, TierAccounts: tierAccounts, WrittenAt: time.Now().UnixMilli()})
		if mErr != nil {
			return mErr
		}
		tmp := path + ".tmp"
		if wErr := os.WriteFile(tmp, data, 0o600); wErr != nil {
			return wErr
		}
		return os.Rename(tmp, path)
	}()
	if err != nil {
		slog.Warn("pool cooldown state file write failed — cooldowns won't survive a restart",
			"event.name", observability.EventProxyGroupAccountCooldown, "error", err.Error())
	}
}

// noteServerError records one 5xx/transport failure for an account (P0-B) and
// returns (avoid-until, true) once the CONSECUTIVE streak reaches the
// threshold (the streak resets so recovery gets a fresh count after the cool).
// Below threshold → (zero, false): a transient blip cools nobody.
func (s *poolCooldownStore) noteServerError(accountID string) (time.Time, bool) {
	if accountID == "" {
		return time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serverErrStreak == nil { // tests build the store literally; stay nil-safe
		s.serverErrStreak = make(map[string]int)
	}
	s.serverErrStreak[accountID]++
	if s.serverErrStreak[accountID] < serverErrStreakThreshold {
		return time.Time{}, false
	}
	delete(s.serverErrStreak, accountID)
	until := s.now().Add(serverErrCooldown)
	if cur, ok := s.m[accountID]; !ok || until.After(cur) {
		s.m[accountID] = until
		s.persistLocked()
	}
	return until, true
}

// noteSuccess resets an account's server-error streak (any successful response
// proves the account serves again).
func (s *poolCooldownStore) noteSuccess(accountID string) {
	if accountID == "" {
		return
	}
	s.mu.Lock()
	if _, ok := s.serverErrStreak[accountID]; ok {
		delete(s.serverErrStreak, accountID)
	}
	s.mu.Unlock()
}

// mark cools an account down until `until`. A no-op for an empty id or a time
// already in the past.
func (s *poolCooldownStore) mark(accountID string, until time.Time) {
	if accountID == "" {
		return
	}
	s.mu.Lock()
	if cur, ok := s.m[accountID]; !ok || until.After(cur) {
		s.m[accountID] = until
		s.persistLocked()
	}
	s.mu.Unlock()
}

// skipSet returns the accounts currently cooling down, for the resolver's `skip`
// argument. Lapsed entries are dropped. Returns nil when nothing is cooling
// (so the resolver's `skip[id]` lookups stay cheap).
func (s *poolCooldownStore) skipSet() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out map[string]bool
	for id, until := range s.m {
		if now.Before(until) {
			if out == nil {
				out = make(map[string]bool)
			}
			out[id] = true
		} else {
			delete(s.m, id)
		}
	}
	return out
}

// markTier cools an account for ONE model tier only (P1-C): requests of that
// tier skip the account; every other model keeps serving it.
func (s *poolCooldownStore) markTier(accountID, tierKey string, until time.Time) {
	if accountID == "" || tierKey == "" {
		return
	}
	s.mu.Lock()
	if s.tierM == nil { // literal test construction safety
		s.tierM = make(map[string]time.Time)
	}
	key := tierCooldownKey(accountID, tierKey)
	if cur, ok := s.tierM[key]; !ok || until.After(cur) {
		s.tierM[key] = until
		s.persistLocked()
	}
	s.mu.Unlock()
}

// skipSetFor returns the resolver skip set for a request of the given model:
// whole-account cooldowns PLUS the accounts tier-cooled for that model's tier
// (standard-tier models see only the whole-account set).
func (s *poolCooldownStore) skipSetFor(model string) map[string]bool {
	out := s.skipSet()
	tier := tierForModel(model)
	if tier == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	suffix := "|" + tier.Key
	for key, until := range s.tierM {
		if !now.Before(until) {
			delete(s.tierM, key)
			continue
		}
		if strings.HasSuffix(key, suffix) {
			if out == nil {
				out = make(map[string]bool)
			}
			out[strings.TrimSuffix(key, suffix)] = true
		}
	}
	return out
}

// tierCooldownUntil reports the latest avoid-until across accounts cooled for a
// tier ((zero, false) when none) — feeds the client guidance message's reset
// time when a tier is exhausted pool-wide.
func (s *poolCooldownStore) tierCooldownUntil(tierKey string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var latest time.Time
	suffix := "|" + tierKey
	for key, until := range s.tierM {
		if !now.Before(until) {
			delete(s.tierM, key)
			continue
		}
		if strings.HasSuffix(key, suffix) && until.After(latest) {
			latest = until
		}
	}
	return latest, !latest.IsZero()
}

// snapshot returns the accounts currently cooling down → seconds remaining, for
// the admin health surface (N9 组路由健康). Lapsed entries are pruned (same as
// skipSet). Returns nil when nothing is cooling.
func (s *poolCooldownStore) snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out map[string]int
	for id, until := range s.m {
		if now.Before(until) {
			if out == nil {
				out = make(map[string]int)
			}
			out[id] = int(until.Sub(now).Seconds())
		} else {
			delete(s.m, id)
		}
	}
	return out
}

// cooldownDecision classifies an upstream response: when the chosen pool account
// should be cooled down, returns (avoid-until, true). 401 → broken account.
// 429 with limit EVIDENCE → cool for the best reset we can read (codex window
// reset → unified reset epoch → Retry-After → short no-reset fallback). 429
// WITHOUT evidence (suspected WAF / business rejection) and everything else →
// (_, false).
func cooldownDecision(resp *http.Response, now time.Time) (time.Time, bool) {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return now.Add(poolCooldownDefault), true
	case 529:
		// P0-B: the upstream's explicit overload signal — shed load off this
		// account for a short, overload-scoped window (NOT the 429 semantics;
		// see poolCooldown529Overload). Generic 5xx is handled by the caller's
		// consecutive-streak path, not here.
		return now.Add(poolCooldown529Overload), true
	case http.StatusTooManyRequests:
		if !hasRateLimitSignal(resp.Header) {
			return time.Time{}, false // suspected WAF / business rejection — not the account's fault
		}
		// Cooldown length comes from the reset EVIDENCE (sub2api-style, B1 fix
		// 2026-07-19): codex window reset first (R37/D9), then the anthropic
		// unified reset epoch of the exhausted window (closes the 0630-audit #18
		// gap — the reactive path never consumed unified-reset), then Retry-After.
		// Evidence of limiting but NO reset info anywhere = the transient
		// per-minute class → SHORT cool (0630-audit #8 / E9 三分类: the flat 5-min
		// default over-cooled a good account exactly like a 5h exhaustion).
		d := poolCooldown429NoReset
		if cx := codexRateLimitReset(resp.Header); cx > 0 {
			d = cx
		} else if ar := anthropicUnifiedResetDuration(resp.Header, now); ar > 0 {
			d = ar
		} else if ra := retryAfterDuration(resp.Header); ra > 0 {
			d = ra
		}
		if d > poolCooldownMax {
			d = poolCooldownMax
		}
		return now.Add(d), true
	default:
		return time.Time{}, false
	}
}

// hasRateLimitSignal reports whether the response carries REAL rate-limit /
// exhaustion evidence (vs a WAF business rejection). Two header families
// (mutually exclusive per account provider):
//   - codex (x-codex-* usage headers): presence-based — these only ride on the
//     ChatGPT backend and a codex 429 omitting them would be mis-read as WAF and
//     the exhausted account never cooled (打死号, R37 verified live 2026-07-06);
//   - anthropic: VALUE-based (B1 fix 2026-07-19, sub2api-style). The unified-*
//     headers ride on EVERY anthropic response — 200s included — so "some header
//     name contains ratelimit" (the old rule) proved nothing: a WAF/business 429
//     that carries the routine unified telemetry cooled a perfectly good account
//     for 5 minutes, and a correlated WAF burst could chain-cool the whole pool
//     (the 0717-review B1 risk). Real limiting must show CONCRETE evidence:
//     a *-status flip, utilization at/over 1.0, or an explicit Retry-After.
func hasRateLimitSignal(h http.Header) bool {
	if h.Get("Retry-After") != "" {
		return true
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-codex-") {
			return true
		}
	}
	return anthropicExhaustionEvidence(h)
}

// anthropicExhaustionEvidence reports whether the anthropic unified headers show
// the account actually hit a limit: an aggregate status flip (实测
// allowed|rate_limited), a general 5h/7d window exhausted, or a premium-tier
// window (Fable 7d_oi) exhausted — per-window evidence uses the uniform
// status/surpassed/utilization judgment (anthropicWindowExhausted; per-window
// status + surpassed-threshold confirmed real by sub2api production code,
// 2026-07-19). Absence of evidence on a 429 means "very likely not a real
// limit" (WAF / business rejection / extra-usage prompts) — pass it through
// instead of pulling the account. Tier-only evidence still counts here (the 429
// is REAL, and N9 may fail the request over to an account whose tier window has
// headroom); the cooldown SCOPE decision (tier vs whole account) is made by the
// caller's tier-first guard, not by this predicate.
func anthropicExhaustionEvidence(h http.Header) bool {
	switch strings.ToLower(strings.TrimSpace(h.Get("anthropic-ratelimit-unified-status"))) {
	case "rate_limited", "rejected", "exceeded", "exhausted":
		return true
	}
	if anthropicWindowExhausted(h, "5h") || anthropicWindowExhausted(h, "7d") {
		return true
	}
	for i := range modelTiers {
		if anthropicWindowExhausted(h, modelTiers[i].WindowID) {
			return true
		}
	}
	return false
}

// anthropicUnifiedResetDuration derives the cooldown from the unified reset
// epochs of the EXHAUSTED window(s): the longest reset among windows at/over 1.0
// utilization (same never-un-cool-into-a-full-window insight as codex D9), else
// the aggregate unified-reset epoch. Returns 0 when no future epoch is readable
// (caller falls back to Retry-After / the short no-reset cool).
func anthropicUnifiedResetDuration(h http.Header, now time.Time) time.Duration {
	epochAfter := func(key string) (time.Time, bool) {
		if v := h.Get(key); v != "" {
			if epoch, err := strconv.ParseInt(v, 10, 64); err == nil && epoch > 0 {
				if t := time.Unix(epoch, 0); t.After(now) {
					return t, true
				}
			}
		}
		return time.Time{}, false
	}
	var best time.Time
	if u, ok := parseUtil(h, hdrUtil5h); ok && u >= 1.0 {
		if t, ok := epochAfter(hdrReset5h); ok && t.After(best) {
			best = t
		}
	}
	if u, ok := parseUtil(h, hdrUtil7d); ok && u >= 1.0 {
		if t, ok := epochAfter(hdrReset7d); ok && t.After(best) {
			best = t
		}
	}
	if best.IsZero() {
		if t, ok := epochAfter(hdrReset); ok {
			best = t
		}
	}
	if best.IsZero() {
		return 0
	}
	return best.Sub(now)
}

// codexRateLimitReset extracts the cooldown duration from codex's own rate-limit
// headers (ChatGPT backend; wire format verified live 2026-07-06, see
// research/oauth-codex-ratelimit/). We cool for the LONGEST reset among the
// EXHAUSTED (used_percent ≥ 100) windows, so we never un-cool the account into a
// window that is still full and immediately re-429. Returns 0 when no codex reset
// header is present (caller falls back to Retry-After / default). Anthropic
// responses carry no x-codex-* headers, so this is a no-op on the claude path.
//
// Why compare reset DURATIONS, not the primary/secondary NAME: the primary/
// secondary label is NOT tied to a fixed 5h/7d window — a Plus account's primary
// IS the 5h window (verified live 2026-07-06; sub2api's "primary=weekly" comment
// is backwards). The previous code returned the primary reset first assuming
// primary=7d ("the longer wall"), so when BOTH windows were exhausted it
// under-cooled to whichever window happened to be primary and re-429'd. Comparing
// resets directly sidesteps the naming trap entirely.
// Ref: bugfix 2026-07-06-codex-ratelimit-reset-window-by-name.md.
func codexRateLimitReset(h http.Header) time.Duration {
	primaryReset := codexHeaderInt(h, "x-codex-primary-reset-after-seconds")
	secondaryReset := codexHeaderInt(h, "x-codex-secondary-reset-after-seconds")
	primaryUsed := codexHeaderFloat(h, "x-codex-primary-used-percent")
	secondaryUsed := codexHeaderFloat(h, "x-codex-secondary-used-percent")

	// Longest reset among EXHAUSTED windows wins (the bigger wall).
	best := 0
	if primaryUsed >= 100 && primaryReset > best {
		best = primaryReset
	}
	if secondaryUsed >= 100 && secondaryReset > best {
		best = secondaryReset
	}
	if best == 0 {
		// 429 with neither window flagged exhausted → cool for the longer reset we
		// can see (both windows' resets ride on the response regardless).
		best = primaryReset
		if secondaryReset > best {
			best = secondaryReset
		}
	}
	if best > 0 {
		return time.Duration(best) * time.Second
	}
	return 0
}

func codexHeaderInt(h http.Header, key string) int {
	if v := strings.TrimSpace(h.Get(key)); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return 0
}

func codexHeaderFloat(h http.Header, key string) float64 {
	if v := strings.TrimSpace(h.Get(key)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

// retryAfterDuration parses the Retry-After header's delta-seconds form. The
// HTTP-date form is ignored (returns 0 → caller uses the default).
func retryAfterDuration(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}
