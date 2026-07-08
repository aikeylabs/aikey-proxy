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
)

// poolCooldownStore holds a per-account "avoid until" time. Concurrency-safe.
// Bounded by the number of distinct pool accounts; lapsed entries are dropped
// lazily on read.
type poolCooldownStore struct {
	mu  sync.Mutex
	m   map[string]time.Time // accountID → avoid-until
	now func() time.Time     // injectable clock (tests)
}

func newPoolCooldownStore() *poolCooldownStore {
	s := &poolCooldownStore{m: make(map[string]time.Time), now: time.Now}
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
	if len(accounts) == 0 {
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
		data, mErr := json.Marshal(poolCooldownFileBody{Accounts: accounts, WrittenAt: time.Now().UnixMilli()})
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
// Exhaustion-429 (rate-limit signal present) → honor Retry-After if given, else
// default. WAF-business-429 (no signal) and everything else → (_, false).
func cooldownDecision(resp *http.Response, now time.Time) (time.Time, bool) {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return now.Add(poolCooldownDefault), true
	case http.StatusTooManyRequests:
		if !hasRateLimitSignal(resp.Header) {
			return time.Time{}, false // WAF business rejection — not the account's fault
		}
		d := poolCooldownDefault
		// Codex (ChatGPT) carries its own reset headers (x-codex-*-reset-after-
		// seconds) instead of Retry-After — prefer them; else Retry-After; else
		// default. See research/oauth-codex-ratelimit + R37 (2026-07-04).
		if cx := codexRateLimitReset(resp.Header); cx > 0 {
			d = cx
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

// hasRateLimitSignal reports whether the response carries a real rate-limit /
// exhaustion marker (vs a WAF business rejection that omits them). Covers the
// anthropic form (Retry-After / *ratelimit* headers) AND the codex form
// (x-codex-* usage headers) — a codex 429 that omitted both would otherwise be
// mis-read as a WAF rejection and the exhausted account never cooled (打死号).
func hasRateLimitSignal(h http.Header) bool {
	if h.Get("Retry-After") != "" {
		return true
	}
	for k := range h {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "ratelimit") || strings.HasPrefix(lk, "x-codex-") {
			return true
		}
	}
	return false
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
