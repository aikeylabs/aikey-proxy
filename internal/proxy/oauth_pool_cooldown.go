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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

const (
	// poolCooldownDefault is used when the upstream gives no Retry-After hint.
	// Short enough to recover soon after a 5h window resets, long enough to not
	// hammer a broken account every few seconds.
	poolCooldownDefault = 5 * time.Minute
	// poolCooldownMax caps a server-provided Retry-After so a hostile/huge value
	// can't lock an account out for an unreasonable time.
	poolCooldownMax = 1 * time.Hour
	// poolCooldown429NoReset is the product default SHORT cool for a 429 that proves limiting
	// (evidence present) but carries NO reset time from any source — the
	// transient per-minute rate-limit class (R4: 限流→短退避, never the 5-min
	// exhaustion treatment; over-cooling pulled a good account for 5min and
	// scattered its cache). sub2api's analogous fallback is 5s. This code-level
	// value is the rolling-upgrade default; each pool may override it through the
	// existing routing_config rail. Provider recovery evidence takes priority.
	poolCooldown429NoReset = 5 * time.Second
	poolCooldown429Min     = 1 * time.Second

	// poolCooldown529Overload (P0-B, 2026-07-19): a 529 is the upstream's OWN
	// "this lane is overloaded" signal — semantically overload, NOT rate-limit,
	// so it gets its own (short) cooldown instead of the 429 treatment. Routing
	// the next requests elsewhere for a couple of minutes is exactly the load
	// shedding the upstream asked for. sub2api ships 10min (configurable); ours
	// starts shorter — overload recovers faster than a quota window, and an
	// over-long cool idles pool capacity. Structural default, tunable.
	poolCooldown529Overload = 2 * time.Minute

	// serverErrStreakThreshold / serverErrCooldown (P0-B): generic HTTP 5xx
	// failures cool an account only after CONSECUTIVE repeats —
	// a single transient 502 must not pull a good account (sub2api marks nothing
	// on 5xx; we need the streak because we have no EWMA soft-scoring and sticky
	// binding otherwise re-sends every next request into the same broken
	// account, burning one wasted in-request-failover attempt per request).
	// Success resets the streak. In-memory only (transient by nature — a
	// restart legitimately starts a fresh streak).
	serverErrStreakThreshold = 3
	serverErrCooldown        = 60 * time.Second

	poolRouteWindowExhausted     = "window_exhausted"
	poolRouteWindowProtected     = "window_protected"
	poolRouteRateLimited         = "rate_limited"
	poolRouteAuthFailed          = "auth_failed"
	poolRouteUpstreamUnavailable = "upstream_unavailable"
	windowStatusExhausted        = "exhausted_current_window"
)

// PoolAccountRouteState is the display-safe projection of one whole-account
// cooldown. The cooldown store remains the routing truth; this value only lets
// the local vault explain why an account was skipped and when it is expected to
// recover. RetryAt is unix seconds. Tier-only cooldowns are intentionally absent.
type PoolAccountRouteState struct {
	Status    string `json:"status"`
	RetryAt   int64  `json:"retry_at,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// poolCooldownStore holds a per-account "avoid until" time. Concurrency-safe.
// Bounded by the number of distinct pool accounts; lapsed entries are dropped
// lazily on read.
type poolCooldownStore struct {
	mu sync.Mutex
	// persistWake crosses the request/background boundary. Request-path
	// mutations only publish a coalesced, non-blocking wake-up; the writer loop
	// is started at construction and owns every scheduled filesystem call.
	persistWake       chan struct{}
	persistStop       chan struct{}
	persistDone       chan struct{}
	persistCloseOnce  sync.Once
	persistWriting    bool
	persistRevision   uint64
	persistIO         sync.Mutex
	persistedRevision uint64
	persistPath       string
	m                 map[string]time.Time             // accountID → avoid-until (whole account)
	meta              map[string]PoolAccountRouteState // accountID → display reason/recovery
	// windowStatuses is the replayable control-plane projection keyed by the
	// local account id. It is persisted with the cooldown and re-reported while
	// the provider reset is still in the future; routing never depends on it.
	windowStatuses map[string]windowStatusSample
	now            func() time.Time // injectable clock (tests)
	// onAccountSetChanged is a best-effort notification that the WHOLE-ACCOUNT
	// skip-set membership changed (enter cooldown or expire). The callback must be
	// non-blocking: mark() runs on the request hot path. It is copied under mu and
	// invoked after unlock so a consumer may safely call skipSet() while recomputing
	// the current_routed display projection. Tier-only cooldowns deliberately do not
	// notify because current_routed has no model dimension.
	onAccountSetChanged func()
	// serverErrStreak counts CONSECUTIVE HTTP 5xx responses per account
	// (P0-B); reset by any success. Deliberately NOT persisted — a streak is a
	// live-liveness observation, not durable state.
	serverErrStreak map[string]int
	// tierM holds MODEL-TIER-scoped cooldowns (P1-C): "accountID|tierKey" →
	// avoid-until. A tier entry excludes the account ONLY for requests whose
	// model maps into that tier (skipSetFor); every other model keeps serving —
	// a Fable weekly-window exhaustion must not block Sonnet traffic.
	tierM map[string]time.Time
	// lapsed records accounts whose cooldown (whole-account or tier) was
	// observed EXPIRED and pruned — consumed once by the scheduling-log settle
	// hook so "same account resumed after recovery" gets its route_resolved
	// (reason=recovered) row (覆盖度审计拍板 2026-08-18). Bounded by the distinct
	// account set; entries clear on consumption. Deliberately not persisted —
	// recovery attribution is a live observation.
	lapsed map[string]struct{}
	// authFailedTokens is a route-member + token-version tombstone, not a timed
	// cooldown. The key includes group, seat and account: one Cluster Worker can
	// serve several members of the same pool, whose tokens must remain isolated.
	// Keeping only a SHA-256 fingerprint lets the resolver reject the exact bad
	// token across requests/restarts without storing or logging token material.
	authFailedTokens map[string]string
}

func tierCooldownKey(accountID, tierKey string) string { return accountID + "|" + tierKey }

func authFailureRouteKey(oauthGroupID, seatID, accountID string) string {
	return oauthGroupID + "|" + seatID + "|" + accountID
}

func parseAuthFailureRouteKey(key string) (PoolAuthFailureState, bool) {
	parts := strings.SplitN(key, "|", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return PoolAuthFailureState{}, false
	}
	return PoolAuthFailureState{OAuthGroupID: parts[0], SeatID: parts[1], AccountID: parts[2]}, true
}

// PoolAuthFailureState is one member-scoped hard-revocation projection. A
// zero-time auth failure is intentionally separate from whole-account cooldowns.
type PoolAuthFailureState struct {
	OAuthGroupID string `json:"oauth_group_id"`
	SeatID       string `json:"seat_id"`
	AccountID    string `json:"account_id"`
}

func newPoolCooldownStore() *poolCooldownStore {
	s := &poolCooldownStore{m: make(map[string]time.Time), now: time.Now,
		meta: make(map[string]PoolAccountRouteState), serverErrStreak: make(map[string]int), tierM: make(map[string]time.Time),
		authFailedTokens: make(map[string]string), windowStatuses: make(map[string]windowStatusSample), lapsed: make(map[string]struct{}),
		persistWake: make(chan struct{}, 1), persistStop: make(chan struct{}), persistDone: make(chan struct{})}
	s.persistPath, _ = poolCooldownPath()
	// Cross-restart persistence (2026-07-04 self-heal, §S4): without it a proxy
	// restart forgot every cooldown and could immediately route traffic back
	// onto an account that just 401'd / rate-limited. STRICTLY an enhancement,
	// never a dependency (owner constraint): a missing/corrupt/unreadable file
	// falls back to an empty store and the main link proceeds untouched.
	s.hydrateFromFile()
	go s.persistenceLoop()
	return s
}

// setAccountSetChangedHook installs the display-projection wake-up hook. The
// store owns only the cooldown truth; it does not perform vault I/O itself.
func (s *poolCooldownStore) setAccountSetChangedHook(hook func()) {
	s.mu.Lock()
	s.onAccountSetChanged = hook
	s.mu.Unlock()
}

// ── cross-restart persistence (bypass state file, §S4 2026-07-04) ───────────
// Same ownership pattern as sync-health.json / group-login-required.json:
// one concern, one file, one background writer (this store). Mutations on
// mark() schedule a coalesced atomic snapshot (temp+rename); reads happen ONCE
// at construction. Every failure path is best-effort:
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
	// AccountStates is additive metadata for the user-facing runtime projection.
	// The authoritative avoid-until remains Accounts; old files without this map
	// continue to route correctly and simply render no explanatory status.
	AccountStates map[string]PoolAccountRouteState `json:"account_states,omitempty"`
	// WindowStatuses is an additive replay snapshot. Older proxies ignore it;
	// upgraded proxies hydrate it only while the matching cooldown/reset is live.
	WindowStatuses map[string]windowStatusSample `json:"window_statuses,omitempty"`
	// AuthFailedTokens maps "oauthGroupID|seatID|accountID" to the fingerprint
	// of the exact OAuth access token rejected as hard-revoked.
	AuthFailedTokens map[string]string `json:"auth_failed_tokens,omitempty"`
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
	path := s.persistPath
	if path == "" {
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
			if state, ok := body.AccountStates[id]; ok && state.Status != "" {
				if s.meta == nil {
					s.meta = make(map[string]PoolAccountRouteState)
				}
				s.meta[id] = state
			}
			loaded++
		}
	}
	for accountID, state := range body.WindowStatuses {
		until, cooling := s.m[accountID]
		if !cooling || !now.Before(until) || state.CredentialID == "" {
			continue
		}
		state = activeWindowStatusSample(state, now)
		if state.WindowStatus == "" && state.Window7dStatus == "" {
			continue
		}
		s.windowStatuses[accountID] = state
	}
	for key, untilUnix := range body.TierAccounts {
		until := time.Unix(untilUnix, 0)
		if key != "" && now.Before(until) {
			s.tierM[key] = until
			loaded++
		}
	}
	for routeKey, fingerprint := range body.AuthFailedTokens {
		if _, ok := parseAuthFailureRouteKey(routeKey); !ok || fingerprint == "" {
			continue
		}
		s.authFailedTokens[routeKey] = fingerprint
		loaded++
	}
	if loaded > 0 {
		slog.Info("pool cooldowns hydrated from state file (survive restart)",
			"event.name", observability.EventProxyGroupAccountCooldown, "accounts", loaded)
	}
}

// persistLocked publishes one coalesced wake-up and returns immediately. The
// caller holds s.mu, often on the request path; it must never encode JSON,
// create a timer callback that reaches the writer, or touch the filesystem.
// The construction-time writer loop is the explicit async boundary, so both
// runtime behavior and the PLANE-01 call graph keep file I/O off Proxy.Handle.
func (s *poolCooldownStore) persistLocked() {
	s.persistRevision++
	select {
	case s.persistWake <- struct{}{}:
	default:
		// One pending wake already represents every newer in-memory revision.
	}
}

func (s *poolCooldownStore) persistenceLoop() {
	defer close(s.persistDone)
	for {
		select {
		case <-s.persistWake:
		case <-s.persistStop:
			return
		}

		// Bound coalescing latency from the first mutation. Further wakes are
		// drained during this window; a mutation after snapshot capture remains
		// buffered and drives exactly one follow-up write.
		timer := time.NewTimer(5 * time.Millisecond)
	coalesce:
		for {
			select {
			case <-s.persistWake:
			case <-timer.C:
				break coalesce
			case <-s.persistStop:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			}
		}
		s.persistScheduledSnapshot()
	}
}

// persistScheduledSnapshot is called only by persistenceLoop, never by the
// forwarding graph. It copies state under mu, then performs file I/O unlocked.
func (s *poolCooldownStore) persistScheduledSnapshot() {
	s.mu.Lock()
	s.persistWriting = true
	revision := s.persistRevision
	body := s.persistenceSnapshotLocked()
	s.mu.Unlock()
	s.writePersistenceSnapshot(body, revision)

	s.mu.Lock()
	s.persistWriting = false
	s.mu.Unlock()
}

func (s *poolCooldownStore) persistenceSnapshotLocked() poolCooldownFileBody {
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
	states := make(map[string]PoolAccountRouteState, len(accounts))
	for id := range accounts {
		if state, ok := s.meta[id]; ok && state.Status != "" {
			states[id] = state
		}
	}
	windows := make(map[string]windowStatusSample, len(accounts))
	for id := range accounts {
		if state, ok := s.windowStatuses[id]; ok {
			state = activeWindowStatusSample(state, now)
			if state.WindowStatus != "" || state.Window7dStatus != "" {
				windows[id] = state
			}
		}
	}
	authFailedTokens := make(map[string]string, len(s.authFailedTokens))
	for id, fingerprint := range s.authFailedTokens {
		authFailedTokens[id] = fingerprint
	}
	return poolCooldownFileBody{
		Accounts: accounts, AccountStates: states, WindowStatuses: windows, TierAccounts: tierAccounts,
		AuthFailedTokens: authFailedTokens, WrittenAt: time.Now().UnixMilli(),
	}
}

func (s *poolCooldownStore) writePersistenceSnapshot(body poolCooldownFileBody, revision uint64) {
	s.persistIO.Lock()
	defer s.persistIO.Unlock()
	// A timer may have captured an older snapshot just before shutdown flush
	// captured a newer one. Mutex serialization alone does not define which
	// waiter writes last, so reject stale revisions explicitly; otherwise the
	// old timer could overwrite the shutdown snapshot after flush returned.
	if revision < s.persistedRevision {
		return
	}
	path := s.persistPath
	if path == "" {
		return
	}
	var err error
	if len(body.Accounts) == 0 && len(body.TierAccounts) == 0 && len(body.AuthFailedTokens) == 0 && len(body.WindowStatuses) == 0 {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			slog.Warn("pool cooldown state file remove failed",
				"event.name", observability.EventProxyGroupAccountCooldown, "error", rmErr.Error())
		}
		s.persistedRevision = revision
		return
	}
	err = func() error {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return mkErr
		}
		data, mErr := json.Marshal(body)
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
	s.persistedRevision = revision
}

// flushPersistence is a lifecycle/test barrier. It is deliberately allowed to
// block because callers are process shutdown or persistence assertions, never
// inference requests.
func (s *poolCooldownStore) flushPersistence() {
	if s == nil {
		return
	}
	s.mu.Lock()
	body := s.persistenceSnapshotLocked()
	revision := s.persistRevision
	s.mu.Unlock()
	s.writePersistenceSnapshot(body, revision)
}

// closePersistence retires the construction-time writer before the final
// snapshot. Process shutdown is the only production caller; no request is
// permitted beyond this lifecycle boundary.
func (s *poolCooldownStore) closePersistence() {
	if s == nil {
		return
	}
	s.persistCloseOnce.Do(func() {
		close(s.persistStop)
		<-s.persistDone
		s.flushPersistence()
	})
}

// oauthTokenFingerprint returns a non-reversible identifier for one delivered
// token version. It is safe to persist, unlike the token itself.
func oauthTokenFingerprint(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// markAuthFailedToken replaces the generic timed 401 cooldown with a durable
// token-version tombstone. Waiting cannot repair a revoked token; only delivery
// of a different token version should re-admit the account.
func (s *poolCooldownStore) markAuthFailedToken(oauthGroupID, seatID, accountID, fingerprint string) {
	if oauthGroupID == "" || seatID == "" || accountID == "" || fingerprint == "" {
		return
	}
	routeKey := authFailureRouteKey(oauthGroupID, seatID, accountID)
	s.mu.Lock()
	if s.authFailedTokens == nil {
		s.authFailedTokens = make(map[string]string)
	}
	changed := s.authFailedTokens[routeKey] != fingerprint
	s.authFailedTokens[routeKey] = fingerprint
	if changed {
		s.persistLocked()
	}
	hook := s.onAccountSetChanged
	s.mu.Unlock()
	if changed && hook != nil {
		hook()
	}
}

// authFailureSkipSet compares persisted hard-revoke tombstones with the latest
// delivered group material. The same token is skipped; needs_login material is
// left to the resolver so it can emit the actionable login prompt; a newly
// delivered token clears the tombstone immediately and is eligible now.
func (s *poolCooldownStore) authFailureSkipSet(oauthGroupID, seatID, groupRuntime string, derivedKey []byte) map[string]bool {
	prefix := oauthGroupID + "|" + seatID + "|"
	s.mu.Lock()
	known := make(map[string]string)
	for routeKey, fingerprint := range s.authFailedTokens {
		if strings.HasPrefix(routeKey, prefix) {
			known[routeKey] = fingerprint
		}
	}
	s.mu.Unlock()
	if len(known) == 0 || groupRuntime == "" {
		return nil
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(groupRuntime), &material); err != nil {
		return nil
	}
	var skip map[string]bool
	cleared := false
	for routeKey, rejectedFingerprint := range known {
		routeState, ok := parseAuthFailureRouteKey(routeKey)
		if !ok {
			continue
		}
		mat, ok := material[routeState.AccountID]
		if !ok || mat.NeedsLogin {
			continue
		}
		token, err := decryptGroupSecret(derivedKey, mat)
		if err != nil || token == "" {
			continue
		}
		currentFingerprint := oauthTokenFingerprint(token)
		if currentFingerprint == rejectedFingerprint {
			if skip == nil {
				skip = make(map[string]bool)
			}
			skip[routeState.AccountID] = true
			continue
		}
		s.mu.Lock()
		if s.authFailedTokens[routeKey] == rejectedFingerprint {
			delete(s.authFailedTokens, routeKey)
			s.persistLocked()
			cleared = true
		}
		s.mu.Unlock()
	}
	if cleared {
		s.mu.Lock()
		hook := s.onAccountSetChanged
		s.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	return skip
}

func (s *poolCooldownStore) authFailureSnapshot() []PoolAuthFailureState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PoolAuthFailureState, 0, len(s.authFailedTokens))
	for routeKey := range s.authFailedTokens {
		if state, ok := parseAuthFailureRouteKey(routeKey); ok {
			out = append(out, state)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OAuthGroupID != out[j].OAuthGroupID {
			return out[i].OAuthGroupID < out[j].OAuthGroupID
		}
		if out[i].SeatID != out[j].SeatID {
			return out[i].SeatID < out[j].SeatID
		}
		return out[i].AccountID < out[j].AccountID
	})
	return out
}

func mergeAccountSkipSets(sets ...map[string]bool) map[string]bool {
	var out map[string]bool
	for _, set := range sets {
		for id, skipped := range set {
			if !skipped {
				continue
			}
			if out == nil {
				out = make(map[string]bool)
			}
			out[id] = true
		}
	}
	return out
}

// noteServerError records one 5xx/transport failure for an account (P0-B) and
// returns (avoid-until, true) once the CONSECUTIVE streak reaches the
// threshold (the streak resets so recovery gets a fresh count after the cool).
// Below threshold → (zero, false): a transient blip cools nobody.
func (s *poolCooldownStore) noteServerError(accountID string) (time.Time, bool) {
	return s.noteServerErrorWithState(accountID, PoolAccountRouteState{
		Status: poolRouteUpstreamUnavailable,
	})
}

// noteServerErrorWithState is the reason-preserving variant used when the
// transport already classified a precise failure (notably per-account egress).
// Routing still depends only on the cooldown deadline; the extra state prevents
// the next request from being mislabeled as quota/rate-limit exhaustion.
func (s *poolCooldownStore) noteServerErrorWithState(accountID string, state PoolAccountRouteState) (time.Time, bool) {
	if accountID == "" {
		return time.Time{}, false
	}
	s.mu.Lock()
	if s.serverErrStreak == nil { // tests build the store literally; stay nil-safe
		s.serverErrStreak = make(map[string]int)
	}
	s.serverErrStreak[accountID]++
	if s.serverErrStreak[accountID] < serverErrStreakThreshold {
		s.mu.Unlock()
		return time.Time{}, false
	}
	delete(s.serverErrStreak, accountID)
	now := s.now()
	until := now.Add(serverErrCooldown)
	cur, existed := s.m[accountID]
	wasCooling := existed && now.Before(cur)
	if !existed || until.After(cur) {
		s.m[accountID] = until
		if s.meta == nil {
			s.meta = make(map[string]PoolAccountRouteState)
		}
		if state.Status == "" {
			state.Status = poolRouteUpstreamUnavailable
		}
		state.RetryAt = until.Unix()
		s.meta[accountID] = state
		s.persistLocked()
	}
	hook := s.onAccountSetChanged
	s.mu.Unlock()
	if !wasCooling && hook != nil {
		hook()
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

// mark keeps the historical generic entry point used by tests and callers that
// have no display classification. Routing behavior is identical; existing
// explanatory metadata, if any, is preserved.
func (s *poolCooldownStore) mark(accountID string, until time.Time) {
	s.markWithState(accountID, until, PoolAccountRouteState{})
}

// markWithState cools an account and records why the whole account is being
// skipped. A metadata-only change also wakes the projection even when the
// account was already cooling, so a transient limit that becomes confirmed
// window exhaustion is reflected without waiting for the next material pull.
func (s *poolCooldownStore) markWithState(accountID string, until time.Time, state PoolAccountRouteState) {
	s.markWithStateAndWindows(accountID, until, state, windowStatusSample{})
}

// markWithStateAndWindows atomically records routing cooldown, display cause
// and the replayable Master projection under one local lock. The extra state is
// best-effort metadata: request routing still depends only on m/accountID.
func (s *poolCooldownStore) markWithStateAndWindows(accountID string, until time.Time, state PoolAccountRouteState, windows windowStatusSample) {
	if accountID == "" {
		return
	}
	s.mu.Lock()
	now := s.now()
	if !until.After(now) {
		s.mu.Unlock()
		return
	}
	cur, existed := s.m[accountID]
	wasCooling := existed && now.Before(cur)
	metaChanged := false
	windowChanged := false
	if !existed || until.After(cur) {
		s.m[accountID] = until
	}
	if state.Status != "" {
		if s.meta == nil {
			s.meta = make(map[string]PoolAccountRouteState)
		}
		if prior, ok := s.meta[accountID]; !ok || prior != state {
			s.meta[accountID] = state
			metaChanged = true
		}
	}
	if windows.CredentialID != "" {
		windows = activeWindowStatusSample(windows, now)
		if windows.WindowStatus != "" || windows.Window7dStatus != "" {
			if s.windowStatuses == nil {
				s.windowStatuses = make(map[string]windowStatusSample)
			}
			merged := mergeWindowStatusSample(s.windowStatuses[accountID], windows)
			if prior, ok := s.windowStatuses[accountID]; !ok || prior != merged {
				s.windowStatuses[accountID] = merged
				windowChanged = true
			}
		}
	}
	if !existed || until.After(cur) || metaChanged || windowChanged {
		s.persistLocked()
	}
	hook := s.onAccountSetChanged
	s.mu.Unlock()
	if (!wasCooling || metaChanged || windowChanged) && hook != nil {
		hook()
	}
}

func activeWindowStatusSample(sample windowStatusSample, now time.Time) windowStatusSample {
	if sample.WindowResetAt <= now.Unix() {
		sample.WindowStatus = ""
		sample.WindowResetAt = 0
	}
	if sample.Window7dResetAt <= now.Unix() {
		sample.Window7dStatus = ""
		sample.Window7dResetAt = 0
	}
	return sample
}

func mergeWindowStatusSample(current, incoming windowStatusSample) windowStatusSample {
	if current.CredentialID == "" || current.CredentialID != incoming.CredentialID {
		current = windowStatusSample{CredentialID: incoming.CredentialID}
	}
	if incoming.WindowStatus != "" && incoming.WindowResetAt >= current.WindowResetAt {
		current.WindowStatus = incoming.WindowStatus
		current.WindowResetAt = incoming.WindowResetAt
	}
	if incoming.Window7dStatus != "" && incoming.Window7dResetAt >= current.Window7dResetAt {
		current.Window7dStatus = incoming.Window7dStatus
		current.Window7dResetAt = incoming.Window7dResetAt
	}
	return current
}

// windowStatusSnapshot is the reporter's idempotent reconcile read. It emits
// active persisted facts on every low-frequency tick and prunes expired window
// fields, so an outage/restart cannot strand Master behind the local truth.
func (s *poolCooldownStore) windowStatusSnapshot() []windowStatusSample {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	now := s.now()
	out := make([]windowStatusSample, 0, len(s.windowStatuses))
	changed := false
	for accountID, sample := range s.windowStatuses {
		active := activeWindowStatusSample(sample, now)
		if active.WindowStatus == "" && active.Window7dStatus == "" {
			delete(s.windowStatuses, accountID)
			changed = true
			continue
		}
		if active != sample {
			s.windowStatuses[accountID] = active
			changed = true
		}
		out = append(out, active)
	}
	if changed {
		s.persistLocked()
	}
	s.mu.Unlock()
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CredentialID < out[j].CredentialID })
	return out
}

// skipSet returns the accounts currently cooling down, for the resolver's `skip`
// argument. Lapsed entries are dropped. Returns nil when nothing is cooling
// (so the resolver's `skip[id]` lookups stay cheap).
func (s *poolCooldownStore) skipSet() map[string]bool {
	s.mu.Lock()
	now := s.now()
	var out map[string]bool
	pruned := false
	for id, until := range s.m {
		if now.Before(until) {
			if out == nil {
				out = make(map[string]bool)
			}
			out[id] = true
		} else {
			delete(s.m, id)
			delete(s.meta, id)
			delete(s.windowStatuses, id)
			if s.lapsed == nil {
				s.lapsed = make(map[string]struct{})
			}
			s.lapsed[id] = struct{}{}
			pruned = true
		}
	}
	hook := s.onAccountSetChanged
	s.mu.Unlock()
	if pruned && hook != nil {
		hook()
	}
	return out
}

// earliestRetryAfterSeconds returns the first active cooldown deadline among
// the route accounts currently skipped by the resolver. Round up so the client
// never retries in the final fractional second before the account is eligible.
// Expiry cleanup remains owned by skipSet; stale entries are simply ignored.
func (s *poolCooldownStore) earliestRetryAfterSeconds(routeIDs, skip map[string]bool) (int, bool) {
	seconds, _, _, ok := s.earliestRetryAdvice(routeIDs, skip)
	return seconds, ok
}

// earliestRetryAdvice returns the exact local routing deadline and display
// classification for the first route account that will re-enter. The cooldown
// deadline (not a database/window estimate) is authoritative for retry timing.
func (s *poolCooldownStore) earliestRetryAdvice(routeIDs, skip map[string]bool) (seconds int, retryAt int64, reason string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var earliest time.Time
	earliestID := ""
	for id := range routeIDs {
		if !skip[id] {
			continue
		}
		until, ok := s.m[id]
		if !ok || !now.Before(until) {
			continue
		}
		if earliest.IsZero() || until.Before(earliest) {
			earliest = until
			earliestID = id
		}
	}
	if earliest.IsZero() {
		return 0, 0, "", false
	}
	remaining := earliest.Sub(now)
	seconds = int((remaining + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	if state, exists := s.meta[earliestID]; exists {
		reason = state.Status
	}
	return seconds, earliest.Unix(), reason, true
}

// routeStateSnapshot returns the active whole-account display states. It uses
// the same expiry test as skipSet, so the UI cannot claim an account is still
// exhausted after routing has admitted it again. The returned map is detached.
func (s *poolCooldownStore) routeStateSnapshot() map[string]PoolAccountRouteState {
	s.mu.Lock()
	now := s.now()
	var out map[string]PoolAccountRouteState
	pruned := false
	for id, state := range s.meta {
		until, ok := s.m[id]
		if !ok || !now.Before(until) {
			delete(s.meta, id)
			delete(s.m, id)
			delete(s.windowStatuses, id)
			pruned = true
			continue
		}
		if out == nil {
			out = make(map[string]PoolAccountRouteState)
		}
		out[id] = state
	}
	hook := s.onAccountSetChanged
	s.mu.Unlock()
	if pruned && hook != nil {
		hook()
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
			if s.lapsed == nil {
				s.lapsed = make(map[string]struct{})
			}
			s.lapsed[strings.SplitN(key, "|", 2)[0]] = struct{}{}
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
			if s.lapsed == nil {
				s.lapsed = make(map[string]struct{})
			}
			s.lapsed[strings.SplitN(key, "|", 2)[0]] = struct{}{}
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
	now := s.now()
	var out map[string]int
	pruned := false
	for id, until := range s.m {
		if now.Before(until) {
			if out == nil {
				out = make(map[string]int)
			}
			out[id] = int(until.Sub(now).Seconds())
		} else {
			delete(s.m, id)
			delete(s.meta, id)
			delete(s.windowStatuses, id)
			if s.lapsed == nil {
				s.lapsed = make(map[string]struct{})
			}
			s.lapsed[id] = struct{}{}
			pruned = true
		}
	}
	hook := s.onAccountSetChanged
	s.mu.Unlock()
	if pruned && hook != nil {
		hook()
	}
	return out
}

// cooldownDecision classifies an upstream response: when the chosen pool account
// should be cooled down, returns (avoid-until, true). 401 → broken account.
// 429 with limit EVIDENCE → cool for the best reset we can read. A concrete
// exhausted window uses its window reset; an aggregate temporary limit uses
// Retry-After or the short fallback. 429 WITHOUT evidence (suspected WAF /
// business rejection) and everything else → (_, false).
func cooldownDecision(resp *http.Response, now time.Time) (time.Time, bool) {
	return cooldownDecisionWithTemporaryFallback(resp, now, poolCooldown429NoReset)
}

func cooldownDecisionWithTemporaryFallback(resp *http.Response, now time.Time, temporaryFallback time.Duration) (time.Time, bool) {
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
		// 2026-07-19): a concrete exhausted window may use its reset, while the
		// aggregate `rate_limited` status alone is transient and must not inherit
		// a representative reset that can be hours away. Evidence of limiting but
		// no actionable reset uses the short fallback.
		if temporaryFallback < poolCooldown429Min || temporaryFallback > poolCooldownMax {
			temporaryFallback = poolCooldown429NoReset
		}
		d := temporaryFallback
		authoritativeWindowReset := false
		if cx := codexRateLimitReset(resp.Header); cx > 0 {
			d = cx
		} else if ar := anthropicExhaustedWindowResetDuration(resp.Header, now); ar > 0 {
			d = ar
			authoritativeWindowReset = true
		} else if ra := retryAfterDuration(resp.Header); ra > 0 {
			d = ra
		}
		// The one-hour ceiling still applies to Codex reset-after durations and
		// generic Retry-After values. Only Anthropic's independently classified
		// concrete 5h/7d exhaustion carries an authoritative multi-day wall here;
		// treating every Codex reset header as that class bypassed the established
		// safety cap and broke TestCooldownDecision_CodexRateLimit.
		// Ref: workflow/CI/bugfix/2026-08-27-oauth-pool-quota-state-convergence.md.
		if !authoritativeWindowReset && d > poolCooldownMax {
			d = poolCooldownMax
		}
		return now.Add(d), true
	default:
		return time.Time{}, false
	}
}

type groupCooldownPolicy struct {
	TemporaryRateLimitCooldownSeconds *int `json:"temporary_rate_limit_cooldown_seconds"`
}

// groupTemporaryRateLimitCooldown reads the pool policy already carried on the
// existing routing_config rail. Missing config keeps upgraded pools on the
// product default. Invalid config returns an error so the request logger can
// surface the fallback instead of silently hiding control-plane drift.
func groupTemporaryRateLimitCooldown(routingConfig string) (time.Duration, error) {
	raw := strings.TrimSpace(routingConfig)
	if raw == "" {
		return poolCooldown429NoReset, nil
	}
	var policy groupCooldownPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return poolCooldown429NoReset, err
	}
	if policy.TemporaryRateLimitCooldownSeconds == nil {
		return poolCooldown429NoReset, nil
	}
	d := time.Duration(*policy.TemporaryRateLimitCooldownSeconds) * time.Second
	if d < poolCooldown429Min || d > poolCooldownMax {
		return poolCooldown429NoReset, fmt.Errorf("temporary_rate_limit_cooldown_seconds must be between 1 and 3600")
	}
	return d, nil
}

// groupTemporaryRateLimitCooldownForResponse keeps policy parsing and its WARN
// on the one response class that consumes the setting. A malformed policy must
// not spam successful requests and must not block the serving path.
func groupTemporaryRateLimitCooldownForResponse(
	status int,
	routingConfig, oauthGroupID string,
	logger *slog.Logger,
) time.Duration {
	if status != http.StatusTooManyRequests {
		return poolCooldown429NoReset
	}
	d, err := groupTemporaryRateLimitCooldown(routingConfig)
	if err == nil {
		return d
	}
	logger.Warn("pool routing config is invalid; using temporary rate-limit cooldown default",
		"event.name", observability.EventProxyGroupRoutingConfigInvalid,
		"oauth_group_id", oauthGroupID,
		"error", err.Error())
	return d
}

// cooldownRouteState classifies the already-approved whole-account cooldown for
// display. It never participates in routing; cooldownDecision + the store's
// avoid-until remain authoritative. For confirmed window exhaustion, RetryAt
// prefers the provider's actual reset evidence even when routing caps the local
// cooldown duration as a safety valve.
func cooldownRouteState(resp *http.Response, now, cooldownUntil time.Time) PoolAccountRouteState {
	state := PoolAccountRouteState{RetryAt: cooldownUntil.Unix()}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		state.Status = poolRouteAuthFailed
	case 529:
		state.Status = poolRouteUpstreamUnavailable
	case http.StatusTooManyRequests:
		state.Status = poolRouteRateLimited
		if windowExhaustionEvidence(resp.Header) {
			state.Status = poolRouteWindowExhausted
			if d := codexRateLimitReset(resp.Header); d > 0 {
				state.RetryAt = now.Add(d).Unix()
			} else if d := anthropicExhaustedWindowResetDuration(resp.Header, now); d > 0 {
				state.RetryAt = now.Add(d).Unix()
			}
		}
	default:
		state.Status = poolRouteUpstreamUnavailable
	}
	return state
}

// windowExhaustionEvidence is narrower than hasRateLimitSignal: Retry-After by
// itself is a transient throttling hint, not proof that a quota window is full.
// The Mock Provider and real upstreams expose 100%-used/status evidence here.
func windowExhaustionEvidence(h http.Header) bool {
	if anthropicWindowExhausted(h, "5h") || anthropicWindowExhausted(h, "7d") {
		return true
	}
	return codexHeaderFloat(h, "x-codex-primary-used-percent") >= 100 ||
		codexHeaderFloat(h, "x-codex-secondary-used-percent") >= 100
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

// anthropicExhaustedWindowResetDuration derives the cooldown only from concrete
// exhausted 5h/7d windows. The aggregate unified reset is accepted solely as a
// compatibility fallback for a window already proven exhausted; it must never
// turn aggregate `rate_limited` telemetry into an hours-long account removal.
// Returns 0 when no window is exhausted or no future reset is readable, so the
// caller can honor Retry-After or use the short transient fallback.
func anthropicExhaustedWindowResetDuration(h http.Header, now time.Time) time.Duration {
	var best time.Time
	if anthropicWindowExhausted(h, "5h") {
		if t := anthropicWindowResetTime(h, "5h", now); t.After(best) {
			best = t
		}
	}
	if anthropicWindowExhausted(h, "7d") {
		if t := anthropicWindowResetTime(h, "7d", now); t.After(best) {
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

// consumeLapsed reports (and clears) whether accountID's cooldown was observed
// to expire since the last consumption — the scheduling-log settle hook turns
// this into a route_resolved(reason=recovered) row. One-shot by design: the
// recovery is attributed to the first request that resumes the account.
func (s *poolCooldownStore) consumeLapsed(accountID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.lapsed[accountID]; ok {
		delete(s.lapsed, accountID)
		return true
	}
	return false
}
