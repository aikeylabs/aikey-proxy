package proxy

// Fence for R-oauth-account-pool-4.2 on the seat path (task T3-1.2): the time a
// member is told the pool will be usable again must be the moment routing
// really lets an account back in.
//
// One account is kept out until the LATER of two deadlines: the Worker's own
// cooldown (the store's avoid-until, which is the routing truth, never the
// display-only RetryAt) and the master-delivered window wall
// (vkeys.MaterialWindowBlockedUntil, the judgment the picker applies). A
// delivered window exhausted with no reset keeps the account out with no known
// time, and the later of a deadline and "unknown" is unknown, so such an account
// never contributes a time. The pool advertises the EARLIEST account time.
//
// Every fixture row is checked at the single exit (accountRecovery), at both of
// its consumers (earliestRetryAdvice, routeAccountStates) and on the member's
// real request path: the GROUP_ALL_UNUSABLE 429's Retry-After, retry_at,
// retry_reason and per-account lines. The message wording belongs to task 1.3
// and is not asserted here.
//
// Only a TEMPORARILY unavailable account carries a time: a credential that is
// dead for this member (the upstream rejected this seat's token, the member has
// no token, or the access token expired) re-admits nobody when a gate reopens,
// so neither gate counts for it — the rows F1a/F1b/F1b-swap/F1c are the review
// probes of that case (fix round 1, Ruling-70/71). The pool's reason is the
// earliest account's, and an exact tie goes to window_exhausted, never to map
// iteration order (Ruling-72).
//
// Guards (rule R-oauth-account-pool-4.2 in
// workflow/CI/requirements/2026-06-23-oauth-account-pool.md;
// scenario tables in roadmap20260320/技术实现/update/
// 20260924-Codex冷却例外补全与提示显示恢复时间.md):
//   - R-oauth-account-pool-4.2 the told time is the time routing really releases an account
//   - R-oauth-account-pool-4.2.S1 local cooldown and delivered wall: the later wins
//   - R-oauth-account-pool-4.2.S3 seat path with a local cooldown: the earliest account
//   - R-oauth-account-pool-4.2.S4 seat path held only by delivered state still gets a time
//
// Run: cd aikey-proxy && GOWORK=off go test ./internal/proxy -run '^TestEarliestRetryAdvice_TakesLaterOfLocalAndDelivered$' -count=1

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// recoveryCard is one pool account of a fixture; durations are offsets from the
// test clock.
type recoveryCard struct {
	id string
	// local is the Worker's own cooldown still to run (0 = none) and localStatus
	// the reason recorded with it. shownIn is the display RetryAt recorded with
	// it (0 = same as local): a capped Codex cooldown shows the provider's raw
	// reset there, which is display-only and must never become the told time.
	local       time.Duration
	localStatus string
	shownIn     time.Duration
	// fiveHour and sevenDay are the master-delivered windows.
	fiveHour, sevenDay deliveredWindow
	// expiredAgo > 0: the delivered access token expired this long ago.
	// revoked: the upstream already rejected this seat's current token (a
	// hard-revoke tombstone on this Worker). Either makes the credential dead.
	expiredAgo time.Duration
	revoked    bool
}

// deliveredWindow is one master-delivered window. The zero value is a window
// that is not exhausted; exhausted with resetIn 0 is "exhausted, no reset
// delivered".
type deliveredWindow struct {
	exhausted bool
	resetIn   time.Duration
}

func exhaustedFor(d time.Duration) deliveredWindow {
	return deliveredWindow{exhausted: true, resetIn: d}
}

var exhaustedNoReset = deliveredWindow{exhausted: true}

func (w deliveredWindow) fields(now time.Time) (status string, resetAt *int64) {
	if !w.exhausted {
		return "", nil
	}
	if w.resetIn > 0 {
		at := now.Add(w.resetIn).Unix()
		resetAt = &at
	}
	return windowStatusExhausted, resetAt
}

// material is the card's delivered runtime entry, secrets excluded.
func (c recoveryCard) material(now time.Time) vkeys.GroupRuntimeAccount {
	m := vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-" + c.id}
	if c.expiredAgo > 0 {
		m.ExpiresAt = now.Add(-c.expiredAgo).Unix()
	}
	m.WindowStatus, m.WindowResetAt = c.fiveHour.fields(now)
	m.Window7dStatus, m.Window7dResetAt = c.sevenDay.fields(now)
	return m
}

// cardRecovery is a recovery answer: for one card what accountRecovery must
// return, for the pool what earliestRetryAdvice must return.
type cardRecovery struct {
	in     time.Duration // kept out until now+in; 0 = no time to promise
	reason string        // "" = nothing keeps it out
}

// at is the instant the answer promises; the zero time when there is none.
func (c cardRecovery) at(now time.Time) time.Time {
	if c.in == 0 {
		return time.Time{}
	}
	return now.Add(c.in)
}

// retryAt is the wire form of at: unix seconds, 0 (omitted) when there is none.
func (c cardRecovery) retryAt(now time.Time) int64 {
	if c.in == 0 {
		return 0
	}
	return now.Add(c.in).Unix()
}

func TestEarliestRetryAdvice_TakesLaterOfLocalAndDelivered(t *testing.T) {
	const exhausted = poolRouteWindowExhausted
	rows := []struct {
		name  string
		cards []recoveryCard
		pool  cardRecovery // the pool's earliest recovery; zero = no time to advertise
		want  map[string]cardRecovery
	}{
		{
			name: "local only: the routing deadline, not the display's raw reset",
			cards: []recoveryCard{
				{id: "acc-a", local: time.Hour, localStatus: exhausted, shownIn: 3 * time.Hour},
			},
			pool: cardRecovery{time.Hour, exhausted},
			want: map[string]cardRecovery{"acc-a": {time.Hour, exhausted}},
		},
		{
			name: "delivered only: a card this Worker never hit still has a time",
			cards: []recoveryCard{
				{id: "acc-a", fiveHour: exhaustedFor(2 * time.Hour)},
			},
			pool: cardRecovery{2 * time.Hour, exhausted},
			want: map[string]cardRecovery{"acc-a": {2 * time.Hour, exhausted}},
		},
		{
			name: "S1 local 1h and delivered 3h: 3h, never 1h",
			cards: []recoveryCard{
				{id: "acc-a", local: time.Hour, localStatus: exhausted, shownIn: 3 * time.Hour, fiveHour: exhaustedFor(3 * time.Hour)},
			},
			pool: cardRecovery{3 * time.Hour, exhausted},
			want: map[string]cardRecovery{"acc-a": {3 * time.Hour, exhausted}},
		},
		{
			name: "local later than the delivered wall: the local deadline and its reason",
			cards: []recoveryCard{
				{id: "acc-a", local: 45 * time.Minute, localStatus: poolRouteRateLimited, fiveHour: exhaustedFor(20 * time.Minute)},
			},
			pool: cardRecovery{45 * time.Minute, poolRouteRateLimited},
			want: map[string]cardRecovery{"acc-a": {45 * time.Minute, poolRouteRateLimited}},
		},
		{
			name: "a tie goes to the delivered wall",
			cards: []recoveryCard{
				{id: "acc-a", local: time.Hour, localStatus: poolRouteRateLimited, fiveHour: exhaustedFor(time.Hour)},
			},
			pool: cardRecovery{time.Hour, exhausted},
			want: map[string]cardRecovery{"acc-a": {time.Hour, exhausted}},
		},
		{
			name: "both windows full: the later reset",
			cards: []recoveryCard{
				{id: "acc-a", fiveHour: exhaustedFor(time.Hour), sevenDay: exhaustedFor(72 * time.Hour)},
			},
			pool: cardRecovery{72 * time.Hour, exhausted},
			want: map[string]cardRecovery{"acc-a": {72 * time.Hour, exhausted}},
		},
		{
			name: "S3 A cools locally for 3h, B is held by the delivered state for 20 min: 20 min",
			cards: []recoveryCard{
				{id: "acc-a", local: 3 * time.Hour, localStatus: exhausted},
				{id: "acc-b", fiveHour: exhaustedFor(20 * time.Minute)},
			},
			pool: cardRecovery{20 * time.Minute, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {3 * time.Hour, exhausted},
				"acc-b": {20 * time.Minute, exhausted},
			},
		},
		{
			name: "S4 nothing cools locally, every card is held by the delivered state: the earliest reset",
			cards: []recoveryCard{
				{id: "acc-a", fiveHour: exhaustedFor(2 * time.Hour)},
				{id: "acc-b", sevenDay: exhaustedFor(5 * time.Hour)},
			},
			pool: cardRecovery{2 * time.Hour, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {2 * time.Hour, exhausted},
				"acc-b": {5 * time.Hour, exhausted},
			},
		},
		{
			name: "a card exhausted without a reset takes no part",
			cards: []recoveryCard{
				{id: "acc-a", fiveHour: exhaustedNoReset},
				{id: "acc-b", fiveHour: exhaustedFor(2 * time.Hour)},
			},
			pool: cardRecovery{2 * time.Hour, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {0, exhausted},
				"acc-b": {2 * time.Hour, exhausted},
			},
		},
		{
			name: "every card exhausted without a reset: no time at all",
			cards: []recoveryCard{
				{id: "acc-a", fiveHour: exhaustedNoReset},
				{id: "acc-b", sevenDay: exhaustedNoReset},
			},
			want: map[string]cardRecovery{
				"acc-a": {0, exhausted},
				"acc-b": {0, exhausted},
			},
		},
		{
			// T3-1.1 review I2, option A': the discriminating row. Reading
			// RecoversAt == 0 as "not blocked" would fall back to the local hour.
			name: "local 1h plus a reset-less delivered window: the card takes no part, the pool never says 1h",
			cards: []recoveryCard{
				{id: "acc-a", local: time.Hour, localStatus: poolRouteRateLimited, fiveHour: exhaustedNoReset},
				{id: "acc-b", fiveHour: exhaustedFor(3 * time.Hour)},
			},
			pool: cardRecovery{3 * time.Hour, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {0, exhausted},
				"acc-b": {3 * time.Hour, exhausted},
			},
		},
		{
			name: "the same card alone: no time rather than 1h",
			cards: []recoveryCard{
				{id: "acc-a", local: time.Hour, localStatus: poolRouteRateLimited, fiveHour: exhaustedNoReset},
			},
			want: map[string]cardRecovery{"acc-a": {0, exhausted}},
		},
		// The pool's reason is the EARLIEST account's (review M1): 1.3b picks
		// the Codex usage-limit shape from it, a one-way door. Both directions,
		// and an exact tie, which goes to window_exhausted (Ruling-72). The tie
		// row puts the rate-limited card first in id order on purpose, so
		// "first in sorted order wins" is red too.
		{
			name: "M1 A rate-limited 45m locally, B delivered 20m: B's time and B's reason",
			cards: []recoveryCard{
				{id: "acc-a", local: 45 * time.Minute, localStatus: poolRouteRateLimited},
				{id: "acc-b", fiveHour: exhaustedFor(20 * time.Minute)},
			},
			pool: cardRecovery{20 * time.Minute, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {45 * time.Minute, poolRouteRateLimited},
				"acc-b": {20 * time.Minute, exhausted},
			},
		},
		{
			name: "M1 A rate-limited 20m locally, B delivered 45m: A's time and A's reason",
			cards: []recoveryCard{
				{id: "acc-a", local: 20 * time.Minute, localStatus: poolRouteRateLimited},
				{id: "acc-b", fiveHour: exhaustedFor(45 * time.Minute)},
			},
			pool: cardRecovery{20 * time.Minute, poolRouteRateLimited},
			want: map[string]cardRecovery{
				"acc-a": {20 * time.Minute, poolRouteRateLimited},
				"acc-b": {45 * time.Minute, exhausted},
			},
		},
		{
			name: "M1 A rate-limited and B delivered, both at 20m: window_exhausted wins the tie",
			cards: []recoveryCard{
				{id: "acc-a", local: 20 * time.Minute, localStatus: poolRouteRateLimited},
				{id: "acc-b", fiveHour: exhaustedFor(20 * time.Minute)},
			},
			pool: cardRecovery{20 * time.Minute, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {20 * time.Minute, poolRouteRateLimited},
				"acc-b": {20 * time.Minute, exhausted},
			},
		},
		{
			// A tie between two other reasons must be just as deterministic;
			// the first account id in sorted order keeps it.
			name: "M1 two other reasons tie at 20m: the same answer on every call (first account id)",
			cards: []recoveryCard{
				{id: "acc-a", local: 20 * time.Minute, localStatus: poolRouteRateLimited},
				{id: "acc-b", local: 20 * time.Minute, localStatus: poolRouteWindowProtected},
			},
			pool: cardRecovery{20 * time.Minute, poolRouteRateLimited},
			want: map[string]cardRecovery{
				"acc-a": {20 * time.Minute, poolRouteRateLimited},
				"acc-b": {20 * time.Minute, poolRouteWindowProtected},
			},
		},
		// A credential that is dead for this member takes no part (review I1,
		// Ruling-70/71). Fixtures are the review probes (probe-f1-f2.txt): at
		// the 20 minutes the pre-fix answer promised, F1a answers a login prompt
		// and F1b-swap another 429 for 3 hours — the told time was never a
		// release. The dead card's line keeps its status and carries no time.
		{
			name: "F1a A's token for this seat was rejected, A held 20m by the delivered state, B 3h: 3h",
			cards: []recoveryCard{
				{id: "acc-a", fiveHour: exhaustedFor(20 * time.Minute), revoked: true},
				{id: "acc-b", fiveHour: exhaustedFor(3 * time.Hour)},
			},
			pool: cardRecovery{3 * time.Hour, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {0, poolRouteRevokedToken},
				"acc-b": {3 * time.Hour, exhausted},
			},
		},
		{
			name: "F1b A's access token expired, A held 20m by the delivered state, B 3h: 3h",
			cards: []recoveryCard{
				{id: "acc-a", expiredAgo: time.Minute, fiveHour: exhaustedFor(20 * time.Minute)},
				{id: "acc-b", fiveHour: exhaustedFor(3 * time.Hour)},
			},
			pool: cardRecovery{3 * time.Hour, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {0, exhausted},
				"acc-b": {3 * time.Hour, exhausted},
			},
		},
		{
			name: "F1b-swap the expired card is not the seat's first-ranked one: 3h",
			cards: []recoveryCard{
				{id: "acc-b", expiredAgo: time.Minute, fiveHour: exhaustedFor(20 * time.Minute)},
				{id: "acc-a", fiveHour: exhaustedFor(3 * time.Hour)},
			},
			pool: cardRecovery{3 * time.Hour, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {3 * time.Hour, exhausted},
				"acc-b": {0, exhausted},
			},
		},
		{
			// Existed before this task on the local side: the rejected card's
			// own cooldown used to set the pool's time.
			name: "F1c A's token rejected while A cools locally 20m, B cools locally 3h: 3h",
			cards: []recoveryCard{
				{id: "acc-a", local: 20 * time.Minute, localStatus: poolRouteRateLimited, revoked: true},
				{id: "acc-b", local: 3 * time.Hour, localStatus: exhausted},
			},
			pool: cardRecovery{3 * time.Hour, exhausted},
			want: map[string]cardRecovery{
				"acc-a": {0, poolRouteRevokedToken},
				"acc-b": {3 * time.Hour, exhausted},
			},
		},
	}

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			// A whole second, so Retry-After and retry_at are exact. The picker
			// judges the delivered windows on the real clock, which is at most a
			// second ahead: every wall below is at least 20 minutes away.
			now := time.Unix(time.Now().Unix(), 0)
			key := grKey()
			refs := make([]vkeys.GroupAccountRef, 0, len(tc.cards))
			plain := make(map[string]vkeys.GroupRuntimeAccount, len(tc.cards))
			delivered := make(map[string]vkeys.GroupRuntimeAccount, len(tc.cards))
			for _, c := range tc.cards {
				refs = append(refs, vkeys.GroupAccountRef{AccountID: c.id, ProviderCode: "anthropic"})
				plain[c.id] = c.material(now)
				delivered[c.id] = encMat(t, key, plain[c.id], "tok-"+c.id)
			}
			route := &vkeys.ResolvedRoute{
				VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
				ProviderCode: "anthropic", RouteSource: "team",
				SeatID: "seat-1", OauthGroupID: "grp-1",
				GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, delivered),
			}
			p, tr := setupGroupProxy(t, key, route)
			store := p.poolCooldown
			store.now = func() time.Time { return now }
			for _, c := range tc.cards {
				if c.local == 0 {
					continue
				}
				shown := c.shownIn
				if shown == 0 {
					shown = c.local
				}
				store.markWithState(c.id, now.Add(c.local), PoolAccountRouteState{Status: c.localStatus, RetryAt: now.Add(shown).Unix()})
			}
			for _, c := range tc.cards {
				if c.revoked {
					// What the request path records when the upstream rejects
					// this seat's token for good (the delivered token is "tok-<id>").
					store.markAuthFailedToken(route.OauthGroupID, route.SeatID, c.id, oauthTokenFingerprint("tok-"+c.id))
				}
			}

			// 1. The single exit, card by card, as the seat path asks it (with
			// the member's seat, so its tombstones count). The public entry has
			// no seat: for every card without a tombstone it must agree.
			for _, c := range tc.cards {
				want := tc.want[c.id]
				store.mu.Lock()
				at, reason, ok := store.accountRecoveryLocked(c.id, plain[c.id], true, route.OauthGroupID, route.SeatID, store.now())
				store.mu.Unlock()
				if ok != (want.in > 0) || !at.Equal(want.at(now)) || reason != want.reason {
					t.Errorf("accountRecovery(%s) for this seat = (%s, %q, ok=%v), want (%s, %q)",
						c.id, recoveryOffset(at, now), reason, ok, recoveryOffset(want.at(now), now), want.reason)
				}
				if c.revoked {
					continue
				}
				if pubAt, pubReason, pubOK := store.accountRecovery(c.id, plain[c.id], true); pubOK != ok || !pubAt.Equal(at) || pubReason != reason {
					t.Errorf("accountRecovery(%s) public entry = (%s, %q, ok=%v), want the seat's answer (%s, %q, ok=%v)",
						c.id, recoveryOffset(pubAt, now), pubReason, pubOK, recoveryOffset(at, now), reason, ok)
				}
			}

			// 2. Consumer one: the pool fold behind Retry-After and retry_at.
			// Asked repeatedly: map iteration order changes from call to call, and
			// the answer — above all the reason, which 1.3b turns into a wire
			// shape — must not.
			wantSeconds := int(tc.pool.in / time.Second)
			for i := 0; i < 32; i++ {
				seconds, retryAt, reason, ok := store.earliestRetryAdvice(groupRouteAccountIDs(route), plain, route.OauthGroupID, route.SeatID)
				if ok != (tc.pool.in > 0) || seconds != wantSeconds || retryAt != tc.pool.retryAt(now) || reason != tc.pool.reason {
					t.Errorf("earliestRetryAdvice call %d = (%ds, retry_at %s, %q, ok=%v), want (%ds, retry_at %s, %q)",
						i+1, seconds, unixOffset(retryAt, now), reason, ok, wantSeconds, unixOffset(tc.pool.retryAt(now), now), tc.pool.reason)
					break
				}
			}

			// 3. Consumer two: the per-account lines read the same per-card time.
			lines := map[string]poolAccountStateView{}
			for _, v := range store.routeAccountStates(route, groupRouteAccountIDs(route)) {
				lines[v.AccountID] = v
			}
			for _, c := range tc.cards {
				want := tc.want[c.id]
				if got := lines[c.id]; got.Status != want.reason || got.RetryAt != want.retryAt(now) {
					t.Errorf("routeAccountStates line for %s = status %q retry_at %s, want status %q retry_at %s",
						c.id, got.Status, unixOffset(got.RetryAt, now), want.reason, unixOffset(want.retryAt(now), now))
				}
			}

			// 4. The member's request on the seat path.
			req, w := groupReq(groupBody)
			p.Handle(w, req)
			var body struct {
				Error struct {
					Code              string                 `json:"code"`
					RetryAfterSeconds *int                   `json:"retry_after_seconds"`
					RetryAt           *int64                 `json:"retry_at"`
					RetryReason       string                 `json:"retry_reason"`
					Accounts          []poolAccountStateView `json:"accounts"`
				} `json:"error"`
			}
			if w.Code != http.StatusTooManyRequests || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error.Code != groupErrAllUnusable {
				t.Fatalf("every card is held: want 429 %s, got %d: %s", groupErrAllUnusable, w.Code, w.Body.String())
			}
			if tr.calls != 0 {
				t.Fatalf("a held pool must not reach the upstream, calls=%d", tr.calls)
			}
			header := w.Header().Get("Retry-After")
			if tc.pool.in == 0 {
				if header != "" || body.Error.RetryAt != nil {
					t.Fatalf("no time exists to promise, yet Retry-After=%q (retry_at present: %v): %s", header, body.Error.RetryAt != nil, w.Body.String())
				}
				return
			}
			if header != strconv.Itoa(wantSeconds) ||
				body.Error.RetryAfterSeconds == nil || *body.Error.RetryAfterSeconds != wantSeconds ||
				body.Error.RetryAt == nil || *body.Error.RetryAt != tc.pool.retryAt(now) ||
				body.Error.RetryReason != tc.pool.reason {
				t.Fatalf("seat-path 429 Retry-After=%q, want %d with retry_at %s and retry_reason %q: %s",
					header, wantSeconds, unixOffset(tc.pool.retryAt(now), now), tc.pool.reason, w.Body.String())
			}
			onWire := map[string]poolAccountStateView{}
			for _, v := range body.Error.Accounts {
				onWire[v.AccountID] = v
			}
			for _, c := range tc.cards {
				want := tc.want[c.id]
				if got := onWire[c.id]; got.Status != want.reason || got.RetryAt != want.retryAt(now) {
					t.Errorf("429 accounts line for %s = status %q retry_at %s, want status %q retry_at %s",
						c.id, got.Status, unixOffset(got.RetryAt, now), want.reason, unixOffset(want.retryAt(now), now))
				}
			}
		})
	}

	// hasMat=false is how a caller that reads the delivered state itself asks
	// (the device path passes nil material): only a live local cooldown counts.
	t.Run("without delivered material only a live local cooldown counts", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0)
		s := &poolCooldownStore{m: map[string]time.Time{}, meta: map[string]PoolAccountRouteState{}, now: func() time.Time { return now }}
		held := recoveryCard{id: "acc-a", fiveHour: exhaustedFor(3 * time.Hour)}.material(now)
		s.markWithState("acc-a", now.Add(time.Hour), PoolAccountRouteState{Status: poolRouteWindowExhausted, RetryAt: now.Add(3 * time.Hour).Unix()})
		if at, reason, ok := s.accountRecovery("acc-a", held, false); !ok || !at.Equal(now.Add(time.Hour)) || reason != poolRouteWindowExhausted {
			t.Fatalf("no material: accountRecovery = (%s, %q, ok=%v), want the local hour", recoveryOffset(at, now), reason, ok)
		}
		if seconds, _, _, ok := s.earliestRetryAdvice(map[string]bool{"acc-a": true}, nil, "", ""); !ok || seconds != 3600 {
			t.Fatalf("nil material: earliestRetryAdvice = (%ds, ok=%v), want the local 3600s", seconds, ok)
		}
		// An entry past its deadline that skipSet has not pruned yet is no cooldown.
		s.m["acc-b"] = now.Add(-time.Minute)
		s.meta["acc-b"] = PoolAccountRouteState{Status: poolRouteRateLimited}
		if at, reason, ok := s.accountRecovery("acc-b", vkeys.GroupRuntimeAccount{}, true); ok || !at.IsZero() || reason != "" {
			t.Fatalf("expired local cooldown: accountRecovery = (%s, %q, ok=%v), want nothing keeping it out", recoveryOffset(at, now), reason, ok)
		}
		if _, _, _, ok := s.earliestRetryAdvice(map[string]bool{"acc-b": true}, nil, "", ""); ok {
			t.Fatal("an expired local cooldown must not produce a retry time")
		}
	})

	// The public entry (what task 1.4 calls) has no seat, so it cannot see a
	// seat's tombstone; it still reads the material's own credential. An
	// expired or needs-login account keeps its status and never gets a time,
	// even with a live local cooldown.
	t.Run("the public entry never times a dead credential in the material", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0)
		s := &poolCooldownStore{m: map[string]time.Time{}, meta: map[string]PoolAccountRouteState{}, now: func() time.Time { return now }}
		s.markWithState("acc-a", now.Add(20*time.Minute), PoolAccountRouteState{Status: poolRouteRateLimited, RetryAt: now.Add(20 * time.Minute).Unix()})
		expired := recoveryCard{id: "acc-a", expiredAgo: time.Minute, fiveHour: exhaustedFor(3 * time.Hour)}.material(now)
		if at, reason, ok := s.accountRecovery("acc-a", expired, true); ok || !at.IsZero() || reason != poolRouteWindowExhausted {
			t.Fatalf("expired token: accountRecovery = (%s, %q, ok=%v), want no time and the window's status", recoveryOffset(at, now), reason, ok)
		}
		needsLogin := vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", NeedsLogin: true}
		if at, reason, ok := s.accountRecovery("acc-a", needsLogin, true); ok || !at.IsZero() || reason != poolRouteRateLimited {
			t.Fatalf("needs login: accountRecovery = (%s, %q, ok=%v), want no time and the local status", recoveryOffset(at, now), reason, ok)
		}
	})
}

// recoveryOffset renders a recovery time relative to the test clock for
// failure output.
func recoveryOffset(at, now time.Time) string {
	if at.IsZero() {
		return "no time"
	}
	return "+" + at.Sub(now).String()
}

// unixOffset is recoveryOffset for a wire retry_at (unix seconds, 0 = none).
func unixOffset(retryAt int64, now time.Time) string {
	if retryAt == 0 {
		return "no time"
	}
	return recoveryOffset(time.Unix(retryAt, 0), now)
}
