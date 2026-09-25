package proxy

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// ① GROUP_ALL_UNUSABLE must name each blocked account and why (2026-09-03).
// The proxy held every fact (cooldown reason + retry_at, auth tombstone,
// identity) and told the member only "retried in N seconds".
// bugfix: workflow/CI/bugfix/2026-09-03-池全部不可用不说哪个账号为什么.md
func TestRouteAccountStatesNamesCooldownsAndTombstones(t *testing.T) {
	s := newPoolCooldownStore()
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	material, _ := json.Marshal(map[string]vkeys.GroupRuntimeAccount{
		"acct-cool": {Identity: "cool@example.com"},
		"acct-dead": {Identity: "dead@example.com"},
		"acct-ok":   {Identity: "ok@example.com"},
	})
	route := &vkeys.ResolvedRoute{OauthGroupID: "g1", SeatID: "s1", GroupRuntime: string(material)}
	s.m["acct-cool"] = now.Add(90 * time.Second)
	s.meta["acct-cool"] = PoolAccountRouteState{Status: poolRouteRateLimited}
	s.authFailedTokens[authFailureRouteKey("g1", "s1", "acct-dead")] = "deadbeef"

	got := s.routeAccountStates(route, map[string]bool{"acct-cool": true, "acct-dead": true, "acct-ok": true})
	if len(got) != 2 {
		t.Fatalf("only accounts with a local verdict are listed, got %+v", got)
	}
	byID := map[string]poolAccountStateView{}
	for _, v := range got {
		byID[v.AccountID] = v
	}
	if v := byID["acct-cool"]; v.Status != poolRouteRateLimited || v.RetryAt != now.Add(90*time.Second).Unix() || v.Identity != "cool@example.com" {
		t.Fatalf("cooldown account must carry reason + retry_at + identity: %+v", v)
	}
	if v := byID["acct-dead"]; v.Status != "revoked_token" || v.RetryAt != 0 || v.Identity != "dead@example.com" {
		t.Fatalf("tombstoned account must read revoked_token with no retry clock: %+v", v)
	}
	text := describePoolAccountStates(got)
	for _, want := range []string{"cool@example.com: rate_limited (retry at ", "dead@example.com: token rejected upstream", "sign in again to get a NEW token"} {
		if !strings.Contains(text, want) {
			t.Fatalf("member-facing clause missing %q in %q", want, text)
		}
	}
	if strings.Contains(text, "deadbeef") {
		t.Fatal("a fingerprint must never reach the member-facing text")
	}
}

// A correct accessor nobody calls is the defect shape this repo keeps hitting,
// so the fence also lands on the 429 call site.
func TestGroupAllUnusableResponseCarriesTheAccountDetail(t *testing.T) {
	src, err := os.ReadFile("group_serve.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func (p *Proxy) degradeGroupWithRetry(")
	end := strings.Index(body[start:], "\n}\n")
	fn := body[start : start+end]
	for _, want := range []string{
		"p.poolCooldown.routeAccountStates(route, groupRouteAccountIDs(route))",
		"describePoolAccountStates(accounts)",
		`"accounts":            accounts,`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("degradeGroupWithRetry dropped %q — the 429 is back to an anonymous retry timer", want)
		}
	}
}

// A member refused because every pool account is temporarily out must read WHEN
// in the 429 text, and it must be the time the header and retry_at carry: one
// value in three places (R-oauth-account-pool-4.2). The text's instant is
// retry_at verbatim — a whole second, the deadline rounded down, the same second
// the per-account lines print — and its duration is retry_after_seconds, the
// Retry-After header's own number (the remaining time rounded up). Both
// roundings stay as they were (Ruling-76, 2026-09-25).
//
// Rows: S3 (an account cooling locally for hours must not set the time), S4 (a
// pool held only by the delivered state — every account used up by OTHER
// members — still gets a time, not the generic sentence), a deadline inside a
// second, the one row where the two roundings differ: change either rounding
// alone, or derive the text's time any other way, and it turns red — and an
// account whose token this seat saw rejected: the text's time is the advice the
// header got, judged with the seat, never asked again without it.
//
// Two more rows (review M1 / M2, fix round 1): with no time known the approved
// sentence stays word for word and nothing is promised; and the instant prints
// in UTC with a Z whatever zone the machine runs in — on a UTC machine a text
// printed in local time looks the same, so that row forces a non-UTC zone.
//
// Guards (rule R-oauth-account-pool-4.2 in
// workflow/CI/requirements/2026-06-23-oauth-account-pool.md; scenarios in
// roadmap20260320/技术实现/update/20260924-Codex冷却例外补全与提示显示恢复时间.md):
//   - R-oauth-account-pool-4.2.S3 seat path with a local cooldown: the text names the earliest account's time
//   - R-oauth-account-pool-4.2.S4 seat path held only by the delivered state: a time, not the generic sentence
//
// Run: cd aikey-proxy && GOWORK=off go test ./internal/proxy -run '^TestGroupAllUnusable_HintCarriesRecoveryTime$' -count=1
func TestGroupAllUnusable_HintCarriesRecoveryTime(t *testing.T) {
	// First, before any proxy of this test is up: it swaps the process-wide
	// time.Local, which is only safe while nothing else reads it (no test in
	// this package runs in parallel). With Local = UTC, dropping .UTC() from the
	// text would print the same "Z", so the zone here must not be UTC.
	t.Run("the instant prints in UTC with a Z whatever the machine's zone", func(t *testing.T) {
		saved := time.Local
		time.Local = time.FixedZone("UTC-4", -4*3600)
		t.Cleanup(func() { time.Local = saved })
		if got, want := recoveryHint(7200, 1_790_000_000), "about 2 h (2026-09-21T14:13:20Z)"; got != want {
			t.Fatalf("recoveryHint = %q, want %q", got, want)
		}
	})

	rows := []struct {
		name  string
		cards []recoveryCard
		// earliest is the account the pool's time comes from; seconds is
		// Retry-After and retry_after_seconds; retry_at is now+retryIn; duration
		// is the text's "about <duration>".
		earliest string
		seconds  int
		retryIn  time.Duration
		duration string
		notSaid  string // BUT NOT
	}{
		{
			name: "S3 an account cooling locally for hours does not set the time",
			cards: []recoveryCard{
				{id: "acc-a", local: 3 * time.Hour, localStatus: poolRouteWindowExhausted},
				{id: "acc-b", fiveHour: exhaustedFor(20 * time.Minute)},
			},
			earliest: "acc-b", seconds: 1200, retryIn: 20 * time.Minute, duration: "20 min",
			notSaid: "about 3 h",
		},
		{
			name: "S4 held only by the delivered state: a time, not the generic sentence",
			cards: []recoveryCard{
				{id: "acc-a", fiveHour: exhaustedFor(3 * time.Hour)},
				{id: "acc-b", fiveHour: exhaustedFor(2 * time.Hour)},
			},
			earliest: "acc-b", seconds: 7200, retryIn: 2 * time.Hour, duration: "2 h",
			notSaid: groupDegradeMessage(groupErrAllUnusable),
		},
		{
			name: "a deadline inside a second: retry_at rounds down, Retry-After up, the text keeps each",
			cards: []recoveryCard{
				{id: "acc-a", local: 30*time.Second + 400*time.Millisecond, localStatus: poolRouteRateLimited},
			},
			earliest: "acc-a", seconds: 31, retryIn: 30 * time.Second, duration: "31 s",
			notSaid: "about 30 s",
		},
		{
			// The text takes the advice the header got, judged with this seat;
			// asked again without the seat, the revoked card's 5 minutes would
			// set it (T3-1.2 re-review NN3).
			name: "an account whose token this seat saw rejected never sets the time",
			cards: []recoveryCard{
				{id: "acc-a", local: 5 * time.Minute, localStatus: poolRouteRateLimited, revoked: true},
				{id: "acc-b", fiveHour: exhaustedFor(20 * time.Minute)},
			},
			earliest: "acc-b", seconds: 1200, retryIn: 20 * time.Minute, duration: "20 min",
			notSaid: "about 5 min",
		},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(time.Now().Unix(), 0)
			p := hintPool(t, now, tc.cards)

			req, w := groupReq(groupBody)
			p.Handle(w, req)
			var body struct {
				Error struct {
					Code              string                 `json:"code"`
					Message           string                 `json:"message"`
					RetryAfterSeconds int                    `json:"retry_after_seconds"`
					RetryAt           int64                  `json:"retry_at"`
					Accounts          []poolAccountStateView `json:"accounts"`
				} `json:"error"`
			}
			if w.Code != http.StatusTooManyRequests || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error.Code != groupErrAllUnusable {
				t.Fatalf("every account is out: want 429 %s, got %d: %s", groupErrAllUnusable, w.Code, w.Body.String())
			}

			// The header and the body carry one number and one instant.
			wantAt := now.Add(tc.retryIn).Unix()
			if got := w.Header().Get("Retry-After"); got != strconv.Itoa(tc.seconds) || body.Error.RetryAfterSeconds != tc.seconds || body.Error.RetryAt != wantAt {
				t.Fatalf("Retry-After=%q retry_after_seconds=%d retry_at=%s, want %d / %d / %s: %s",
					got, body.Error.RetryAfterSeconds, unixOffset(body.Error.RetryAt, now), tc.seconds, tc.seconds, unixOffset(wantAt, now), w.Body.String())
			}

			// The text opens with the approved sentence: its instant is retry_at,
			// its duration is Retry-After — the time only, never a reason
			// (R-oauth-account-pool-43).
			utc := time.Unix(wantAt, 0).UTC().Format(time.RFC3339)
			want := "AiKey: All accounts in this credential-sharing group are currently unavailable. " +
				"The earliest one is expected to be available again in about " + tc.duration + " (" + utc + ")."
			if !strings.HasPrefix(body.Error.Message, want) {
				t.Fatalf("429 text = %q\nwant it to open with %q", body.Error.Message, want)
			}
			if strings.Contains(body.Error.Message, tc.notSaid) {
				t.Fatalf("429 text must not say %q: %q", tc.notSaid, body.Error.Message)
			}

			// The earliest account's own line prints that same second.
			var line poolAccountStateView
			for _, v := range body.Error.Accounts {
				if v.AccountID == tc.earliest {
					line = v
				}
			}
			if line.RetryAt != wantAt || !strings.Contains(body.Error.Message, tc.earliest+": "+line.Status+" (retry at "+utc+")") {
				t.Fatalf("%s's line = %+v, want retry_at %s printed as %s: %q", tc.earliest, line, unixOffset(wantAt, now), utc, body.Error.Message)
			}
		})
	}

	// No time known — every account exhausted with no reset delivered — means
	// no advice, and the user-approved rule is to keep today's sentence word for
	// word and promise nothing (R-oauth-account-pool-4.2.S2: never make a time
	// up). Pinned as a literal: groupDegradeMessage would move with the very
	// sentence it guards.
	t.Run("no time known: the approved sentence, word for word, and no time", func(t *testing.T) {
		now := time.Unix(time.Now().Unix(), 0)
		p := hintPool(t, now, []recoveryCard{
			{id: "acc-a", fiveHour: exhaustedNoReset},
			{id: "acc-b", fiveHour: exhaustedNoReset},
		})
		req, w := groupReq(groupBody)
		p.Handle(w, req)
		var body struct {
			Error struct {
				Code              string `json:"code"`
				Message           string `json:"message"`
				RetryAfterSeconds *int   `json:"retry_after_seconds"`
				RetryAt           *int64 `json:"retry_at"`
			} `json:"error"`
		}
		if w.Code != http.StatusTooManyRequests || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error.Code != groupErrAllUnusable {
			t.Fatalf("every account is out: want 429 %s, got %d: %s", groupErrAllUnusable, w.Code, w.Body.String())
		}
		const approved = "AiKey: All accounts in this credential-sharing group are currently unavailable (rate-limited or expired). " +
			"Contact your administrator if this persists."
		if body.Error.Message != approved || strings.Contains(body.Error.Message, "about") {
			t.Fatalf("no time to promise: text = %q, want exactly %q", body.Error.Message, approved)
		}
		if got := w.Header().Get("Retry-After"); got != "" || body.Error.RetryAfterSeconds != nil || body.Error.RetryAt != nil {
			t.Fatalf("no time to promise, yet Retry-After=%q (retry_after_seconds present: %v, retry_at present: %v): %s",
				got, body.Error.RetryAfterSeconds != nil, body.Error.RetryAt != nil, w.Body.String())
		}
	})
}

// hintPool is the seat-path proxy one fence row runs against: the cards'
// delivered material with the store's clock at now (a whole second, so the only
// fraction is a row's own deadline; the picker judges delivered windows on the
// real clock, at most a second ahead, and every wall in the rows is at least 20
// minutes away), plus the local cooldowns and this seat's rejected tokens,
// recorded the way the request path records them.
func hintPool(t *testing.T, now time.Time, cards []recoveryCard) *Proxy {
	t.Helper()
	key := grKey()
	refs := make([]vkeys.GroupAccountRef, 0, len(cards))
	delivered := make(map[string]vkeys.GroupRuntimeAccount, len(cards))
	for _, c := range cards {
		refs = append(refs, vkeys.GroupAccountRef{AccountID: c.id, ProviderCode: "anthropic"})
		delivered[c.id] = encMat(t, key, c.material(now), "tok-"+c.id)
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, delivered),
	}
	p, _ := setupGroupProxy(t, key, route)
	p.poolCooldown.now = func() time.Time { return now }
	for _, c := range cards {
		if c.local > 0 {
			until := now.Add(c.local)
			p.poolCooldown.markWithState(c.id, until, PoolAccountRouteState{Status: c.localStatus, RetryAt: until.Unix()})
		}
		if c.revoked {
			// The upstream rejected this seat's token for good; the delivered
			// token is "tok-<id>".
			p.poolCooldown.markAuthFailedToken(route.OauthGroupID, route.SeatID, c.id, oauthTokenFingerprint("tok-"+c.id))
		}
	}
	return p
}

// ② GetBody: the group body is already buffered for failover replay; net/http
// must be handed a re-opener or an h2 stream error after the body was written
// turns into an unretryable hard failure (PC2 2026-09-03 04:03, 39.5s).
// bugfix: workflow/CI/bugfix/2026-09-03-h2流错误无法重放请求体.md
func TestReplayBodyCanBeReopenedForTransportRetry(t *testing.T) {
	replay, err := readGroupReplayBody(strings.NewReader(`{"input":"hello"}`), -1, groupReplayBodyLimit, processGroupReplayBudget)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	// Mirrors what serveGroupAttempt hands to net/http: each GetBody call must
	// yield a fresh reader over the same bytes.
	for i := 0; i < 2; i++ {
		rc := replay.Open()
		buf := make([]byte, 64)
		n, _ := rc.Read(buf)
		if string(buf[:n]) != `{"input":"hello"}` {
			t.Fatalf("re-open %d returned %q — a retry would send a different body", i, buf[:n])
		}
	}
}

func TestServeGroupAttemptWiresGetBody(t *testing.T) {
	src, err := os.ReadFile("group_serve.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func (p *Proxy) serveGroupAttempt(")
	end := strings.Index(body[start:], "\n}\n")
	fn := body[start : start+end]
	if !strings.Contains(fn, "r.GetBody = func() (io.ReadCloser, error) { return replay.Open(), nil }") {
		t.Fatal("serveGroupAttempt no longer sets GetBody — h2 stream errors after the body is written are unretryable again")
	}
}
