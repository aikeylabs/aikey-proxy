package proxy

import (
	"encoding/json"
	"os"
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
