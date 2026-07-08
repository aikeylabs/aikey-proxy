package proxy

// Integration (mock-upstream) — real Anthropic unified rate-limit headers drive the
// window pre-cut → account switch → success chain, AND the I5 utilization uplink to
// master (which feeds the 动态决策账号分配引擎). 2026-07-01.
//
// WHY this test (user ask): the "额度不足 → 切换账号 → 切换成功" path must be exercised
// with a mock Provider returning REAL response headers (not a fabricated WindowStatus),
// so the REAL parse path (oauth_pool_window.go parseUtil + signal_report.go
// parseUnifiedUtil5h) is under test. Both read the SAME header, so one injected header
// covers both legs:
//   - proxy-local reactive pre-cut: util ≥ delivered cap → cool the account → the
//     resolver routes the NEXT request to another account (switch), which succeeds.
//   - engine uplink (I5): the util value is enqueued to the signal reporter, which the
//     collector ships to master; the allocation engine reads the util trend from it.
//
// Header shape is the VERIFIED real Anthropic Claude-subscription "unified" rate-limit
// block (platform docs + reverse-engineering, 2026-07):
//   anthropic-ratelimit-unified-5h-utilization: 0.98   (float 0..1)
//   anthropic-ratelimit-unified-7d-utilization: 0.40
//   anthropic-ratelimit-unified-5h-reset:       <unix epoch seconds>
//   anthropic-ratelimit-unified-status:         allowed | exceeded | rate_limited
//   anthropic-ratelimit-unified-representative-claim: five_hour
// "额度剩余" = 1 − utilization; the proxy pre-cuts on utilization ≥ cap/100.

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// unifiedRateLimitHeaders builds the real Anthropic unified rate-limit response block.
// Built via Set so the keys are canonicalized exactly like a real wire response
// (http.Header.Get canonicalizes on read, so casing must match).
func unifiedRateLimitHeaders(util5h, util7d string, resetEpoch int64) http.Header {
	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-5h-utilization", util5h)
	h.Set("anthropic-ratelimit-unified-7d-utilization", util7d)
	h.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(resetEpoch, 10))
	h.Set("anthropic-ratelimit-unified-status", "allowed")
	h.Set("anthropic-ratelimit-unified-representative-claim", "five_hour")
	return h
}

// drainForUtil non-blockingly scans the signal channel for a sample matching
// (credID, util5h). Returns true on the first match.
func drainForUtil(in <-chan signalSample, credID string, want float64) bool {
	for {
		select {
		case s := <-in:
			if s.CredentialID == credID && s.Util5h == want {
				return true
			}
		default:
			return false
		}
	}
}

// twoAccountWindowRoute builds a 2-OAuth-account group VK whose accounts each carry a
// delivered window cap (so stashWindowCap fires) + a real credential_id (so the I5
// enqueue, which keys on credential_id, isn't dropped).
func twoAccountWindowRoute(t *testing.T, key []byte, capPct int) (*vkeys.ResolvedRoute, map[string]string, map[string]string) {
	t.Helper()
	cap := capPct
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-1", CredentialID: "cred-1", ProviderCode: "anthropic"},
		{AccountID: "acc-2", CredentialID: "cred-2", ProviderCode: "anthropic"},
	}
	mk := func(ext string) vkeys.GroupRuntimeAccount {
		return vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: ext,
			WindowMaxUtilPct: &cap, WindowStatus: "active",
		}
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, mk("uuid-1"), "tok-1"),
		"acc-2": encMat(t, key, mk("uuid-2"), "tok-2"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	tokToAcct := map[string]string{"tok-1": "acc-1", "tok-2": "acc-2"}
	credOf := map[string]string{"acc-1": "cred-1", "acc-2": "cred-2"}
	return route, tokToAcct, credOf
}

// util ≥ cap (from a real header on a 200) → pre-cut the served account → next request
// SWITCHES to the other account and SUCCEEDS; the util is also uplinked (I5) to master.
func TestGroupServe_WindowUtilHeaderPreCutsSwitchesAndUplinks(t *testing.T) {
	key := grKey()
	route, tokToAcct, credOf := twoAccountWindowRoute(t, key, 97)

	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	// Inspectable reporter so we can assert the util was enqueued for the master
	// uplink (no loop() goroutine — the buffer just holds the samples for the test).
	rep := &signalReporter{in: make(chan signalSample, 8)}
	p.signalReporter = rep
	tr := &outboundCapture{}
	p.SetTransport(tr)

	// ── Request 1: mock upstream 200 + util 0.98 (≥ cap 0.97) on the served account ──
	reset := time.Now().Add(2 * time.Hour).Unix()
	tr.respHeader = unifiedRateLimitHeaders("0.98", "0.40", reset)
	req1, w1 := groupReq(groupBody)
	p.Handle(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("the request itself must still succeed (200); pre-cut is for the NEXT one, got %d: %s", w1.Code, w1.Body.String())
	}
	served1 := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]
	if served1 == "" {
		t.Fatalf("req1 outbound auth %q did not map to a known account", tr.auth)
	}
	// (a) LOCAL pre-cut: util ≥ cap must cool the served account for its window.
	if !p.poolCooldown.skipSet()[served1] {
		t.Fatalf("util 0.98 ≥ cap 0.97 must PRE-CUT (cool) the served account %s (防封, before it hits 100%%)", served1)
	}
	// (b) ENGINE uplink: the same util must be enqueued to the signal reporter (I5 →
	// collector → master; the 动态决策引擎 reads the util trend from it).
	if !drainForUtil(rep.in, credOf[served1], 0.98) {
		t.Fatalf("util 0.98 must be enqueued to the signal reporter for cred %s (I5 uplink to the allocation engine)", credOf[served1])
	}

	// ── Request 2: util now low; pre-cut account is skipped → SWITCH → SUCCESS ──
	tr.respHeader = unifiedRateLimitHeaders("0.10", "0.10", reset)
	req2, w2 := groupReq(groupBody)
	p.Handle(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("额度将满→切换：the switch request must SUCCEED via the other account, got %d: %s", w2.Code, w2.Body.String())
	}
	served2 := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]
	if served2 == "" || served2 == served1 {
		t.Fatalf("must switch to a DIFFERENT account after the pre-cut; served1=%s served2=%s (auth=%q)", served1, served2, tr.auth)
	}
}

// Negative control: util 0.50 < cap 0.97 → NO pre-cut → the next request STAYS on the
// same account (a transient/low reading must not churn the route). Mirrors E4's matrix.
func TestGroupServe_WindowUtilBelowCapNoPreCut(t *testing.T) {
	key := grKey()
	route, tokToAcct, _ := twoAccountWindowRoute(t, key, 97)

	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	tr := &outboundCapture{}
	p.SetTransport(tr)

	reset := time.Now().Add(2 * time.Hour).Unix()
	tr.respHeader = unifiedRateLimitHeaders("0.50", "0.30", reset)
	req1, w1 := groupReq(groupBody)
	p.Handle(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("req1 status=%d body=%s", w1.Code, w1.Body.String())
	}
	served1 := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]
	if p.poolCooldown.skipSet()[served1] {
		t.Fatalf("util 0.50 < cap 0.97 must NOT pre-cut account %s (no needless churn)", served1)
	}

	req2, w2 := groupReq(groupBody)
	p.Handle(w2, req2)
	served2 := tokToAcct[strings.TrimPrefix(tr.auth, "Bearer ")]
	if served2 != served1 {
		t.Fatalf("no pre-cut → must STAY on the same account (sticky); served1=%s served2=%s", served1, served2)
	}
}
