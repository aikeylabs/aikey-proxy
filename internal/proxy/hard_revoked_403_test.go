package proxy

// O23 — a 403 must be ABLE to carry a hard-revocation marker.
//
// # What this fixes and what it leaves open
//
// `isHardRevoked` gated on `status != 401 → false` before looking at the body, so
// 403 could never quarantine an account no matter what the body said. That is a
// STRUCTURAL blocker, separate from the question of which words mean "banned",
// and it is the part that can be fixed without evidence we do not have.
//
// 🚫 No marker was added. The list is unchanged. What changed is that the status
// code no longer vetoes a marker that is unambiguous wherever it appears.
//
// 🔴 The plan-expiry case is still OPEN. Six probes across three real vendors on
// 2026-08-01 produced zero 403s, so there is no captured body to read. The
// negative cases below are therefore the important half of this file: they pin
// that a 403 WITHOUT a revocation marker — which is every 403 we have actually
// seen described (content filter, region block, org policy) — still does not
// quarantine anything.

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestIsHardRevoked_StatusAndMarkerMustBothAgree(t *testing.T) {
	// 🔴 The two 401 bodies here are REAL, captured 2026-08-01 from live vendors.
	// A synthetic body would prove only that the matcher matches itself.
	const anthropic401 = `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"},"request_id":"req_011Cdbgu4D2nt7kcqHgzCyR3"}`
	const glm401 = `{"error":{"message":"令牌已过期或验证不正确","type":"401"}}`

	for _, tc := range []struct {
		name   string
		status int
		errTyp string
		body   string
		want   bool
		why    string
	}{
		// ── The change: 403 can now carry a marker ─────────────────────────
		{"403 saying revoked", http.StatusForbidden, "", `{"error":{"message":"OAuth token has been revoked"}}`, true,
			"a 403 that literally says revoked is a revocation; the status must not veto it"},
		{"403 token_invalidated", http.StatusForbidden, "token_invalidated", "", true,
			"same marker, same meaning, different status"},

		// ── Unchanged: 401 behavior  ───────────────────────────────────────
		{"401 saying revoked", http.StatusUnauthorized, "", `{"error":{"message":"OAuth token has been revoked"}}`, true, ""},
		{"401 detail unauthorized", http.StatusUnauthorized, "", `{"detail":"Unauthorized"}`, true, ""},

		// ── 🔴 The negatives that keep this from becoming a blanket rule ───
		{"REAL Anthropic bad-key 401", http.StatusUnauthorized, "authentication_error", anthropic401, false,
			"a plain bad key is not a revocation — quarantining here would evict a healthy account " +
				"for a typo in one credential"},
		{"REAL GLM bad-key 401", http.StatusUnauthorized, "401", glm401, false,
			"the real GLM 401 says the token is expired or wrong, not revoked"},
		{"403 content filter", http.StatusForbidden, "", `{"error":{"message":"content blocked by safety policy"}}`, false,
			"THE case that makes a blanket 403 rule wrong: one user's prompt would quarantine the " +
				"account for the whole organization"},
		{"403 region block", http.StatusForbidden, "", `{"error":{"message":"unsupported_country_region_territory"}}`, false,
			"a region block is about where the request came from, not the credential"},
		{"403 org policy", http.StatusForbidden, "", `{"error":{"message":"insufficient permissions for this endpoint"}}`, false,
			"a permission boundary is not a revocation"},

		// ── Statuses that still may not quarantine ─────────────────────────
		{"429 saying revoked", http.StatusTooManyRequests, "", `{"error":{"message":"revoked"}}`, false,
			"a rate limit is recoverable; the account axis owns 429"},
		{"402 payment required", http.StatusPaymentRequired, "", `{"error":{"message":"revoked"}}`, false,
			"an expiry is recoverable — quarantining removes a working upstream, which is worse " +
				"than the retry loop"},
		{"404 no-access model", http.StatusNotFound, "not_found_error", `{"error":{"message":"model: claude-3-opus"}}`, false,
			"REAL shape, captured 2026-08-01 — a missing model says nothing about the credential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := isHardRevoked(tc.status, tc.errTyp, tc.body)
			if got != tc.want {
				t.Errorf("isHardRevoked(%d, %q, …) = %v, want %v%s",
					tc.status, tc.errTyp, got, tc.want, func() string {
						if tc.why == "" {
							return ""
						}
						return "\n  " + tc.why
					}())
			}
		})
	}
}

// 🔴 The anti-blanket fence, stated as its own test because it is the property
// most likely to be "simplified" away later: adding 403 must NOT mean every 403
// quarantines. If someone widens this to a bare status check, this fails.
func TestIsHardRevoked_A403WithoutAMarkerNeverQuarantines(t *testing.T) {
	for _, body := range []string{
		``,
		`{}`,
		`{"error":{"message":"forbidden"}}`,
		`{"error":{"type":"permission_error","message":"you do not have access to this resource"}}`,
		`Forbidden`,
	} {
		if isHardRevoked(http.StatusForbidden, "", body) {
			t.Errorf("a bare 403 quarantined the account (body %q). Every 403 we have actually "+
				"observed carries no revocation marker, so a blanket rule would evict healthy "+
				"accounts from the pool — strictly worse than the retry loop O23 describes", body)
		}
	}
}

// 调用点围栏：硬吊销上报**必须**把上游状态码与错误类型传下去。
//
// 🔴 为什么单独守调用点：wire 侧的断言（signal_report_test.go）直接调
// enqueueAuthFailure，**绕过了 recordEvent 这个真实调用点**。实测把
// `resp.StatusCode, errType` 改回 `0, ""` 之后，那条 wire 断言**仍然全绿**——
// 概念有两个出口（装载 + 传参），只守一个等于没守。这与 G30 是同一个陷阱。
//
// 守的东西很朴素：`isHardRevoked` 判定用的那两个值，必须原样交给上报，
// 而不是在旁边被丢掉。丢掉的后果是「为什么被拒」在 Master 侧无从归因
// （2026-08-31 客户现场：登录成功→一会儿变登录失效，只能靠猜）。
func TestHardRevokedReportPassesUpstreamEvidenceFromTheCallSite(t *testing.T) {
	src, err := os.ReadFile("events_and_helpers.go")
	if err != nil {
		t.Fatalf("read call site: %v", err)
	}
	text := string(src)
	idx := strings.Index(text, "isHardRevoked(resp.StatusCode, errType, errMsg)")
	if idx < 0 {
		t.Fatal("找不到硬吊销判定——调用点改了形状，这条围栏要跟着改，不能默默失效")
	}
	// ⚠️ 窗口必须从 enqueueAuthFailure **本身**开始截，不能从判定行开始：
	// 判定行 `isHardRevoked(resp.StatusCode, errType, errMsg)` 自己就含这两个
	// 字符串，从它起算的窗口**恒为真**——第一版就是这么写的，de-fix 打不红。
	call := strings.Index(text[idx:], "enqueueAuthFailure(")
	if call < 0 {
		t.Fatal("硬吊销判定后没有上报调用")
	}
	window := text[idx+call:]
	if end := strings.Index(window, ")\n"); end > 0 {
		window = window[:end]
	}
	for _, arg := range []string{"resp.StatusCode", "errType"} {
		if !strings.Contains(window, arg) {
			t.Errorf("硬吊销上报没有把 %s 传给 enqueueAuthFailure。\n"+
				"判定这一步已经拿到了它，却在上报时丢掉——Master 侧只会收到一个"+
				"恒定的 token_revoked，「为什么被拒」永远查不出来。", arg)
		}
	}
}
