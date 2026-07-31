// upstream_fallback.go — P0a 上游 Fallback · 契约冻结（openspec change
// `aliyun-aigw-p0-upstream-fallback`, tasks 0.2 / 0.3 / 0.4 / 0.5 / 0.16).
//
// This file is the SINGLE source of truth for every wire-visible name the
// upstream-fallback capability introduces: three error codes, one event name,
// one response header family, and four usage-event field names.
//
// 🔴 Why they live here and nowhere else (task 0.2): the codes are consumed by
// the proxy, by the console, and by customer-facing docs. A string literal
// spelled at the use site is how two spellings of the same code end up on the
// wire — the console then switches on a code the proxy never emits, and the
// mismatch is invisible until a customer hits the branch. Every emit site MUST
// reference these constants; `upstream_fallback_contract_test.go` locks the
// spellings so a rename has to be deliberate.
//
// F-5 (决策点, tasks 0.9) = A — FLAT code style, matching the 15 codes already
// in handler.go. The sister change `aliyun-aigw-p0-rate-limit` MUST give the
// same answer; two styles on one wire is the failure this decision prevents.
package observability

// ---- Error codes (tasks 0.2, 0.16) ----

const (
	// ErrCodeUpstreamFallbackExhausted: every candidate in the route group was
	// tried and every one of them failed. HTTP status is the LAST upstream's
	// status, passed through — we do not invent one, because the admin's next
	// action depends on what the upstreams actually said.
	//
	// Next action this code implies: go look at the upstreams.
	ErrCodeUpstreamFallbackExhausted = "UPSTREAM_FALLBACK_EXHAUSTED"

	// ErrCodeUpstreamFallbackUnconfigured: the upstream failed and there was
	// nothing to fall back TO — the chain has exactly one member.
	//
	// 🔴 PERMANENT STATE (task 0.2). The copy for this code must never contain
	// "retry" in any language: retrying changes nothing until an administrator
	// adds a second upstream. Telling the user to retry sends them into a loop
	// that cannot terminate, and hides the one action that would fix it.
	//
	// 🔴 This is deliberately NOT the same code as "this virtual key has no
	// route group at all" (task 0b.9 / 2.0). No group → single-shot legacy
	// behavior, which is Personal edition's permanent, correct state. One-member
	// group → a chain an admin built and probably believes is redundant. The two
	// need opposite next actions, so they must stay distinguishable.
	ErrCodeUpstreamFallbackUnconfigured = "UPSTREAM_FALLBACK_UNCONFIGURED"

	// ErrCodeUpstreamFallbackBudgetExceeded (task 0.16): the whole-chain time
	// budget ran out before the chain did. HTTP 504.
	//
	// 🔴 MUST NOT be merged into EXHAUSTED (task 2.32). The two point at
	// opposite diagnoses:
	//   BUDGET    — the upstreams may be perfectly healthy; we stopped waiting.
	//               → the admin raises the budget.
	//   EXHAUSTED — the upstreams you configured are not working.
	//               → the admin investigates the upstreams.
	// Collapsing them sends half the operators down the wrong path.
	ErrCodeUpstreamFallbackBudgetExceeded = "UPSTREAM_FALLBACK_BUDGET_EXCEEDED"
)

// ---- Event name (task 0.3) ----

// EventProxyRouteFallback is emitted once per actual switch to a next
// candidate. Named into the existing `proxy.*` family so it sorts and filters
// alongside `proxy.request.*` and `proxy.group.*` rather than inventing a
// sibling namespace.
const EventProxyRouteFallback = "proxy.route.fallback"

// ---- Response header (task 0.4) ----

const (
	// HeaderUpstreamFallback carries `to=<provider_code>; reason=<code>; attempt=<n>`.
	//
	// 🔴 PROVIDER CODE ONLY — never the resolved base_url (task 0.4). An
	// upstream address may be a customer's internal gateway or a private
	// acceleration endpoint; echoing it to every client broadcasts internal
	// topology to anyone holding a key.
	HeaderUpstreamFallback = "X-Aikey-Fallback"

	// Header attribute keys, frozen so the formatter and any parser agree.
	HeaderAttrFallbackTo      = "to"
	HeaderAttrFallbackReason  = "reason"
	HeaderAttrFallbackAttempt = "attempt"
)

// FormatFallbackHeader builds the frozen `X-Aikey-Fallback` value.
//
// One formatter so the three attributes are always spelled and ordered the same
// way. 🔴 `to` is a PROVIDER CODE — passing a base_url here would broadcast a
// customer's internal topology to every client holding a key, which task 0.4
// rules out at the security level, not the tidiness level.
func FormatFallbackHeader(providerCode, reason string, attempt int) string {
	return HeaderAttrFallbackTo + "=" + providerCode + "; " +
		HeaderAttrFallbackReason + "=" + reason + "; " +
		HeaderAttrFallbackAttempt + "=" + itoa(attempt)
}

// ---- Usage-event field names (task 0.5) ----

// 🚫 NO MODEL-NAME FIELD IN THIS SET (task 0.5). This change does not switch
// model tiers; a model field here would be read as evidence that it does.
//
// (The upstream-side model name DOES vary per hop under mixed chains — task
// 2.29 — but that is the provider's spelling of the SAME model, carried by the
// existing mapping machinery, not a tier change this event should advertise.)
const (
	// UsageFieldServedProvider — the provider that actually produced the
	// response. 🔴 Cost is attributed to THIS, not to the primary (task 3.3).
	UsageFieldServedProvider = "served_provider"
	// UsageFieldServedBindingID — the binding row that produced the response.
	UsageFieldServedBindingID = "served_binding_id"
	// UsageFieldFallbackReason — the frozen error code that caused the switch.
	UsageFieldFallbackReason = "fallback_reason"
	// UsageFieldFallbackAttempt — 1-based hop index that produced the response.
	//
	// 🔴 Task 3.11: this and served_* MUST be read from the hop that produced
	// the response, never from the `route` variable visible outside the
	// candidate loop. Reading the outer variable compiles, and passes every
	// single-hop test, because on a single hop the two are equal. It is wrong
	// only when a switch actually happened — the exact case the dashboards
	// exist to report.
	UsageFieldFallbackAttempt = "fallback_attempt"
)

// ---- User-facing copy (task 0.2: 前后端一致 en+zh) ----

// FallbackMessage returns the frozen en/zh copy for a fallback error code.
// The console renders these same strings; keeping both languages beside the
// code is what stops the two surfaces from drifting into different promises.
//
// `attempts` is the number of upstreams actually tried (used by EXHAUSTED).
func FallbackMessage(code string, lang string, attempts int) string {
	zh := lang == "zh" || lang == "zh-CN" || lang == "zh-Hans"
	switch code {
	case ErrCodeUpstreamFallbackExhausted:
		if zh {
			return "已按配置顺序尝试全部 " + itoa(attempts) + " 个上游，均未成功。请管理员检查这些上游的可用性。"
		}
		return "All " + itoa(attempts) + " configured upstreams were tried in order and none succeeded. Ask your administrator to check those upstreams."
	case ErrCodeUpstreamFallbackUnconfigured:
		// 🔴 Permanent state — no "retry"/"重试" in either language.
		if zh {
			return "该密钥在此协议下只配置了一个上游，没有可切换的备用上游。请管理员在路由组中添加备用上游。"
		}
		return "This key has only one upstream configured for this protocol, so there is no alternate to switch to. Ask your administrator to add a fallback upstream to the route group."
	case ErrCodeUpstreamFallbackBudgetExceeded:
		// Copy must point at the adjustable number (task 2.32).
		if zh {
			return "整体等待上限已用尽，尚未拿到上游响应。上游可能仍然正常，只是我们没有等到 —— 请管理员调大整体等待上限。"
		}
		return "The overall wait limit ran out before an upstream responded. The upstreams may be healthy; we stopped waiting. Ask your administrator to raise the overall wait limit."
	}
	return ""
}

// itoa is a tiny local int→string to keep this contract file free of imports
// that would tempt future edits to pull logic in here. This file is a freeze,
// not a place for behavior.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
