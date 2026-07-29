// upstream_fallback_contract_test.go — locks the frozen names from
// openspec change `aliyun-aigw-p0-upstream-fallback` tasks 0.2/0.3/0.4/0.5/0.16.
//
// These assertions look tautological on purpose. They are not testing logic;
// they are the mechanism that makes a rename DELIBERATE. Every one of these
// strings is on the wire, read by the console and by customer documentation,
// so a silent rename is a compatibility break that no other test would notice.
package observability

import (
	"strings"
	"testing"
)

func TestUpstreamFallbackErrorCodesFrozen(t *testing.T) {
	// 🔴 F-5 = A: flat style, matching the existing 15 codes in handler.go.
	// A three-segment code here would put two styles on one wire.
	cases := map[string]string{
		ErrCodeUpstreamFallbackExhausted:      "UPSTREAM_FALLBACK_EXHAUSTED",
		ErrCodeUpstreamFallbackUnconfigured:   "UPSTREAM_FALLBACK_UNCONFIGURED",
		ErrCodeUpstreamFallbackBudgetExceeded: "UPSTREAM_FALLBACK_BUDGET_EXCEEDED",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("frozen error code changed: got %q want %q", got, want)
		}
	}
}

// TestBudgetAndExhaustedAreDistinct locks task 2.32 / 0.16: the two codes must
// never collapse into one. They imply opposite next actions for the operator.
func TestBudgetAndExhaustedAreDistinct(t *testing.T) {
	if ErrCodeUpstreamFallbackBudgetExceeded == ErrCodeUpstreamFallbackExhausted {
		t.Fatal("BUDGET_EXCEEDED and EXHAUSTED collapsed into one code: " +
			"budget means 'the upstreams may be fine, we stopped waiting' → raise the limit; " +
			"exhausted means 'your upstreams are not working' → go check them. " +
			"One code sends half the operators down the wrong diagnosis.")
	}
}

// TestUnconfiguredIsPermanentNoRetryCopy locks the 🔴 rule in task 0.2:
// UNCONFIGURED is a PERMANENT state, so its copy must not suggest retrying in
// any language. Retrying cannot succeed until an admin adds a second upstream.
func TestUnconfiguredIsPermanentNoRetryCopy(t *testing.T) {
	for _, lang := range []string{"en", "zh"} {
		msg := FallbackMessage(ErrCodeUpstreamFallbackUnconfigured, lang, 1)
		if msg == "" {
			t.Fatalf("lang %s: UNCONFIGURED has no frozen copy", lang)
		}
		lower := strings.ToLower(msg)
		for _, banned := range []string{"retry", "try again", "重试", "再试", "稍后"} {
			if strings.Contains(lower, banned) {
				t.Errorf("lang %s: UNCONFIGURED copy contains %q — this is a PERMANENT "+
					"state; retrying can never succeed until an administrator adds a "+
					"second upstream. Copy: %s", lang, banned, msg)
			}
		}
	}
}

// TestBudgetCopyPointsAtTheAdjustableValue locks task 2.32: the message must
// tell the admin which number to change, otherwise the code is just a nicer
// spelling of "timeout".
func TestBudgetCopyPointsAtTheAdjustableValue(t *testing.T) {
	for lang, want := range map[string]string{
		"en": "wait limit",
		"zh": "等待上限",
	} {
		msg := FallbackMessage(ErrCodeUpstreamFallbackBudgetExceeded, lang, 3)
		if !strings.Contains(msg, want) {
			t.Errorf("lang %s: BUDGET copy must point at the adjustable value (%q); got: %s",
				lang, want, msg)
		}
	}
}

// TestEveryCodeHasBothLanguages — task 0.2 requires en+zh parity. A code with
// only English copy silently renders blank on a zh console.
func TestEveryCodeHasBothLanguages(t *testing.T) {
	codes := []string{
		ErrCodeUpstreamFallbackExhausted,
		ErrCodeUpstreamFallbackUnconfigured,
		ErrCodeUpstreamFallbackBudgetExceeded,
	}
	for _, code := range codes {
		for _, lang := range []string{"en", "zh"} {
			if FallbackMessage(code, lang, 2) == "" {
				t.Errorf("code %s has no %s copy", code, lang)
			}
		}
	}
}

func TestFallbackEventAndHeaderFrozen(t *testing.T) {
	// Task 0.3 — event name stays in the existing proxy.* family.
	if EventProxyRouteFallback != "proxy.route.fallback" {
		t.Errorf("frozen event name changed: %q", EventProxyRouteFallback)
	}
	if !strings.HasPrefix(EventProxyRouteFallback, "proxy.") {
		t.Errorf("fallback event left the proxy.* family: %q", EventProxyRouteFallback)
	}
	// Task 0.4 — header name and its three attribute keys.
	if HeaderUpstreamFallback != "X-Aikey-Fallback" {
		t.Errorf("frozen header changed: %q", HeaderUpstreamFallback)
	}
	for got, want := range map[string]string{
		HeaderAttrFallbackTo:      "to",
		HeaderAttrFallbackReason:  "reason",
		HeaderAttrFallbackAttempt: "attempt",
	} {
		if got != want {
			t.Errorf("frozen header attribute changed: got %q want %q", got, want)
		}
	}
}

// TestUsageFieldsFrozenAndCarryNoModelName locks task 0.5, both halves: the
// four field names, and the 🚫 that none of them is a model-name field.
func TestUsageFieldsFrozenAndCarryNoModelName(t *testing.T) {
	fields := map[string]string{
		UsageFieldServedProvider:  "served_provider",
		UsageFieldServedBindingID: "served_binding_id",
		UsageFieldFallbackReason:  "fallback_reason",
		UsageFieldFallbackAttempt: "fallback_attempt",
	}
	for got, want := range fields {
		if got != want {
			t.Errorf("frozen usage field changed: got %q want %q", got, want)
		}
		if strings.Contains(got, "model") {
			t.Errorf("usage field %q looks like a model-name field — task 0.5 freezes "+
				"this set WITHOUT one, because this change does not switch model tiers "+
				"and such a field would be read as evidence that it does", got)
		}
	}
	if len(fields) != 4 {
		t.Errorf("task 0.5 freezes exactly 4 usage fields, found %d", len(fields))
	}
}
