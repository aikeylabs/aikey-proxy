package proxy

// truthful_provider_code_d4_test.go — task 0b.7b (D-4 / F-18) of openspec change
// `aliyun-aigw-p0-upstream-fallback`, plus the two rev6.1 fences listed in P6.2.
//
// D-4 narrows truthfulProviderCode from "the address decides the vendor" to
// "correct a MISLABEL, but never overrule a DECLARATION". The two halves have to
// be tested TOGETHER, because the easy way to satisfy either one alone is to
// break the other:
//
//	fix the mislabel by always trusting the address → `zhipu-coding` collapses to
//	  `zhipu`, and a chain's two hops report the same name (I4 broken);
//	protect the declaration by always trusting it → a binding that says
//	  `anthropic` while calling GLM is attributed to Anthropic, i.e. the original
//	  bug is back.
//
// So every test below asserts one half while a sibling asserts the other.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// TestD4_MislabelStillCorrectedAndDeclarationNoLongerOverruled is the core table.
//
// 能红 (both directions):
//   - drop the `declaredIsKnown` guard → the zhipu-coding rows fail;
//   - always return `declared` → the mislabel rows fail.
func TestD4_MislabelStillCorrectedAndDeclarationNoLongerOverruled(t *testing.T) {
	cases := []struct {
		name     string
		baseURL  string
		declared string
		want     string
		why      string
	}{
		{
			name:     "mislabel: declared a known vendor, calling another known vendor",
			baseURL:  "https://open.bigmodel.cn/api/anthropic",
			declared: "anthropic",
			want:     "zhipu",
			why: "the ORIGINAL bug this function exists for. `anthropic` is in the route table, so " +
				"we know which addresses it owns; bigmodel.cn is not one of them, which makes this a " +
				"genuine mislabel rather than a declaration",
		},
		{
			name:     "mislabel: GLM coding endpoint declared as anthropic",
			baseURL:  "https://open.bigmodel.cn/api/coding/paas/v4",
			declared: "anthropic",
			want:     "zhipu",
			why:      "same mislabel via GLM's other path prefix",
		},
		{
			name:     "declaration: org-registered second provider keeps its own code",
			baseURL:  "https://open.bigmodel.cn/api/anthropic",
			declared: "zhipu-coding",
			want:     "zhipu-coding",
			why: "🔴 THE D-4 CHANGE. `zhipu-coding` is not in the route table, so it is an ORG " +
				"REGISTRATION, not a typo — and we hold no address knowledge that could contradict " +
				"it. Collapsing it back to `zhipu` erases the only reason to register a second " +
				"provider (which is how rev6 says you get a second address for one brand) and makes " +
				"two hops of one chain report the same `to=` name, breaking I4",
		},
		{
			name:     "declaration: self-hosted gateway pointed at a known vendor's host",
			baseURL:  "https://open.bigmodel.cn/api/anthropic",
			declared: "selfhost-gw",
			want:     "selfhost-gw",
			why:      "any org-registered code is a declaration, not only the zhipu-* family",
		},
		// Unchanged behaviors — these guard against over-correcting the fix.
		{
			name:     "no-op: declared vendor owns the address",
			baseURL:  "https://api.anthropic.com",
			declared: "anthropic",
			want:     "anthropic",
			why:      "agreement needs no correction",
		},
		{
			name:     "no-op: multi-host known vendor on its own host",
			baseURL:  "https://api.kimi.com/coding/v1",
			declared: "kimi_code",
			want:     "kimi_code",
			why:      "kimi_code is in the table and owns this host",
		},
		{
			name:     "no-op: unknown host is nobody's evidence",
			baseURL:  "https://third-party.example/v1",
			declared: "custom",
			want:     "custom",
			why:      "a third-party gateway host tells us nothing, so the declaration stands",
		},
		{
			name:     "no-op: empty base_url",
			baseURL:  "",
			declared: "anthropic",
			want:     "anthropic",
			why:      "nothing to reverse-look-up",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := truthfulProviderCode(c.baseURL, c.declared)
			if got != c.want {
				t.Errorf("truthfulProviderCode(%q, %q) = %q, want %q\n  why: %s",
					c.baseURL, c.declared, got, c.want, c.why)
			}
		})
	}
}

// TestD4_TwoRegisteredProvidersOnOneHostStayDistinct — P6.2 rev6.1 fence #1.
//
// tasks.md lists this as RED until D-4 lands, and says it must go green once D-4
// is implemented correctly. "Register `zhipu` and `zhipu-coding`, call each once,
// assert the usage event's `provider` holds TWO DIFFERENT values."
func TestD4_TwoRegisteredProvidersOnOneHostStayDistinct(t *testing.T) {
	p := &Proxy{}
	const glmAnthropic = "https://open.bigmodel.cn/api/anthropic"

	seen := map[string]bool{}
	for _, declared := range []string{"zhipu", "zhipu-coding"} {
		req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", nil)
		resp := &http.Response{StatusCode: 200}
		route := &vkeys.ResolvedRoute{
			VirtualKeyID: "team:vk",
			ProviderCode: truthfulProviderCode(glmAnthropic, declared),
			ProtocolType: "anthropic",
			BaseURL:      glmAnthropic,
		}
		ev := p.buildBaseEvent(req, resp, time.Now(), route, false)
		seen[ev.Provider] = true
	}

	if len(seen) != 2 {
		var got []string
		for k := range seen {
			got = append(got, k)
		}
		t.Errorf("two separately registered providers on one host produced %d distinct usage-event "+
			"provider value(s) %v, want 2.\nWith one value the bill cannot distinguish the two "+
			"packages, and a chain that switches between them reports the same `to=` twice — "+
			"there is then no way to tell from the response header that a switch happened at all (I4).",
			len(seen), got)
	}
}

// TestD4_ChainHopsOnOneHostGetDistinctFallbackNames — P6.2 rev6.1 fence #2.
//
// "One switch along a chain → assert the two hops' `X-Aikey-Fallback: to=` differ."
// Checked at the attribution level, since that value is what the header is built from.
func TestD4_ChainHopsOnOneHostGetDistinctFallbackNames(t *testing.T) {
	// A realistic mixed chain that lives entirely on one vendor host: the official
	// GLM package as primary, the coding package as fallback. This is exactly the
	// shape rev6 tells admins to build when they want two addresses for one brand.
	primary := truthfulProviderCode("https://open.bigmodel.cn/api/anthropic", "zhipu")
	fallback := truthfulProviderCode("https://open.bigmodel.cn/api/coding/paas/v4", "zhipu-coding")

	if primary == fallback {
		t.Fatalf("both hops attribute to %q. `X-Aikey-Fallback: to=` would report the same name "+
			"before and after the switch, so a client could not tell a switch occurred, and cost "+
			"could not be split between the two packages (I4).", primary)
	}
	if fallback != "zhipu-coding" {
		t.Errorf("fallback hop attributed to %q, want zhipu-coding — the org registered it "+
			"deliberately and its identity must survive to the header", fallback)
	}
	// And the header value itself must carry the provider CODE, never the address
	// (task 0.4: an upstream address may be a customer's internal gateway).
	header := observability.HeaderAttrFallbackTo + "=" + fallback
	if strings.Contains(header, "bigmodel.cn") || strings.Contains(header, "http") {
		t.Errorf("fallback header %q leaks an address; task 0.4 freezes it to the provider code only", header)
	}
}

// TestD4_AttributionFollowsDeclarationWhileMappingFollowsAddress pins the split
// that D-4's rationale rests on. Getting these backwards is subtle and silent.
func TestD4_AttributionFollowsDeclarationWhileMappingFollowsAddress(t *testing.T) {
	const glmCoding = "https://open.bigmodel.cn/api/coding/paas/v4"

	// ATTRIBUTION (who gets billed / named in the header) → the DECLARATION.
	if got := truthfulProviderCode(glmCoding, "zhipu-coding"); got != "zhipu-coding" {
		t.Errorf("attribution = %q, want zhipu-coding: money and responsibility must stay separable", got)
	}

	// MODEL MAPPING → the ADDRESS. Both packages answer to the same model names,
	// so they legitimately share one mapping table, keyed by where we are calling.
	byAddress, ok := provider.Routes().LookupByBaseURL(glmCoding)
	if !ok || byAddress.Provider != "zhipu" {
		t.Fatalf("address lookup for %q gave (%v, %v), want provider zhipu", glmCoding, byAddress.Provider, ok)
	}
	if byAddress.Provider == "zhipu-coding" {
		t.Error("model mapping resolved to the DECLARED code. Then `zhipu-coding` would need its own " +
			"duplicate mapping table for identical model names — a second source of truth for the " +
			"same fact")
	}
}
