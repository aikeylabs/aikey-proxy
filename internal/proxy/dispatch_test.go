package proxy

// Tests for the namespace-authority dispatch rules.
//
// These tests pin the contracts in roadmap20260320/技术实现/update/
// 20260429-token前缀按角色重命名.md §3 "命名空间权威性原则":
//   - Every aikey_*-prefixed token reaches a deterministic DispatchAction.
//   - Unknown / malformed aikey_* shapes return TokenInvalid (NOT silent
//     fallthrough — that would mask config bugs).
//   - aikey_active_* is the SOLE exception allowed to fall through.
//   - Native (non-aikey_) tokens always go to Tier3Native.

import (
	"strings"
	"testing"
)

func TestClassifyToken_Tier1Team(t *testing.T) {
	cases := []string{
		"aikey_team_acc-1234",                  // typical server-issued vk_id
		"aikey_team_vk_abc",                    // vk_-prefixed (legitimate post-helper-normalization)
		"aikey_team_a",                         // shortest non-empty vk_id
		"aikey_team_arbitrary-text-with-hyphens",
	}
	for _, tok := range cases {
		got := ClassifyToken(tok)
		if got != Tier1Team {
			t.Errorf("ClassifyToken(%q) = %v, want Tier1Team", tok, got)
		}
	}
}

func TestClassifyToken_Tier1Personal_StrictForm(t *testing.T) {
	hex := strings.Repeat("0", 64)
	cases := []string{
		"aikey_personal_" + hex,
		"aikey_personal_" + strings.Repeat("f", 64),
		"aikey_personal_" + strings.Repeat("a", 32) + strings.Repeat("9", 32),
	}
	for _, tok := range cases {
		got := ClassifyToken(tok)
		if got != Tier1Personal {
			t.Errorf("ClassifyToken(%q) = %v, want Tier1Personal", tok, got)
		}
	}
}

func TestClassifyToken_Tier2Probe(t *testing.T) {
	cases := []string{
		"aikey_probe_my-claude",
		"aikey_probe_a",
		"aikey_probe_alias-with-dashes",
	}
	for _, tok := range cases {
		got := ClassifyToken(tok)
		if got != Tier2Probe {
			t.Errorf("ClassifyToken(%q) = %v, want Tier2Probe", tok, got)
		}
	}
}

func TestClassifyToken_Tier3ActiveSentinel(t *testing.T) {
	cases := []string{
		"aikey_active_anthropic",
		"aikey_active_openai",
		"aikey_active_google",
		"aikey_active_kimi",
		"aikey_active_deepseek",
		// Suffix is intentionally NOT validated — proxy routes via URL path.
		// Passes through fallthrough; the suffix is informational.
		"aikey_active_",
		"aikey_active_unknown_provider",
		"aikey_active_anything-goes",
	}
	for _, tok := range cases {
		got := ClassifyToken(tok)
		if got != Tier3ActiveSentinel {
			t.Errorf("ClassifyToken(%q) = %v, want Tier3ActiveSentinel", tok, got)
		}
	}
}

func TestClassifyToken_Tier3Native(t *testing.T) {
	cases := []string{
		"sk-1234567890",
		"sk-ant-real-secret",
		"abc123",
		"Bearer-stripped-already",
		"",
		// Edge: starts with "aikey" but no underscore — NOT in the namespace
		// because the namespace is `aikey_*` (with underscore). Treat as native.
		"aikeyfoo",
	}
	for _, tok := range cases {
		got := ClassifyToken(tok)
		if got != Tier3Native {
			t.Errorf("ClassifyToken(%q) = %v, want Tier3Native", tok, got)
		}
	}
}

func TestClassifyToken_TokenInvalid_LegacyAndMalformed(t *testing.T) {
	// All these MUST classify as TokenInvalid — namespace-authority
	// principle says any aikey_*-prefixed token that doesn't match a
	// recognized subform fails loud, not silently.
	cases := []struct {
		name string
		tok  string
	}{
		// Reserved namespace (aikey_route_*) — not implemented this round.
		{"reserved aikey_route_*", "aikey_route_anything"},
		{"reserved aikey_route_64hex", "aikey_route_" + strings.Repeat("0", 64)},

		// Unknown subform.
		{"unknown subform", "aikey_unknown_xyz"},
		{"unknown short", "aikey_xyz"},

		// Empty team vk_id — caller bug.
		{"empty team", "aikey_team_"},

		// Legacy aikey_vk_* — fully removed; should fail loud.
		{"legacy aikey_vk_short", "aikey_vk_short"},
		{"legacy aikey_vk_64hex", "aikey_vk_" + strings.Repeat("0", 64)},

		// Malformed personal bearer — wrong length.
		{"personal 63 hex", "aikey_personal_" + strings.Repeat("0", 63)},
		{"personal 65 hex", "aikey_personal_" + strings.Repeat("0", 65)},
		{"personal 128 hex (double)", "aikey_personal_" + strings.Repeat("0", 128)},
		{"personal empty suffix", "aikey_personal_"},

		// Malformed personal bearer — wrong charset.
		{"personal uppercase", "aikey_personal_" + strings.Repeat("A", 64)},
		{"personal mixed case", "aikey_personal_" + strings.Repeat("aA", 32)},
		{"personal non-hex letter g", "aikey_personal_" + strings.Repeat("g", 64)},
		{"personal with hyphen", "aikey_personal_" + strings.Repeat("0", 32) + "-" + strings.Repeat("0", 31)},

		// Legacy personal sentinel forms (aikey_personal_<alias>, <UUID>).
		{"legacy personal alias", "aikey_personal_my-claude"},
		{"legacy personal UUID", "aikey_personal_54f8a3e1-b4d9-4e21-9fa0-0e3c5b7d8a91"},
		{"legacy personal acc_id", "aikey_personal_acc_1234567890"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyToken(c.tok)
			if got != TokenInvalid {
				t.Errorf("ClassifyToken(%q) = %v, want TokenInvalid", c.tok, got)
			}
		})
	}
}

// Order-independence: aikey_probe_<alias> must NEVER be misclassified as a
// malformed personal bearer just because both share the `aikey_p` prefix.
// (Implementation checks probe BEFORE personal — pin that ordering.)
func TestClassifyToken_ProbeChecksBeforePersonal(t *testing.T) {
	tok := "aikey_probe_a-suffix-that-could-look-like-personal"
	got := ClassifyToken(tok)
	if got != Tier2Probe {
		t.Errorf("ClassifyToken(%q) = %v, want Tier2Probe (probe must shadow personal)", tok, got)
	}
}

// Strict form check: isTier1Personal as a standalone unit (also covered
// indirectly by ClassifyToken tests, but worth a focused suite for the
// most security-critical predicate).
func TestIsTier1Personal_StrictForm(t *testing.T) {
	hex64 := strings.Repeat("0", 64)
	if !isTier1Personal("aikey_personal_" + hex64) {
		t.Error("must accept aikey_personal_<64 zeros>")
	}
	if !isTier1Personal("aikey_personal_" + strings.Repeat("abcdef0123456789", 4)) {
		t.Error("must accept aikey_personal_<64 lowercase hex>")
	}

	// Reject everything else.
	rejects := []string{
		"aikey_personal_" + strings.Repeat("0", 63),       // 63
		"aikey_personal_" + strings.Repeat("0", 65),       // 65
		"aikey_personal_" + strings.Repeat("A", 64),       // uppercase
		"aikey_personal_" + strings.Repeat("g", 64),       // non-hex
		"aikey_personal_my-alias",                          // legacy form
		"aikey_personal_",                                  // empty suffix
		"aikey_team_" + hex64,                              // wrong prefix
		"sk-" + hex64,                                      // not aikey
		"",
	}
	for _, tok := range rejects {
		if isTier1Personal(tok) {
			t.Errorf("isTier1Personal(%q) = true, want false", tok)
		}
	}
}
