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
		"aikey_team_acc-1234", // typical server-issued vk_id
		"aikey_team_vk_abc",   // vk_-prefixed (legitimate post-helper-normalization)
		"aikey_team_a",        // shortest non-empty vk_id
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

func TestClassifyToken_Tier1App_StrictForm(t *testing.T) {
	hex := strings.Repeat("0", 64)
	cases := []string{
		"aikey_app_" + hex,
		"aikey_app_" + strings.Repeat("f", 64),
		"aikey_app_" + strings.Repeat("abcdef0123456789", 4),
	}
	for _, tok := range cases {
		got := ClassifyToken(tok)
		if got != Tier1App {
			t.Errorf("ClassifyToken(%q) = %v, want Tier1App", tok, got)
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

		// Malformed app bearer — wrong length.
		{"app 63 hex", "aikey_app_" + strings.Repeat("0", 63)},
		{"app 65 hex", "aikey_app_" + strings.Repeat("0", 65)},
		{"app 128 hex (double)", "aikey_app_" + strings.Repeat("0", 128)},
		{"app empty suffix", "aikey_app_"},

		// Malformed app bearer — wrong charset.
		{"app uppercase", "aikey_app_" + strings.Repeat("A", 64)},
		{"app mixed case", "aikey_app_" + strings.Repeat("aA", 32)},
		{"app non-hex letter g", "aikey_app_" + strings.Repeat("g", 64)},
		{"app with hyphen", "aikey_app_" + strings.Repeat("0", 32) + "-" + strings.Repeat("0", 31)},

		// Legacy app sentinel forms (none in production, but mirror personal — these MUST loud-fail).
		{"app alias-like suffix", "aikey_app_my-agent"},
		{"app UUID suffix", "aikey_app_54f8a3e1-b4d9-4e21-9fa0-0e3c5b7d8a91"},
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

// 2026-05-26 — Tier2ProbeRaw (pre-save probe). Pins the contract from
// roadmap20260320/技术实现/update/20260526-pre-save-proxy-probe-raw.md §2.1.
//
// Three invariants under test:
//
//	A. Canonical-only acceptance — suffix must be in the canonicalProviderCodes
//	   allowlist; aliases (claude/gpt/etc) are rejected with TokenInvalid.
//	B. Order independence vs Tier2Probe — `aikey_probe_raw_<canonical>` shares
//	   the `aikey_probe_` prefix with Tier2Probe; reverse order would silently
//	   misclassify as Tier2Probe with alias="raw_<canonical>". Pin the order.
//	C. Strict form — empty suffix / non-canonical / case-variations all fail.
func TestClassifyToken_Tier2ProbeRaw_Canonical(t *testing.T) {
	// Every canonical provider must accept.
	canonicals := []string{
		"anthropic", "openai", "google", "deepseek",
		"kimi_code", "moonshot", "groq", "xai",
		"openrouter", "perplexity", "zhipu", "qwen",
		"doubao", "siliconflow",
	}
	for _, c := range canonicals {
		tok := "aikey_probe_raw_" + c
		got := ClassifyToken(tok)
		if got != Tier2ProbeRaw {
			t.Errorf("ClassifyToken(%q) = %v, want Tier2ProbeRaw", tok, got)
		}
	}
}

// Invariant B: probe_raw must shadow probe (checked first in classifier).
// If reversed, aikey_probe_raw_anthropic → Tier2Probe with alias="raw_anthropic"
// → silent failure at handler (alias miss → confusing 503 instead of clean
// TOKEN_INVALID surface to caller).
func TestClassifyToken_ProbeRawChecksBeforeProbe(t *testing.T) {
	tok := "aikey_probe_raw_anthropic"
	got := ClassifyToken(tok)
	if got != Tier2ProbeRaw {
		t.Errorf("ClassifyToken(%q) = %v, want Tier2ProbeRaw (probe_raw must shadow probe)", tok, got)
	}
}

// Invariant A & C: aliases + empty + unknown + case variations → TokenInvalid.
// Callers (CLI/Web) MUST pre-normalize to canonical before constructing the
// probe_raw token; reject anything else loud at the dispatch boundary per the
// namespace-authority principle (no implicit normalization).
func TestClassifyToken_Tier2ProbeRaw_RejectsNonCanonical(t *testing.T) {
	rejects := []struct {
		name string
		tok  string
	}{
		// Empty suffix.
		{"empty suffix", "aikey_probe_raw_"},

		// Aliases — caller must normalize to canonical first.
		{"alias claude", "aikey_probe_raw_claude"},
		{"alias gpt", "aikey_probe_raw_gpt"},
		{"alias chatgpt", "aikey_probe_raw_chatgpt"},
		{"alias codex", "aikey_probe_raw_codex"},
		{"alias gemini", "aikey_probe_raw_gemini"},
		{"alias kimi", "aikey_probe_raw_kimi"},
		{"alias grok", "aikey_probe_raw_grok"},
		{"alias glm", "aikey_probe_raw_glm"},
		{"alias dashscope", "aikey_probe_raw_dashscope"},
		{"alias ark", "aikey_probe_raw_ark"},
		{"alias volcengine", "aikey_probe_raw_volcengine"},

		// Case variations — namespace-authority forbids implicit normalization.
		{"uppercase canonical", "aikey_probe_raw_ANTHROPIC"},
		{"mixed case canonical", "aikey_probe_raw_OpenAI"},

		// Unknown provider (typo / future-extension residue / made-up).
		{"unknown made-up", "aikey_probe_raw_blahblah"},
		{"typo of canonical", "aikey_probe_raw_anthopic"},

		// Whitespace and special chars.
		{"trailing space", "aikey_probe_raw_anthropic "},
		{"leading space", "aikey_probe_raw_ anthropic"},
		{"double underscore", "aikey_probe_raw__anthropic"},
	}
	for _, c := range rejects {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyToken(c.tok)
			if got != TokenInvalid {
				t.Errorf("ClassifyToken(%q) = %v, want TokenInvalid", c.tok, got)
			}
		})
	}
}

// isCanonicalProviderCode focused suite — pins the allowlist itself.
// Drift between this list and the providerDefaultBaseURL switch is the
// security-critical risk (a probe_raw token for a provider missing here
// silently fails; a provider added here but missing from base URL silently
// succeeds with empty upstream URL). Both directions need a fence test.
func TestIsCanonicalProviderCode_StrictAllowlist(t *testing.T) {
	accepts := []string{
		"anthropic", "openai", "google", "deepseek",
		"kimi_code", "moonshot", "groq", "xai",
		"openrouter", "perplexity", "zhipu", "qwen",
		"doubao", "siliconflow",
	}
	for _, c := range accepts {
		if !isCanonicalProviderCode(c) {
			t.Errorf("isCanonicalProviderCode(%q) = false, want true", c)
		}
	}

	rejects := []string{
		"", "claude", "gpt", "chatgpt", "codex", "gemini",
		"kimi", "grok", "glm", "dashscope", "ark",
		"ANTHROPIC", "OpenAI", "blahblah", " anthropic", "anthropic ",
	}
	for _, c := range rejects {
		if isCanonicalProviderCode(c) {
			t.Errorf("isCanonicalProviderCode(%q) = true, want false", c)
		}
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
		"aikey_personal_" + strings.Repeat("0", 63), // 63
		"aikey_personal_" + strings.Repeat("0", 65), // 65
		"aikey_personal_" + strings.Repeat("A", 64), // uppercase
		"aikey_personal_" + strings.Repeat("g", 64), // non-hex
		"aikey_personal_my-alias",                   // legacy form
		"aikey_personal_",                           // empty suffix
		"aikey_team_" + hex64,                       // wrong prefix
		"sk-" + hex64,                               // not aikey
		"",
	}
	for _, tok := range rejects {
		if isTier1Personal(tok) {
			t.Errorf("isTier1Personal(%q) = true, want false", tok)
		}
	}
}

// Strict form check for the app bearer predicate — mirrors
// TestIsTier1Personal_StrictForm. Both predicates share the underlying
// hasStrictHex64Suffix helper, so this also pins the shared invariant.
func TestIsTier1App_StrictForm(t *testing.T) {
	hex64 := strings.Repeat("0", 64)
	if !isTier1App("aikey_app_" + hex64) {
		t.Error("must accept aikey_app_<64 zeros>")
	}
	if !isTier1App("aikey_app_" + strings.Repeat("abcdef0123456789", 4)) {
		t.Error("must accept aikey_app_<64 lowercase hex>")
	}

	rejects := []string{
		"aikey_app_" + strings.Repeat("0", 63), // 63
		"aikey_app_" + strings.Repeat("0", 65), // 65
		"aikey_app_" + strings.Repeat("A", 64), // uppercase
		"aikey_app_" + strings.Repeat("g", 64), // non-hex
		"aikey_app_my-alias",                   // alias-like form
		"aikey_app_",                           // empty suffix
		"aikey_personal_" + hex64,              // wrong prefix (personal, not app)
		"aikey_team_" + hex64,                  // wrong prefix (team)
		"sk-" + hex64,                          // not aikey
		"",
	}
	for _, tok := range rejects {
		if isTier1App(tok) {
			t.Errorf("isTier1App(%q) = true, want false", tok)
		}
	}
}
