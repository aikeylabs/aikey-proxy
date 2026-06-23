package apppipe

// Phase 2 中方案 (2026-05-21) — MaybeTranslateRequest matrix tests.
//
// The translator pair-level tests live in pkg/protocol-translator/...; these
// tests pin the App-pipeline-level orchestration: which (inboundFmt, upstream)
// combinations engage translation vs fast-path vs reject.
//
// Matrix coverage:
//   - OpenAI    in + OpenAI    out  → fast path (Engaged=false)
//   - OpenAI    in + Anthropic out  → translate (Engaged=true, body changes)
//   - Anthropic in + Anthropic out  → fast path (Engaged=false) ← NEW in 中方案
//   - Anthropic in + OpenAI    out  → REJECT 501 TRANSLATION_PAIR_NOT_REGISTERED ← NEW
//
// We use a separate translator.Registry per test (not DefaultRegistry()) to
// isolate from blank-import side effects.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"

	// Side-effect import: registers the openai → anthropic pair with
	// translator.DefaultRegistry(). We don't use DefaultRegistry directly
	// (we build local registries below) but it's worth importing here so
	// the tests run in the same Format-availability shape as production.
	_ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/openai_anthropic"
)

// helper: build a registry seeded with the production pair set.
func newTestRegistry() *translator.Registry {
	r := translator.NewRegistry()
	// Register openai → anthropic identity-aware request transform.
	r.Register(
		translator.FormatOpenAI,
		translator.FormatAnthropic,
		func(_ context.Context, model string, body []byte, _ bool) ([]byte, *translator.TranslateError) {
			// Minimal fake: prepend a marker so the test can assert
			// translation engaged. Real translator is exercised by
			// pkg/protocol-translator/pairs/openai_anthropic/... tests.
			return []byte(`{"translated":true,"model":"` + model + `","raw":` + string(body) + `}`), nil
		},
		translator.ResponseTransforms{
			NonStream: func(_ context.Context, body []byte) ([]byte, *translator.TranslateError) {
				return body, nil
			},
		},
	)
	return r
}

// reuse this helper without re-plumbing.
//
//nolint:unparam // `method` kept parameterized so non-POST cases can
func freshHTTPRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(""))
	return r
}

func newAppRoute() *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		VirtualKeyID: "app:test",
		RouteSource:  "app",
		AppSlug:      "test",
		AppKind:      "third-party",
		AppKeyID:     "uuid-test",
	}
}

// ─── Fast path: from == to ────────────────────────────────────────────

func TestMaybeTranslate_OpenAIInOpenAIOut_FastPath(t *testing.T) {
	reg := newTestRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "openai", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatOpenAI, freshHTTPRequest("POST", "/apps/test/v1/chat/completions"),
		body, "gpt-4o",
	)
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if out.Engaged {
		t.Errorf("Engaged = true; same-wire must be fast path (no translation)")
	}
	if string(out.Body) != string(body) {
		t.Errorf("body changed on fast path:\n  in:  %s\n  out: %s", body, out.Body)
	}
	if route.ResponseTransform != nil {
		t.Errorf("ResponseTransform armed on fast path — should stay nil")
	}
}

func TestMaybeTranslate_AnthropicInAnthropicOut_FastPath(t *testing.T) {
	// ← The new中方案 case: Cursor / Claude Code sends Anthropic-shape
	// body to an Anthropic-bound app. Zero translation, byte-identical
	// passthrough. ResponseTransform stays nil.
	reg := newTestRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"claude-3-5-sonnet-20241022","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatAnthropic, freshHTTPRequest("POST", "/apps/test/v1/messages"),
		body, "claude-3-5-sonnet-20241022",
	)
	if err != nil {
		t.Fatalf("expected success on Anthropic→Anthropic passthrough, got %+v", err)
	}
	if out.Engaged {
		t.Errorf("Engaged = true; same-wire passthrough must NOT trigger translation")
	}
	if string(out.Body) != string(body) {
		t.Errorf("body changed on passthrough:\n  in:  %s\n  out: %s", body, out.Body)
	}
	if route.ResponseTransform != nil {
		t.Errorf("ResponseTransform armed on passthrough — Cursor / Claude Code expects byte-identical response")
	}
}

// ─── Translation engaged: OpenAI in + Anthropic out (existing) ─────────

func TestMaybeTranslate_OpenAIInAnthropicOut_Translates(t *testing.T) {
	reg := newTestRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatOpenAI, freshHTTPRequest("POST", "/apps/test/v1/chat/completions"),
		body, "claude-3-5-sonnet-20241022",
	)
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if !out.Engaged {
		t.Errorf("Engaged = false; cross-wire MUST translate")
	}
	if !strings.Contains(string(out.Body), `"translated":true`) {
		t.Errorf("translator transform didn't fire; body = %s", out.Body)
	}
	if route.ResponseTransform == nil {
		t.Errorf("ResponseTransform not armed — response side will be raw Anthropic, breaking OpenAI clients")
	}
}

// ─── Reject: Anthropic in + OpenAI out (no pair registered) ────────────

func TestMaybeTranslate_AnthropicInOpenAIOut_RejectsLoudly(t *testing.T) {
	reg := newTestRegistry() // only has openai → anthropic, NOT the reverse
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "openai", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"gpt-4o","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`)

	_, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatAnthropic, freshHTTPRequest("POST", "/apps/test/v1/messages"),
		body, "gpt-4o",
	)
	if err == nil {
		t.Fatalf("expected loud 501, got success (this combination is not supported in 中方案)")
	}
	if err.StatusCode != http.StatusNotImplemented {
		t.Errorf("StatusCode = %d, want 501", err.StatusCode)
	}
	if err.ErrorCode != "TRANSLATION_PAIR_NOT_REGISTERED" {
		t.Errorf("ErrorCode = %q, want TRANSLATION_PAIR_NOT_REGISTERED", err.ErrorCode)
	}
}

// ─── Empty inboundFmt defaults to OpenAI (defensive) ───────────────────

func TestMaybeTranslate_EmptyInboundFmt_DefaultsToOpenAI(t *testing.T) {
	// InferInboundWire never returns empty in production, but the
	// defensive default in MaybeTranslateRequest is a safety net. Pin it.
	reg := newTestRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "openai", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"gpt-4o","messages":[]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.Format(""), freshHTTPRequest("POST", "/apps/test/v1/chat/completions"),
		body, "gpt-4o",
	)
	if err != nil {
		t.Fatalf("empty inboundFmt should fall back to OpenAI default, got error %+v", err)
	}
	if out.Engaged {
		t.Errorf("Engaged = true; empty-fmt → OpenAI default → matches openai upstream → fast path")
	}
}

// ─── Streaming with cross-wire is still rejected (Day 5 invariant) ─────

func TestMaybeTranslate_StreamingCrossWire_StillRejects(t *testing.T) {
	// The pre-中方案 rule held: cross-wire + stream=true → 501.
	// 中方案 doesn't change this; verify still works.
	reg := newTestRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"claude-3-5","messages":[],"stream":true}`)

	_, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatOpenAI, freshHTTPRequest("POST", "/apps/test/v1/chat/completions"),
		body, "claude-3-5",
	)
	if err == nil {
		t.Fatalf("expected stream reject, got success")
	}
	if err.ErrorCode != "STREAM_TRANSLATION_NOT_SUPPORTED" {
		t.Errorf("ErrorCode = %q, want STREAM_TRANSLATION_NOT_SUPPORTED", err.ErrorCode)
	}
}

// ─── G1 fix: provider/ prefix stripping ────────────────────────────────

// TestMaybeTranslate_PrefixStrippedOnPassthrough is the G1 regression
// (2026-05-21). When the user sends OpenCode-style "anthropic/claude-..."
// and the upstream IS anthropic directly, the prefix must be stripped
// before the body reaches Anthropic (which otherwise 400s).
//
// This test pins the passthrough (Anthropic in → Anthropic out) variant.
func TestMaybeTranslate_PrefixStrippedOnPassthrough(t *testing.T) {
	reg := newTestRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"anthropic/claude-3-5-sonnet-20241022","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatAnthropic, freshHTTPRequest("POST", "/apps/test/v1/messages"),
		body, "anthropic/claude-3-5-sonnet-20241022",
	)
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if out.Engaged {
		t.Errorf("Engaged=true; passthrough should be fast path")
	}
	// Body MUST have been rewritten to strip the prefix.
	if !strings.Contains(string(out.Body), `"model":"claude-3-5-sonnet-20241022"`) {
		t.Errorf("body.model still has prefix; got body=%s", out.Body)
	}
	if strings.Contains(string(out.Body), `"anthropic/claude-3-5-sonnet-20241022"`) {
		t.Errorf("prefix NOT stripped; got body=%s", out.Body)
	}
}

// TestMaybeTranslate_PrefixStrippedOnTranslate is the cross-wire variant
// (OpenAI in → Anthropic out, with "anthropic/" prefix in body.model).
// Translator receives the normalized model arg so the translated body
// has the bare model name.
func TestMaybeTranslate_PrefixStrippedOnTranslate(t *testing.T) {
	reg := newTestRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"anthropic/claude-3-5-sonnet-20241022","messages":[]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatOpenAI, freshHTTPRequest("POST", "/apps/test/v1/chat/completions"),
		body, "anthropic/claude-3-5-sonnet-20241022",
	)
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if !out.Engaged {
		t.Errorf("Engaged=false; cross-wire MUST translate")
	}
	// The fake translator in newTestRegistry echoes "model" — assert the
	// normalized form (no prefix) reached it.
	if !strings.Contains(string(out.Body), `"model":"claude-3-5-sonnet-20241022"`) {
		t.Errorf("translator received un-normalized model; got body=%s", out.Body)
	}
}

// TestMaybeTranslate_PrefixPreservedForAggregatorSubRoute_FastPath
// verifies G1 + B cooperate: G1 strips outer "openrouter/" prefix from
// body.model (because binding.ProviderCode == "openrouter"); B classifies
// openai → openrouter as OpenAI-wire-compatible → fast path (no translator
// engagement). The inner "openai/gpt-5" sub-prefix is preserved for
// OpenRouter to route internally.
//
// Note: this test is the consolidated G1+B aggregator scenario. Pre-B,
// this case would have required a fake openai→openrouter translator
// pair; with B's fast-path it's a no-op + body rewrite.
func TestMaybeTranslate_PrefixPreservedForAggregatorSubRoute_FastPath(t *testing.T) {
	reg := translator.NewRegistry() // no pairs needed for fast path
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "openrouter", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"openrouter/openai/gpt-5","messages":[]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatOpenAI, freshHTTPRequest("POST", "/apps/test/v1/chat/completions"),
		body, "openrouter/openai/gpt-5",
	)
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if out.Engaged {
		t.Errorf("Engaged=true; OpenRouter is OpenAI-wire-compatible (B fix), must fast-path")
	}
	// G1 stripped the outer "openrouter/" prefix; "openai/gpt-5" preserved
	// for OpenRouter's internal routing.
	if !strings.Contains(string(out.Body), `"model":"openai/gpt-5"`) {
		t.Errorf("expected G1 to strip 'openrouter/' and preserve 'openai/gpt-5'; got body=%s", out.Body)
	}
}

// ─── B (2026-05-21): OpenAI-wire-compatible upstreams fast-path ─────────

// TestMaybeTranslate_OpenAIInKimiOut_FastPath verifies the B fix: Kimi
// is OpenAI-wire-compatible, so OpenAI→Kimi should be a fast path with
// NO translator pair needed. Without the fix this would 501.
func TestMaybeTranslate_OpenAIInKimiOut_FastPath(t *testing.T) {
	reg := translator.NewRegistry() // empty - no openai→kimi pair registered
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "kimi", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"kimi-k2-turbo-preview","messages":[{"role":"user","content":"hi"}]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatOpenAI, freshHTTPRequest("POST", "/apps/test/v1/chat/completions"),
		body, "kimi-k2-turbo-preview",
	)
	if err != nil {
		t.Fatalf("expected fast path success, got %+v", err)
	}
	if out.Engaged {
		t.Errorf("Engaged=true; Kimi is OpenAI-wire-compatible, should fast-path")
	}
	// Body unchanged (no translator engagement).
	if string(out.Body) != string(body) {
		t.Errorf("body changed on fast path:\n  in:  %s\n  out: %s", body, out.Body)
	}
	if route.ResponseTransform != nil {
		t.Errorf("ResponseTransform armed on fast path — should stay nil")
	}
}

// TestMaybeTranslate_OpenAIInOpenRouterOut_FastPath verifies aggregator
// gateways (OpenRouter / LiteLLM / Portkey) also fast-path.
func TestMaybeTranslate_OpenAIInOpenRouterOut_FastPath(t *testing.T) {
	reg := translator.NewRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "openrouter", KeySourceType: "personal", KeySourceRef: "k"}
	// Note: OpenCode-style prefix in model — G1's prefix-strip kicks in
	// AND OpenRouter's fast-path. Both layers cooperate.
	body := []byte(`{"model":"openrouter/openai/gpt-5-codex","messages":[]}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatOpenAI, freshHTTPRequest("POST", "/apps/test/v1/chat/completions"),
		body, "openrouter/openai/gpt-5-codex",
	)
	if err != nil {
		t.Fatalf("expected fast path success, got %+v", err)
	}
	if out.Engaged {
		t.Errorf("Engaged=true; OpenRouter is OpenAI-wire-compatible, should fast-path")
	}
	// G1 stripped the "openrouter/" prefix, body.model should now be
	// "openai/gpt-5-codex" (OpenRouter sub-route preserved).
	if !strings.Contains(string(out.Body), `"model":"openai/gpt-5-codex"`) {
		t.Errorf("expected outer 'openrouter/' stripped + 'openai/gpt-5-codex' kept; got body=%s", out.Body)
	}
}

// ─── Streaming SAME-wire is fine (passthrough doesn't need SSE reshaper) ─

func TestMaybeTranslate_StreamingSameWire_OK(t *testing.T) {
	// Anthropic→Anthropic with stream=true: passthrough, no SSE reshaping
	// needed because upstream SSE shape == client SSE shape. The stream
	// check in MaybeTranslateRequest only fires when translation is needed.
	reg := newTestRegistry()
	route := newAppRoute()
	binding := &vault.ProviderBinding{ProviderCode: "anthropic", KeySourceType: "personal", KeySourceRef: "k"}
	body := []byte(`{"model":"claude-3-5","messages":[],"stream":true,"max_tokens":1024}`)

	out, err := MaybeTranslateRequest(
		context.Background(), reg, route, binding,
		translator.FormatAnthropic, freshHTTPRequest("POST", "/apps/test/v1/messages"),
		body, "claude-3-5",
	)
	if err != nil {
		t.Fatalf("same-wire streaming should pass through, got %+v", err)
	}
	if out.Engaged {
		t.Errorf("Engaged = true; same-wire streaming is fast path")
	}
}
