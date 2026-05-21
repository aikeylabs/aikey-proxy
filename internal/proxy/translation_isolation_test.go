package proxy

// translation_isolation_test.go — Phase 2 Day 7 isolation护栏.
//
// CLAUDE.md「版型意识」/「source-of-truth 不要分裂」/ audit at
// `workflow/CI/e2e/cases/2026-05-20-translate-openai-to-anthropic.md` §0
// 都要求 Phase 2 翻译层不能污染 Tier 1 (虚拟密钥) / Tier 2 (原始 provider key)
// 路径。这份文件锁死该承诺，使任何后续 PR 不小心把 ResponseTransform 设到
// 共享路径上时立即红。
//
// 三类断言:
//
//	1. 静态: 注册到 vkeys.Registry 的所有路由的 ResponseTransform 必须为 nil
//	   (registry 是 Tier 1/2 的真相源；handleAppPipeline 每请求构造新的
//	   appResolvedRoute，不应写回 registry).
//	2. 行为: 通过 Tier 1 (personal_byok) 完整跑一次 happy-path,断言上游收到
//	   的 body 与客户端发出的 body 字节相同 (modulo provider 适配器加 header),
//	   路径未被改写 (`/v1/chat/completions` 保留)。如果 Phase 2 误改了共享
//	   path 重写或 body 重写,此断言会红。
//	3. 行为: 同 (2),但用 Anthropic Tier 1 路由 (provider/anthropic.go
//	   RewriteRequest 才是变更高危区),断言 path `/v1/messages` 未被任何
//	   "翻译器顺手优化" 触动。
//
// 这是 belts-and-braces:即便 (1) 失守,(2)(3) 行为级也兜底;反之亦然。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── 1. Static: registry-stored routes have ResponseTransform == nil ─────

func TestIsolation_RegistryRoutesHaveNoResponseTransform(t *testing.T) {
	// setupTestProxy seeds two Tier 1 routes (openai + anthropic) and runs
	// proxy.New() which blank-imports the openai_anthropic translator pair
	// via main.go (in the binary; tests import the package directly via the
	// proxy package's own transitive imports). The translator pair init()
	// registers itself with translator.DefaultRegistry() — completely
	// independent of vkeys.Registry. This test guards the boundary:
	// vkeys.Registry must NEVER carry a ResponseTransform on its routes,
	// because that field is constructed per-request by apppipe and attached
	// to a route value local to handleAppPipeline.
	p := setupTestProxy(t, "http://unused")

	// Drain the registry — there's no public iterator, so we look up each
	// known fixture token (mirrors what production startup tooling does).
	for _, token := range []string{
		"aikey_team_openai_test",
		"aikey_team_anthropic_test",
	} {
		route := p.registry.Resolve(token)
		if route == nil {
			t.Fatalf("fixture missing token %q from registry", token)
		}
		if route.ResponseTransform != nil {
			t.Errorf("registry token %q has ResponseTransform != nil — Phase 2 translator must NEVER write back into the shared registry; only app pipeline's per-request route should carry this", token)
		}
	}
}

// ── 2. Behavioral: Tier 1 OpenAI path forwards body + path verbatim ─────

func TestIsolation_Tier1OpenAIBodyAndPathUnchanged(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"chatcmpl-iso","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	// Body deliberately contains response_format which the App pipeline's
	// translator WOULD synthesize a tool-call from — if the translator
	// were wrongly attached to Tier 1, this body shape would change.
	clientBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_object"}}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(clientBody))
	req.Header.Set("Authorization", "Bearer aikey_team_openai_test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Tier 1 happy path failed: %d %s", w.Code, w.Body.String())
	}

	// Body must be byte-identical (no translator side effects).
	if string(capturedBody) != clientBody {
		t.Errorf("Tier 1 upstream body changed by some downstream layer:\nclient sent: %s\nupstream got: %s", clientBody, string(capturedBody))
	}
	// Path must be /v1/chat/completions verbatim — NOT /v1/messages or any
	// translator-canonicalized variant.
	if capturedPath != "/v1/chat/completions" {
		t.Errorf("Tier 1 upstream path = %q, want /v1/chat/completions (translator must NOT touch Tier 1 path)", capturedPath)
	}
	// Client must see the upstream body verbatim (no Anthropic→OpenAI
	// translation injected on the response side either).
	if !strings.Contains(w.Body.String(), `"chatcmpl-iso"`) {
		t.Errorf("Tier 1 client response was modified by some translator hook: %s", w.Body.String())
	}
}

// ── 3. Behavioral: Tier 1 Anthropic path keeps /v1/messages verbatim ────

func TestIsolation_Tier1AnthropicPathUnchanged(t *testing.T) {
	// The risk this test guards: someone "helpfully" makes the Anthropic
	// provider adapter rewrite /v1/chat/completions → /v1/messages so the
	// App pipeline's cross-protocol case works. That would ALSO redirect
	// a Tier 1 user who sent the wrong path (or a future endpoint).
	// We assert the inbound path passes through unchanged for Tier 1.
	var capturedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	body := `{"model":"claude-sonnet-4-5-20250929","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("x-api-key", "aikey_team_anthropic_test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Tier 1 Anthropic happy path failed: %d %s", w.Code, w.Body.String())
	}
	if capturedPath != "/v1/messages" {
		t.Errorf("Tier 1 Anthropic upstream path = %q, want /v1/messages (translator must NOT touch this)", capturedPath)
	}
}

// ── 4. Static: Proxy.translatorRegistry initialized to DefaultRegistry ──

func TestIsolation_ProxyHasTranslatorRegistry(t *testing.T) {
	// proxy.New must wire translatorRegistry by default so handleAppPipeline
	// has a non-nil registry to consult. A nil registry would panic on the
	// first translation attempt — better to nil-check at construction time
	// than at first request.
	p := setupTestProxy(t, "http://unused")
	if p.translatorRegistry == nil {
		t.Fatal("Proxy.translatorRegistry is nil after New() — must default to translator.DefaultRegistry()")
	}
}
