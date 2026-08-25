package proxy

// Fence for bugfix 2026-08-25-empty-upstream-base-url-unhelpful-error
// (requirements 2026-07-18 §自定义第三方供应商 rule 4: "地址缺失由上游地址解析层
// 报自己的错误" — this is that rule's machine action).
//
// A custom (zero-matrix-rows) provider has NO shipped default endpoint, so a
// credential that carries no base URL anywhere is unroutable by construction.
// Before the guard, serveRoute pushed the empty base into the adapter's URL
// stitch, and the failure surfaced as whatever the transport said about a
// host-less URL — nothing in it named the credential, the provider, or the fix.
// serveRoute is the single funnel every real route passes through (its own
// quota-gate comment documents that), so one guard covers the team-binding,
// personal-binding, personal-alias, and Tier1 lanes at once.
//
// 能红: remove the empty-BaseURL guard at the top of serveRoute → the
// instructive-body assertions fail (the response degrades back to the opaque
// transport error).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestServeRoute_EmptyUpstreamBaseURLIsInstructive(t *testing.T) {
	p := setupTestProxy(t, "http://dummy.invalid")

	prov, err := p.providers.Get("openai_compatible")
	if err != nil {
		t.Fatalf("openai_compatible provider: %v", err)
	}
	// The exact shape a synced custom-provider credential with no
	// base_url_override and no provider default produces (team lane), and a
	// personal key without --base-url produces (default-binding lane).
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-no-base", Provider: "customtest", ProviderCode: "customtest",
		ProtocolType: "openai_compatible", PlaintextKey: "sk-fake", BaseURL: "",
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("content-type", "application/json")
	w := httptest.NewRecorder()

	p.serveRoute(w, req, route, prov, "sk-fake", "", time.Now(), discardLogger())

	body := w.Body.String()
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", w.Code, body)
	}
	if !strings.Contains(body, "UPSTREAM_BASE_URL_MISSING") {
		t.Errorf("body must carry the UPSTREAM_BASE_URL_MISSING code so operators can triage from the client error alone, got: %s", body)
	}
	// The error must name what is broken and what to change — the provider, the
	// credential-side fix (console Base URL) and the personal-key-side fix
	// (aikey add --base-url). Presence-of-words assertions, not exact prose, so
	// wording can improve without re-fencing.
	for _, needle := range []string{"customtest", "Base URL", "--base-url"} {
		if !strings.Contains(body, needle) {
			t.Errorf("instructive error must mention %q, got: %s", needle, body)
		}
	}
}
