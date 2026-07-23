package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/tidwall/gjson"
)

// P3 (design D-5): the response model name is restored to the client's
// original when the request was mapped — never a hardcoded constant.
func TestRestoreResponseModel(t *testing.T) {
	// mapping happened: ctx carries the client's original name
	ctx := context.WithValue(context.Background(), ctxKeyMappedClientModel, "claude-opus-4-8")
	upstream := []byte(`{"model":"glm-4.6","content":[{"text":"hi"}]}`)
	got := restoreResponseModel(ctx, upstream)
	if m := gjson.GetBytes(got, "model").String(); m != "claude-opus-4-8" {
		t.Errorf("restored model = %q, want claude-opus-4-8 (client's original)", m)
	}
	if gjson.GetBytes(got, "content.0.text").String() != "hi" {
		t.Errorf("restore clobbered non-model fields")
	}
	// no mapping: body unchanged
	plain := restoreResponseModel(context.Background(), upstream)
	if !bytes.Equal(plain, upstream) {
		t.Errorf("no-mapping restore must be a no-op")
	}
}

// P2 (design D-1): unit coverage for the mapping primitive against the shipped
// registry (zhipu model_map: opus→glm-4.6, sonnet→glm-4.5, haiku→glm-4.5-air,
// exact claude-opus-4-8→glm-4.6, unmatched=reject).

func bodyWithModel(m string) []byte {
	return []byte(`{"model":"` + m + `","messages":[{"role":"user","content":"hi"}]}`)
}

func TestApplyModelMapping_GLMExactAndRole(t *testing.T) {
	const glmAnthropic = "https://open.bigmodel.cn/api/anthropic"
	cases := []struct {
		requested string
		wantEff   string
	}{
		{"claude-opus-4-8", "glm-4.6"},   // exact
		{"claude-opus-4-9", "glm-4.6"},   // role opus (升版本不失效)
		{"claude-sonnet-4-6", "glm-4.5"}, // role sonnet
	}
	for _, c := range cases {
		body := bodyWithModel(c.requested)
		res := applyModelMapping(glmAnthropic, c.requested, body)
		if !res.Mapped || res.Reject {
			t.Errorf("%s: Mapped=%v Reject=%v, want mapped", c.requested, res.Mapped, res.Reject)
		}
		if res.Provider != "zhipu" {
			t.Errorf("%s: Provider=%q, want zhipu", c.requested, res.Provider)
		}
		if res.EffectiveModel != c.wantEff {
			t.Errorf("%s: EffectiveModel=%q, want %q", c.requested, res.EffectiveModel, c.wantEff)
		}
		if res.RequestedModel != c.requested {
			t.Errorf("%s: RequestedModel=%q (audit 双口径 must keep client name)", c.requested, res.RequestedModel)
		}
		// body model field must now be the upstream name
		if got := gjson.GetBytes(res.NewBody, "model").String(); got != c.wantEff {
			t.Errorf("%s: rewritten body model=%q, want %q", c.requested, got, c.wantEff)
		}
		// non-model fields preserved
		if gjson.GetBytes(res.NewBody, "messages.0.content").String() != "hi" {
			t.Errorf("%s: rewrite clobbered messages", c.requested)
		}
	}
}

func TestApplyModelMapping_RejectOnUnmatched(t *testing.T) {
	// zhipu map has unmatched:reject; a model with no exact/role/wildcard rule
	// must reject (not silently passthrough).
	body := bodyWithModel("gpt-4o")
	res := applyModelMapping("https://open.bigmodel.cn/api/anthropic", "gpt-4o", body)
	if !res.Reject {
		t.Fatalf("expected Reject for unmatched gpt-4o under reject policy")
	}
	if res.NewBody != nil {
		t.Errorf("reject must not rewrite body")
	}
}

func TestApplyModelMapping_PassthroughByteIdentical(t *testing.T) {
	// A provider with no model_map (anthropic official) must leave the body
	// byte-identical — zero blast radius for non-mapped traffic.
	body := bodyWithModel("claude-opus-4-8")
	orig := append([]byte(nil), body...)
	res := applyModelMapping("https://api.anthropic.com", "claude-opus-4-8", body)
	if res.Mapped || res.Reject {
		t.Errorf("anthropic official: Mapped=%v Reject=%v, want passthrough", res.Mapped, res.Reject)
	}
	if res.NewBody != nil {
		t.Errorf("passthrough must yield nil NewBody (no rewrite)")
	}
	if res.EffectiveModel != "claude-opus-4-8" {
		t.Errorf("passthrough EffectiveModel=%q, want unchanged", res.EffectiveModel)
	}
	if !bytes.Equal(body, orig) {
		t.Errorf("passthrough mutated the input body")
	}
}

func TestApplyModelMapping_UnknownHostNoMapping(t *testing.T) {
	// Host not in the table → no mapping, no reject (base_url fail-loud is P1j).
	res := applyModelMapping("https://unknown.example/v1", "claude-opus-4-8", bodyWithModel("claude-opus-4-8"))
	if res.Mapped || res.Reject || res.Provider != "" {
		t.Errorf("unknown host: got Mapped=%v Reject=%v Provider=%q, want inert", res.Mapped, res.Reject, res.Provider)
	}
}

func TestApplyModelMapping_EmptyModelNoop(t *testing.T) {
	res := applyModelMapping("https://open.bigmodel.cn/api/anthropic", "", []byte(`{}`))
	if res.Mapped || res.Reject {
		t.Errorf("empty model must be a no-op")
	}
}

// --- wiring-level integration (drives applyModelMappingToRequest end-to-end
// through a real *http.Request, no live upstream) ---

func newMappingReq(t *testing.T, model string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", bytes.NewReader(bodyWithModel(model)))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestWiring_RewritesGLMBodyAndContentLength(t *testing.T) {
	p := &Proxy{}
	r := newMappingReq(t, "claude-opus-4-8")
	w := httptest.NewRecorder()
	route := &vkeys.ResolvedRoute{BaseURL: "https://open.bigmodel.cn/api/anthropic", ProviderCode: "zhipu"}

	if !p.applyModelMappingToRequest(w, r, route, slog.Default()) {
		t.Fatal("expected proceed=true for mappable model")
	}
	got, _ := io.ReadAll(r.Body)
	if m := gjson.GetBytes(got, "model").String(); m != "glm-4.6" {
		t.Errorf("forwarded body model=%q, want glm-4.6", m)
	}
	if r.ContentLength != int64(len(got)) {
		t.Errorf("ContentLength=%d, want %d", r.ContentLength, len(got))
	}
	if r.Header.Get("Content-Length") != itoaInt64(int64(len(got))) {
		t.Errorf("Content-Length header not updated")
	}
}

func TestWiring_RejectAnswersWithErrorCode(t *testing.T) {
	p := &Proxy{}
	r := newMappingReq(t, "gpt-4o") // no rule, zhipu unmatched=reject
	w := httptest.NewRecorder()
	route := &vkeys.ResolvedRoute{BaseURL: "https://open.bigmodel.cn/api/anthropic", ProviderCode: "zhipu"}

	if p.applyModelMappingToRequest(w, r, route, slog.Default()) {
		t.Fatal("expected proceed=false on reject")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("MODEL_MAPPING_NOT_FOUND")) {
		t.Errorf("response missing MODEL_MAPPING_NOT_FOUND: %s", w.Body.String())
	}
	// Terse文案 must not point at a console switch (rev3).
	if bytes.Contains(w.Body.Bytes(), []byte("console")) || bytes.Contains(w.Body.Bytes(), []byte("控制台")) {
		t.Errorf("reject文案 must not reference a console switch: %s", w.Body.String())
	}
}

func TestWiring_NonMappedProviderInert(t *testing.T) {
	p := &Proxy{}
	r := newMappingReq(t, "claude-opus-4-8")
	w := httptest.NewRecorder()
	route := &vkeys.ResolvedRoute{BaseURL: "https://api.anthropic.com", ProviderCode: "anthropic"}

	if !p.applyModelMappingToRequest(w, r, route, slog.Default()) {
		t.Fatal("expected proceed=true (inert)")
	}
	got, _ := io.ReadAll(r.Body)
	if m := gjson.GetBytes(got, "model").String(); m != "claude-opus-4-8" {
		t.Errorf("non-mapped body model changed to %q, want unchanged", m)
	}
}

// TestWiring_AuditDualModel (P2.8/P4.1 audit 双口径): after mapping, the event
// records the EFFECTIVE upstream model (pricing) while RequestedModel keeps the
// CLIENT model — the two口径 do not collapse.
func TestWiring_AuditDualModel(t *testing.T) {
	p := &Proxy{}
	r := newMappingReq(t, "claude-opus-4-8")
	// extractModel stashes the client model as x-aikey-model (request-entry口径)
	r.Header.Set("x-aikey-model", "claude-opus-4-8")
	w := httptest.NewRecorder()
	route := &vkeys.ResolvedRoute{BaseURL: "https://open.bigmodel.cn/api/anthropic", ProviderCode: "zhipu"}
	if !p.applyModelMappingToRequest(w, r, route, slog.Default()) {
		t.Fatal("expected proceed")
	}
	resp := &http.Response{StatusCode: 200}
	ev := p.buildBaseEvent(r, resp, time.Now(), route, false)
	if ev.Model != "glm-4.6" {
		t.Errorf("ev.Model (effective/pricing) = %q, want glm-4.6", ev.Model)
	}
	if ev.RequestedModel != "claude-opus-4-8" {
		t.Errorf("ev.RequestedModel (client) = %q, want claude-opus-4-8", ev.RequestedModel)
	}
}

// TestApplyModelMapping_CodingEndpointOpenAI: the GLM openai coding endpoint
// resolves the same zhipu map (model_map is per-provider, endpoint-independent).
func TestApplyModelMapping_CodingEndpointSameMap(t *testing.T) {
	res := applyModelMapping("https://open.bigmodel.cn/api/coding/paas/v4", "claude-opus-4-8", bodyWithModel("claude-opus-4-8"))
	if !res.Mapped || res.EffectiveModel != "glm-4.6" {
		t.Errorf("coding endpoint mapping: Mapped=%v Eff=%q, want glm-4.6", res.Mapped, res.EffectiveModel)
	}
}
