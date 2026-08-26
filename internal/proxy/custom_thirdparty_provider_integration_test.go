package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// Integration regression for the 2026-08-25 custom third-party provider defect.
//
// # What broke
//
// The console's "third-party provider" mode lets an administrator type a
// provider code of their own (its help text recommends the flow for Ollama /
// LM Studio / vLLM) with a hand-entered Base URL. master allows such a provider
// on purpose — validateProviderProtocol returns nil for anything absent from the
// compatibility matrix — and the Rust CLI routes it through the protocol's
// client surface. The proxy was the only one of the three that failed closed, so
// from 2026-07-24 (a7de5ac, which introduced the axes check) every such
// credential could be created, displayed as a working channel, and then answer
//
//	502 Active binding is invalid: provider "…" does not support protocol_type "openai_compatible"
//
// on its very first request. Before a7de5ac the binding path read ProviderCode /
// ProtocolType verbatim, which is why this had worked until then.
//
// # Why these are integration tests and not more unit cases
//
// binding_axes_test.go already pins the axes matrix. It cannot show that the
// request actually REACHES an upstream: that needs the credential lookup, the
// protocol-keyed adapter, the base_url overlay and the URL stitch to line up
// too. These drive p.Handle end to end against an httptest upstream, which is
// the same shape the reported failure had.
//
// Docs: workflow/CI/bugfix/20260825-custom-thirdparty-provider-axes-rejected.md
// Spec: workflow/CI/requirements/2026-07-18-provider-protocol-compatibility-and-baseurl.md
//       §自定义第三方供应商
// Run:  make test-bugfix-custom-provider-axes

// relayVaultFixture builds the exact shape the console + CLI produce for a
// custom third-party provider: the binding names the custom vendor while the
// client route stays the protocol's own surface, and the upstream address
// arrives as a provider_base_urls entry keyed by that custom code.
// providerCode stays a parameter even though every current case passes
// "thirdparty_relay": naming it at each call site is what makes the four tests
// below readable as "a CUSTOM vendor code paired with a standard client route"
// — the exact pairing this fixture exists to model. Collapsing it to a constant
// to satisfy unparam would hide the axis under test and delete the knob a
// second custom vendor case needs.
//
//nolint:unparam // deliberate: see above
func relayVaultFixture(clientRoute, providerCode, protocol, baseURL string) *mockActiveVault {
	return &mockActiveVault{
		providerBindings: map[string]*vault.ProviderBinding{
			clientRoute: {
				ClientRoute:   clientRoute,
				ProviderCode:  providerCode,
				ProtocolType:  protocol,
				KeySourceType: "team",
				KeySourceRef:  "vk-relay",
			},
		},
		activeTeamKeys: map[string]*vault.ManagedKey{
			providerCode: {
				VirtualKeyID:     "vk-relay",
				LocalAlias:       "relay-1",
				ProviderCode:     providerCode,
				ProtocolType:     protocol,
				BaseURL:          baseURL,
				PlaintextKey:     "sk-relay-test",
				ProviderBaseURLs: map[string]string{providerCode: baseURL},
			},
		},
	}
}

func TestCustomThirdPartyProvider_OpenAIRelayRoutesEndToEnd(t *testing.T) {
	var gotPath, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"resp_1","object":"response","model":"gpt-4o-mini","usage":{"input_tokens":3,"output_tokens":4}}`))
	}))
	defer upstream.Close()

	p := setupTestProxyWithActive(t, relayVaultFixture("openai", "thirdparty_relay", "openai_compatible", upstream.URL))

	// The reported request, verbatim: an OpenAI Responses API client pointed at
	// the proxy's openai surface.
	req := httptest.NewRequest(http.MethodPost, "/openai/responses",
		strings.NewReader(`{"model":"gpt-4o-mini","input":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	if gotPath != "/responses" {
		t.Errorf("upstream path = %q, want /responses (the /openai client namespace must be stripped whole)", gotPath)
	}
	// Proves the adapter was chosen by PROTOCOL, not by provider code: an
	// unknown vendor still gets OpenAI's bearer-token shape.
	if gotAuth != "Bearer sk-relay-test" {
		t.Errorf("upstream Authorization = %q, want Bearer sk-relay-test", gotAuth)
	}
}

func TestCustomThirdPartyProvider_AnthropicRelayRoutesEndToEnd(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"msg","type":"message","content":[],"model":"claude-3","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	p := setupTestProxyWithActive(t, relayVaultFixture("anthropic", "thirdparty_relay", "anthropic", upstream.URL))

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages",
		strings.NewReader(`{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":5}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	if gotPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", gotPath)
	}
}

// A custom provider has no routing-table row to supply a default address, so an
// empty base_url must be reported as the actionable configuration gap it is
// rather than handed to the reverse proxy, which answered the unactionable
// `http: no Host in request URL`.
func TestCustomThirdPartyProvider_MissingBaseURLIsNamed(t *testing.T) {
	p := setupTestProxyWithActive(t, relayVaultFixture("openai", "thirdparty_relay", "openai_compatible", ""))

	req := httptest.NewRequest(http.MethodPost, "/openai/responses",
		strings.NewReader(`{"model":"gpt-4o-mini","input":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	body := w.Body.String()
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 — body: %s", w.Code, body)
	}
	if !strings.Contains(body, "UPSTREAM_BASE_URL_MISSING") {
		t.Errorf("body = %s, want error code UPSTREAM_BASE_URL_MISSING", body)
	}
	// The remedy must be in the message; a bare code sends the operator hunting.
	for _, want := range []string{"thirdparty_relay", "Base URL"} {
		if !strings.Contains(body, want) {
			t.Errorf("body = %s, want it to mention %q", body, want)
		}
	}
	if strings.Contains(body, "no Host in request URL") {
		t.Errorf("the raw reverse-proxy message leaked to the client: %s", body)
	}
}

// The widening admits a DECLARED protocol, not any string. An invented one is
// still refused at the axes check.
func TestCustomThirdPartyProvider_InventedProtocolStillRejected(t *testing.T) {
	p := setupTestProxyWithActive(t, relayVaultFixture("openai", "thirdparty_relay", "not_a_protocol", "http://unused.invalid"))

	req := httptest.NewRequest(http.MethodPost, "/openai/responses",
		strings.NewReader(`{"model":"gpt-4o-mini","input":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	body := w.Body.String()
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 — body: %s", w.Code, body)
	}
	if !strings.Contains(body, "BINDING_AXES_INVALID") {
		t.Errorf("body = %s, want BINDING_AXES_INVALID", body)
	}
}
