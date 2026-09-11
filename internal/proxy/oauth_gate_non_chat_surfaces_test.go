package proxy

import (
	"net/http"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// Fences for the call path every OAuth lane shares (bridgeOrRejectDialect), not
// for the gate function alone.
//
// 🔴 Why these exist (2026-09-10). #45 deliberately kept refusing /completions
// and /embeddings on a ChatGPT OAuth credential: the codex backend serves
// neither, and forwarding them hands the client the upstream's misleading
// error instead of a sentence naming the real problem. #44 then put the dialect
// bridge in front of the gate, and the bridge returns early for every path it
// does not recognise as a chat dialect — so the gate was never consulted for
// those two paths again, and both were forwarded upstream.
//
// TestOAuthUpstreamRejectsPath_CodexResponsesOnly stayed green throughout,
// because it tests the gate FUNCTION, which never changed. What broke was
// whether anything calls it. These tests go through the entry point the four
// lanes (personal, probe, binding forward, group) all use.
//
// Bugfix: workflow/CI/bugfix/20260910-bridge-dropped-the-gate-for-non-chat-surfaces.md
// Regression: R15 in versions/releases/v1.0.1-alpha.16/evidence/bug-regressions.md

// assertResponsesOnlyRefusal pins the refusal to exactly what the lanes wrote
// before #44 (writeJSONError(w, oauthResponsesOnlyStatus, "invalid_request_error",
// ErrCodeOAuthResponsesOnly, oauthUpstreamRejectsPath(...))) — status, type,
// code AND wording, since the wording carries the remedy users act on.
func assertResponsesOnlyRefusal(t *testing.T, path string, refusal *dialectRefusal) {
	t.Helper()
	if refusal == nil {
		t.Fatalf("%s was not refused: a ChatGPT OAuth credential would forward it to a backend that does not serve it", path)
	}
	want := oauthUpstreamRejectsPath("openai", path)
	if want == "" {
		t.Fatalf("test bug: the gate itself does not refuse %s", path)
	}
	if refusal.Status != oauthResponsesOnlyStatus || refusal.ErrorType != "invalid_request_error" ||
		refusal.Code != observability.ErrCodeOAuthResponsesOnly || refusal.Message != want {
		t.Fatalf("%s refused with %+v; want status=%d type=invalid_request_error code=%s message=%q",
			path, *refusal, oauthResponsesOnlyStatus, observability.ErrCodeOAuthResponsesOnly, want)
	}
}

func TestBridgeGate_ForeignNonChatSurfacesAreRefusedBeforeTheCodexUpstream(t *testing.T) {
	for _, bridge := range []struct {
		name string
		make func() *Proxy
	}{
		{"bridge off (default)", func() *Proxy { return &Proxy{} }},
		{"bridge on, nothing declared", func() *Proxy { p := &Proxy{}; p.SetChatCompletionsBridge(true, nil); return p }},
	} {
		for _, path := range []string{"/v1/completions", "/v1/embeddings", "/completions", "/embeddings", "/v1/embeddings/"} {
			t.Run(bridge.name+" "+path, func(t *testing.T) {
				p := bridge.make()
				r := bridgeRequest(t, path, `{"model":"x","input":"hi"}`)
				_, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
				assertResponsesOnlyRefusal(t, path, refusal)
			})
		}
	}
}

// TestBridgeGate_SurfacesCodexServesStayUntouched keeps #45's half of the
// bargain: the backend serves these, so refusing them is the defect #45 fixed.
func TestBridgeGate_SurfacesCodexServesStayUntouched(t *testing.T) {
	for _, path := range []string{"/v1/models", "/v1/images/generations", "/v1/images/edits", "/models"} {
		t.Run(path, func(t *testing.T) {
			p := &Proxy{}
			r := bridgeRequest(t, path, "")
			out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
			if refusal != nil {
				t.Fatalf("%s refused (%+v) — the codex backend serves it", path, *refusal)
			}
			if out.URL.Path != path || bridgeFromContext(out.Context()) != nil {
				t.Fatalf("%s was rewritten or bridged; it must flow exactly as sent", path)
			}
		})
	}
}

// TestBridgeGate_DeclaredRelaysKeepPassThroughForNonChatSurfaces — the refusal
// is a statement about the ChatGPT codex backend ("serves the Responses API").
// It is false for a relay an operator declared, which may well serve
// /embeddings, so #44's pass-through must survive for those destinations.
func TestBridgeGate_DeclaredRelaysKeepPassThroughForNonChatSurfaces(t *testing.T) {
	const respHost, respBase = "responses-relay.gate-fence.example", "https://responses-relay.gate-fence.example/v1"
	for _, c := range []struct {
		name  string
		rules []BridgeUpstreamRule
		base  string
	}{
		{"chat_completions relay", relayRules(), relayBase},
		{"responses relay", []BridgeUpstreamRule{{Host: respHost, Dialect: "responses"}}, respBase},
	} {
		for _, path := range []string{"/v1/completions", "/v1/embeddings"} {
			t.Run(c.name+" "+path, func(t *testing.T) {
				p := &Proxy{}
				p.SetChatCompletionsBridge(true, c.rules)
				if got := p.oauthUpstreamBase("openai", "openai_compatible", c.base, quietLogger()); got != c.base {
					t.Fatalf("test premise: declared relay resolved to %q, want %q", got, c.base)
				}
				r := bridgeRequest(t, path, `{"model":"x","input":"hi"}`)
				out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", c.base, quietLogger())
				if refusal != nil {
					t.Fatalf("%s to a declared %s was refused (%+v); the codex-only sentence does not describe that host", path, c.name, *refusal)
				}
				if out.URL.Path != path {
					t.Fatalf("%s was rewritten to %s", path, out.URL.Path)
				}
			})
		}
	}
}

// Keep net/http referenced for readers grepping the status constant's type.
var _ = http.StatusUnprocessableEntity
