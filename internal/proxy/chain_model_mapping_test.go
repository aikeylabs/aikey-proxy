package proxy

// chain_model_mapping_test.go — per-hop model mapping on a MIXED chain
// (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 2.4 / 2.29 / 2.30,
// invariant I27).
//
// # 🔴 Why this is not optional
//
// The textbook chain for this feature is "the vendor's own API, plus GLM" — and
// GLM's model map is `sonnet → glm-4.5` with `unmatched: reject`. Two obvious
// implementations both fail, and both fail in the same misleading way:
//
//	replay the body verbatim      → GLM receives `claude-sonnet-4-5`, which it
//	                                does not know. The hop fails.
//	reuse the previous hop's body → the vendor receives `glm-4.5`, which IT does
//	                                not know. The hop fails.
//
// Either way our failover dutifully walks the whole chain and reports "no
// upstream is available" — while EVERY UPSTREAM IS HEALTHY. The chain is not
// broken in a way that points at itself.
//
// The correct statement has two halves (I27):
//
//	client-side  the name never changes. The user sends `claude-sonnet-4-5` and
//	             the response says `claude-sonnet-4-5`, whoever served it.
//	upstream-side the name is computed per hop, from THAT hop's vendor.
//
// 🚫 This is not "switching models" (that is the second layer, deliberately out
// of scope). It is the same model spelled two ways by two vendors.
//
// These tests use the REAL provider registry — `open.bigmodel.cn/api/anthropic`
// is zhipu with the map above — because a hand-stubbed table would prove only
// that the stub works.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// mixedChain registers a two-hop chain across two DIFFERENT vendors, in the
// given order, with real base URLs the provider table recognises.
func mixedChain(t *testing.T, first, second struct{ code, baseURL, bindingID string }) (*Proxy, *chainCapture) {
	t.Helper()
	p := setupTestProxy(t, "http://unused.invalid")
	mk := func(code, baseURL, bindingID string, priority int64) *vkeys.ResolvedRoute {
		return &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-mixed", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: code, RouteSource: "team",
			BaseURL: baseURL, PlaintextKey: "key-" + bindingID, BindingID: bindingID,
			Priority: priority, RouteGroupID: "rg-mixed", RouteGroupName: "mixed",
		}
	}
	a := mk(first.code, first.baseURL, first.bindingID, 1)
	b := mk(second.code, second.baseURL, second.bindingID, 2)
	container := *a
	container.Bindings = []*vkeys.ResolvedRoute{a, b}
	container.BaseURL = ""
	container.PlaintextKey = ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_chaintest": &container})
	cap := &chainCapture{statusByHost: map[string]int{}, headerByHost: map[string]http.Header{}, bodyByHost: map[string]string{}}
	p.SetTransport(cap)
	return p, cap
}

type hop = struct{ code, baseURL, bindingID string }

// 🔴 2.29 + 2.4: each hop sends ITS vendor's name; the client's name never moves.
func TestChainMapping_EachHopSendsItsOwnVendorsModelName(t *testing.T) {
	p, cap := mixedChain(t,
		hop{"anthropic", "https://api.anthropic.com", "b-official"},
		hop{"zhipu", "https://open.bigmodel.cn/api/anthropic", "b-glm"})
	cap.statusByHost["api.anthropic.com"] = 503
	// GLM echoes its OWN model name, as a real upstream would.
	cap.bodyByHost["open.bigmodel.cn"] = `{"id":"msg_1","model":"glm-4.5","content":[]}`

	req, w := chainReq()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(cap.models) != 2 {
		t.Fatalf("made %d upstream attempts, want 2: %v", len(cap.models), cap.models)
	}
	if cap.models[0] != "claude-sonnet-4-5" {
		t.Errorf("hop 1 (the vendor's own API) sent %q, want the client's name unchanged", cap.models[0])
	}
	if cap.models[1] != "glm-4.5" {
		t.Errorf("hop 2 (GLM) sent %q, want %q.\n"+
			"Replaying the body verbatim makes GLM reject a name it does not know, and the "+
			"chain then reports 'no upstream available' while every upstream is healthy",
			cap.models[1], "glm-4.5")
	}
	// 🔴 The client's half of I27: the upstream name must not leak out.
	if body := w.Body.String(); strings.Contains(body, "glm-4.5") {
		t.Errorf("the upstream's model name reached the client: %s\n"+
			"The user asked for claude-sonnet-4-5 and must get claude-sonnet-4-5 back, "+
			"whoever served it", body)
	}
	if body := w.Body.String(); !strings.Contains(body, "claude-sonnet-4-5") {
		t.Errorf("the client's own model name was not restored: %s", w.Body.String())
	}
}

// 🔴 2.30: a hop whose map REJECTS the model is skipped, not answered.
//
// Today's code writes MODEL_MAPPING_NOT_FOUND straight to the client. Inside a
// candidate loop that promotes "the second choice does not speak this model" into
// "your request failed" — while the hop that CAN serve it may not have been asked.
func TestChainMapping_RejectingHopIsSkippedRatherThanAnswered(t *testing.T) {
	// GLM first, so its rejection happens before the vendor is ever tried.
	p, cap := mixedChain(t,
		hop{"zhipu", "https://open.bigmodel.cn/api/anthropic", "b-glm"},
		hop{"anthropic", "https://api.anthropic.com", "b-official"})

	req, w := chainReqWithModel("claude-not-a-real-tier-9")
	p.Handle(w, req)

	if strings.Contains(w.Body.String(), "MODEL_MAPPING_NOT_FOUND") {
		t.Fatalf("a hop that cannot serve this model answered the client: %s\n"+
			"Inside a chain that turns 'this ONE upstream does not speak the model' into "+
			"'the request failed', while the upstream that does speak it was never asked",
			w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want the next hop to have served it", w.Code, w.Body.String())
	}
	dialled := cap.dialled()
	if len(dialled) != 1 || dialled[0] != "api.anthropic.com" {
		t.Fatalf("dialled %v, want only the vendor: GLM must be skipped WITHOUT a round trip, "+
			"since we already know its map rejects the name", dialled)
	}
	// 🔴 And the skipped hop must NOT be cooled: it is healthy, it simply does not
	// speak this model. Cooling it would make an unrelated later request skip a
	// working upstream.
	if _, cooling := p.bindingCooldown.cooling("b-glm", time.Now()); cooling {
		t.Error("a model-map rejection cooled the upstream. The hop is healthy — it just " +
			"does not speak this model — so a later request for a model it DOES speak " +
			"would skip a working upstream for no reason")
	}
}

// chainReqWithModel builds a request naming a specific model.
func chainReqWithModel(model string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages",
		strings.NewReader(`{"model":"`+model+`","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_chaintest")
	return req, httptest.NewRecorder()
}
