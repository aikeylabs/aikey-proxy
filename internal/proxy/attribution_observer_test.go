package proxy

// Fix 2 fence: truthful provider attribution must reach the OBSERVER / rhythm-
// audit stream, not only the usage ledger. For a GLM binding DECLARED anthropic
// but pointed at GLM's /api/anthropic base_url (customer symptom (e)), the
// observer RequestContext.ProviderID must be the REAL vendor ("zhipu").
//
// Before the fix, serveRouteWithObserver built obsReqCtx.ProviderID from the
// still-declared route.ProviderCode ("anthropic") because the truthful
// normalization only happened later, inside serveRoute — so the audit stream was
// stamped anthropic while the ledger was zhipu (a two-source split). This test
// goes RED on that old ordering. Non-env-gated: the forward is served by a canned
// in-process transport, so it runs in CI without any live key or network.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// cannedAnthropicTransport answers every forward with a fixed 200 Anthropic-wire
// body, regardless of the request URL — so serveRoute completes in-process with
// no network dial (the observer context is captured at NotifyStart, before the
// forward, but serveRoute must still finish cleanly).
type cannedAnthropicTransport struct{ body string }

func (c cannedAnthropicTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

// buildUserChatObserverRegistry builds an observer.Registry with a single
// recorder subscribed to the user_chat stream (serveRouteWithObserver's stream),
// so NotifyStart on that stream actually reaches it. Isolated from the global
// registration sink like buildTestObserverRegistry.
func buildUserChatObserverRegistry(t *testing.T, recorder *rhythmHooksRecorder) *observer.Registry {
	t.Helper()
	observer.ResetRegistrationsForTest()
	t.Cleanup(observer.ResetRegistrationsForTest)
	observer.RegisterObserver(observer.Observer{
		Name:         "attr-test-" + t.Name(),
		OwnerAppSlug: "degrade-detector", // matches FirstPartyAllowlist
		Streams:      []string{observer.StreamUserChat},
		Build: func(_ map[string]any) (observer.StreamingObserver, error) {
			return recorder, nil
		},
	})
	reg := observer.NewRegistry(slog.Default())
	reg.BuildObservers(func(_ string) bool { return true }, nil)
	if reg.Active() != 1 {
		t.Fatalf("expected exactly 1 active observer, got %d", reg.Active())
	}
	return reg
}

func TestServeRouteWithObserver_ProviderIDIsTruthfulVendor(t *testing.T) {
	p := setupTestProxy(t, "http://dummy.invalid")
	// Serve the forward from a canned in-process transport (no network).
	p.SetTransport(cannedAnthropicTransport{
		body: `{"id":"msg_x","type":"message","role":"assistant","model":"glm-4.6","content":[{"type":"text","text":"PONG"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`,
	})

	recorder := newRhythmHooksRecorder()
	p.SetObserverRegistry(buildUserChatObserverRegistry(t, recorder))

	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	// Customer symptom (e): binding DECLARED anthropic, base_url is GLM's endpoint.
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-glm-attr", Provider: "anthropic", ProviderCode: "anthropic",
		BaseURL: glmAnthropicBase, ProtocolType: "anthropic", PlaintextKey: "sk-fake",
	}
	const clientModel = "claude-opus-4-8"
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(liveBody(clientModel))))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-aikey-model", clientModel)
	w := httptest.NewRecorder()

	p.serveRouteWithObserver(w, req, route, prov, "sk-fake", "aikey_team_vk-glm-attr",
		time.Now(), discardLogger(), observer.StreamUserChat, "trace-attr-fix2")

	// NotifyEnd is dispatched to the per-request consumer goroutine; wait for it.
	select {
	case <-recorder.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("OnRequestEnd never fired within 2s; observer wiring is broken")
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	rc, ok := recorder.startSeen["trace-attr-fix2"]
	if !ok {
		t.Fatalf("observer never saw the request (startSeen=%v)", recorder.startSeen)
	}
	// The core assertion: the observer/audit stream sees the REAL vendor.
	if rc.ProviderID != "zhipu" {
		t.Errorf("observer RequestContext.ProviderID = %q, want zhipu "+
			"(truthful attribution must reach the audit stream, not just the ledger)", rc.ProviderID)
	}
	// And the ledger side (route mutation) agrees — single source of truth.
	if route.ProviderCode != "zhipu" {
		t.Errorf("route.ProviderCode = %q, want zhipu", route.ProviderCode)
	}
}
