package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// TestLive_RequestChainMetadata drives ONE real claude-opus-4-8 request through
// the full proxy serveRoute funnel to the real GLM /api/anthropic endpoint and
// prints the complete request-chain metadata as JSON: client model → model
// mapping → provider attribution → upstream URL/model → response restoration →
// persisted usage event. Env-gated on AIKEY_LIVE_GLM_KEY (skips without a key).
func TestLive_RequestChainMetadata(t *testing.T) {
	key := liveGLMKey(t)

	cap := &captureEventStore{}
	dummy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer dummy.Close()
	p := setupTestProxyWithStore(t, dummy.URL, cap)

	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	// Customer symptom (e): binding DECLARED anthropic, base_url is GLM's endpoint.
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-glm-demo", Provider: "anthropic", ProviderCode: "anthropic",
		BaseURL: glmAnthropicBase, ProtocolType: "anthropic", PlaintextKey: key,
	}
	const clientModel = "claude-opus-4-8"
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(liveBody(clientModel))))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-aikey-model", clientModel)
	w := httptest.NewRecorder()

	p.serveRoute(w, req, route, prov, key, "aikey_team_vk-glm-demo", time.Now(), discardLogger())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	var out struct {
		Model string         `json:"model"`
		Type  string         `json:"type"`
		ID    string         `json:"id"`
		Usage map[string]any `json:"usage"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)

	// Wait for the collector's async flush before reading the captured event —
	// serveRoute returns before the collector goroutine has necessarily
	// Inserted. Reading cap.events without this poll is both flaky AND a data
	// race (see captureEventStore.waitFirst / live_persist_sqlite_test.go).
	var evReq, evEff, evProv string
	if row, ok := cap.waitFirst(4 * time.Second); ok {
		evReq, evEff, evProv = row.RequestedModel, row.Model, row.Provider
	}

	chain := []any{
		map[string]any{"step": "1_client_request", "model": clientModel, "wire_protocol": "anthropic", "endpoint": "POST /v1/messages"},
		map[string]any{"step": "2_model_mapping", "requested_model": clientModel, "effective_model": evEff, "rule": "role opus → glm-4.6 (per-provider model_map)"},
		map[string]any{"step": "3_provider_resolution", "declared_provider": "anthropic", "attributed_provider": route.ProviderCode, "protocol": route.ProtocolType, "base_url": route.BaseURL},
		map[string]any{"step": "4_upstream_request_to_GLM", "url": route.BaseURL + "/v1/messages", "model_sent_upstream": evEff},
		map[string]any{"step": "5_upstream_response", "served_model": evEff, "type": out.Type, "message_id": out.ID, "usage": out.Usage},
		map[string]any{"step": "6_client_visible_response", "model_restored_to": out.Model},
		map[string]any{"step": "7_usage_event_persisted", "requested_model": evReq, "effective_model": evEff, "provider": evProv},
	}
	b, _ := json.MarshalIndent(chain, "", "  ")
	t.Logf("\n===== REQUEST CHAIN METADATA (real GLM, one live request) =====\n%s\n===== END =====", string(b))

	// Sanity: the chain actually happened as described.
	if route.ProviderCode != "zhipu" || evEff != "glm-4.6" || out.Model != clientModel {
		t.Fatalf("chain mismatch: attributed=%q effective=%q restored=%q", route.ProviderCode, evEff, out.Model)
	}
}
