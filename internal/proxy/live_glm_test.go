package proxy

// LIVE end-to-end tests against the real GLM anthropic endpoint. Env-gated:
// they SKIP unless AIKEY_LIVE_GLM_KEY is set, so CI (no key) never runs them and
// no secret is committed. Run locally:
//   AIKEY_LIVE_GLM_KEY=$key go test ./internal/proxy/ -run TestLive_ -v
//
// Discriminator (verified 2026-07-18): GLM's anthropic endpoint serves an
// UNKNOWN model name with its own default (claude-opus-4-8 → served as glm-4.7),
// but an explicit glm-4.6 is served AS glm-4.6. So a response model of "glm-4.6"
// proves the effective (mapped) model reached GLM; "glm-4.7" would prove it did
// not.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

const glmAnthropicBase = "https://open.bigmodel.cn/api/anthropic"

func liveGLMKey(t *testing.T) string {
	t.Helper()
	k := os.Getenv("AIKEY_LIVE_GLM_KEY")
	if k == "" {
		t.Skip("AIKEY_LIVE_GLM_KEY not set — skipping live GLM test")
	}
	return k
}

func liveBody(model string) []byte {
	return []byte(`{"model":"` + model + `","max_tokens":32,"messages":[{"role":"user","content":"Reply with exactly: PONG"}]}`)
}

// TestLive_MappingReachesRealGLM: the P2 mapping layer rewrites claude-opus-4-8
// → glm-4.6, and the REAL GLM endpoint serves that rewritten body as glm-4.6.
// Proves R-A (mapping executes) + R-B (endpoint) + the effective model actually
// reaches the vendor.
func TestLive_MappingReachesRealGLM(t *testing.T) {
	key := liveGLMKey(t)

	// 1. Client sends claude-opus-4-8.
	clientBody := liveBody("claude-opus-4-8")
	// 2. Mapping layer rewrites it.
	res := applyModelMapping(glmAnthropicBase, "claude-opus-4-8", clientBody)
	if !res.Mapped || res.EffectiveModel != "glm-4.6" || res.Provider != "zhipu" {
		t.Fatalf("mapping: Mapped=%v Eff=%q Provider=%q, want true/glm-4.6/zhipu", res.Mapped, res.EffectiveModel, res.Provider)
	}
	// 3. Forward the REWRITTEN body to the real GLM anthropic endpoint.
	req, _ := http.NewRequest(http.MethodPost, glmAnthropicBase+"/v1/messages", strings.NewReader(string(res.NewBody)))
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GLM request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GLM status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Model string `json:"model"`
		Type  string `json:"type"`
	}
	_ = json.Unmarshal(body, &out)
	// 4. GLM served the mapped model.
	if out.Model != "glm-4.6" {
		t.Fatalf("GLM served model %q, want glm-4.6 (mapping did not reach the vendor)", out.Model)
	}
	if out.Type != "message" {
		t.Fatalf("GLM response type %q, want message (anthropic wire)", out.Type)
	}
	t.Logf("LIVE OK: claude-opus-4-8 → mapped glm-4.6 → GLM served %q (%s)", out.Model, out.Type)
}

// TestLive_FullProxyPathToRealGLM: drives the real serveRoute funnel end-to-end
// against the real GLM endpoint with a binding DECLARED as anthropic but pointed
// at GLM's /api/anthropic base_url (customer symptom (e)). Asserts the whole
// chain works (200 + valid anthropic message) and that the response model was
// restored to the client's original name (P3).
func TestLive_FullProxyPathToRealGLM(t *testing.T) {
	key := liveGLMKey(t)

	// Capturing event store for L1/L2 assertions.
	cap := &captureEventStore{}
	dummy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer dummy.Close()
	p := setupTestProxyWithStore(t, dummy.URL, cap)

	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	// Binding declared as anthropic (symptom (e)) but base_url is GLM's anthropic endpoint.
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "live:vk", Provider: "anthropic", ProviderCode: "anthropic",
		BaseURL: glmAnthropicBase, ProtocolType: "anthropic", PlaintextKey: key,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(liveBody("claude-opus-4-8"))))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-aikey-model", "claude-opus-4-8")
	w := httptest.NewRecorder()

	p.serveRoute(w, req, route, prov, key, "aikey_personal_live", time.Now(), discardLogger())

	if w.Code != http.StatusOK {
		t.Fatalf("full proxy path status %d: %s", w.Code, w.Body.String())
	}
	var out struct{ Model, Type string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Type != "message" {
		t.Fatalf("response type %q, want message", out.Type)
	}
	// P3: client sees its ORIGINAL model name restored (not glm-4.6).
	if out.Model != "claude-opus-4-8" {
		t.Errorf("client-visible model %q, want claude-opus-4-8 (response restoration)", out.Model)
	}
	// P1d: attribution normalized to the real upstream (zhipu) even though the
	// binding was declared anthropic.
	if route.ProviderCode != "zhipu" {
		t.Errorf("route.ProviderCode after serveRoute = %q, want zhipu (attribution)", route.ProviderCode)
	}
	t.Logf("LIVE OK full path: client=claude-opus-4-8 → GLM (real) → restored=%q, attributed=%q", out.Model, route.ProviderCode)
}

// TestLive_StreamingFullPathToRealGLM: streaming Claude Code path against real
// GLM. Request-direction mapping (claude-opus-4-8 → glm-4.6) works for streaming
// too; the SSE first-event rewrite (P3.3) restores the client's model name in
// the streamed message_start.
func TestLive_StreamingFullPathToRealGLM(t *testing.T) {
	key := liveGLMKey(t)
	dummy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer dummy.Close()
	p := setupTestProxyWithStore(t, dummy.URL, &captureEventStore{})
	prov, _ := p.providers.Get("anthropic")
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "live:vk-stream", Provider: "anthropic", ProviderCode: "anthropic",
		BaseURL: glmAnthropicBase, ProtocolType: "anthropic", PlaintextKey: key,
	}
	streamBody := `{"model":"claude-opus-4-8","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"PONG"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(streamBody))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-aikey-model", "claude-opus-4-8")
	w := httptest.NewRecorder()

	p.serveRoute(w, req, route, prov, key, "aikey_personal_live", time.Now(), discardLogger())

	if w.Code != http.StatusOK {
		t.Fatalf("streaming status %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "event: message_start") {
		t.Fatalf("no message_start in stream: %s", body[:min(len(body), 300)])
	}
	// P3.3: the streamed message_start model is the CLIENT's name, not glm-4.6.
	if strings.Contains(body, `"model": "glm-4.6"`) || strings.Contains(body, `"model":"glm-4.6"`) {
		t.Errorf("streaming leaked upstream model glm-4.6 to client (P3.3 restore failed)")
	}
	if !strings.Contains(body, "claude-opus-4-8") {
		t.Errorf("streaming message_start missing restored client model claude-opus-4-8")
	}
	t.Logf("LIVE OK streaming: client=claude-opus-4-8 → GLM streamed → first-event restored to claude-opus-4-8; attributed=%q", route.ProviderCode)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// captureEventStore records inserted usage events for assertions. The
// collector Inserts from its own goroutine while the test reads, so `events`
// is guarded by `mu` — without it `go test -race` flags the append-vs-read
// data race (the collector flush is asynchronous).
type captureEventStore struct {
	mu     sync.Mutex
	events []eventRow
}
type eventRow struct{ Model, RequestedModel, Provider string }

func (c *captureEventStore) Insert(evs []events.UsageEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range evs {
		c.events = append(c.events, eventRow{Model: e.Model, RequestedModel: e.RequestedModel, Provider: e.Provider})
	}
	return nil
}

// len reports the number of captured events under the lock.
func (c *captureEventStore) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// first returns the first captured event (ok=false when none) under the lock.
func (c *captureEventStore) first() (eventRow, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return eventRow{}, false
	}
	return c.events[0], true
}

// waitFirst polls up to `timeout` for the first captured event to appear —
// the async-flush wait every reader needs (mirrors live_persist_sqlite_test.go's
// poll loop). Returns ok=false if none arrived in time.
func (c *captureEventStore) waitFirst(timeout time.Duration) (eventRow, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if row, ok := c.first(); ok {
			return row, true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return eventRow{}, false
}
