package proxy

// Fix 3 fence: default-run (NON-env-gated) persistence proof. Mirrors the
// four-layer L1/L2 acceptance of live_persist_sqlite_test.go but drives a FAKE
// upstream (httptest) instead of the real GLM endpoint, so it runs in CI with no
// AIKEY_LIVE_GLM_KEY. It proves that a mapped GLM request actually lands a row in
// a REAL sqlite usage_events store (HTTP 200 is NOT persistence proof — the live
// test can only run with a secret; this one always runs):
//   L1 existence  : SELECT COUNT(*) FROM usage_events  >= 1
//   L2 requested  : requested_model == claude-opus-4-8
//   L2 effective  : model           == glm-4.6
//   L2 provider   : resolved_provider/provider attribution == zhipu
//
// The binding is DECLARED anthropic with GLM's /api/anthropic base_url (so the
// truthful-attribution normalization → zhipu is exercised), and a host-redirect
// transport sends the bytes to the httptest server while keeping base_url pointed
// at GLM for attribution. The fake upstream returns a canned Anthropic-wire body
// with "model":"glm-4.6".

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"

	_ "modernc.org/sqlite"
)

// hostRedirectTransport rewrites every outbound forward to `target`, so the
// route can keep base_url = GLM's endpoint (for zhipu attribution) while the
// bytes actually reach an in-process httptest server.
type hostRedirectTransport struct{ target *url.URL }

func (h hostRedirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = h.target.Scheme
	r.URL.Host = h.target.Host
	r.Host = h.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

func TestDefaultRun_PersistedUsageEventSQLite_NoLiveKey(t *testing.T) {
	// Fake upstream returns a canned Anthropic-wire body reporting model glm-4.6.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_x","type":"message","role":"assistant","model":"glm-4.6","content":[{"type":"text","text":"PONG"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`))
	}))
	defer upstream.Close()
	upURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "events.db")
	store, err := events.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open events store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	// Real production persistence path: collector (batch=1, 5ms flush) → store.
	p := setupTestProxyWithStore(t, "http://dummy.invalid", store)
	// Redirect the forward to the httptest server WITHOUT touching base_url.
	p.SetTransport(hostRedirectTransport{target: upURL})

	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	// Customer symptom (e): binding DECLARED anthropic, base_url is GLM's endpoint.
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-glm-default", Provider: "anthropic", ProviderCode: "anthropic",
		BaseURL: glmAnthropicBase, ProtocolType: "anthropic", PlaintextKey: "sk-fake",
	}
	const clientModel = "claude-opus-4-8"
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(liveBody(clientModel))))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-aikey-model", clientModel)
	w := httptest.NewRecorder()

	p.serveRoute(w, req, route, prov, "sk-fake", "aikey_team_vk-glm-default", time.Now(), discardLogger())
	if w.Code != http.StatusOK {
		t.Fatalf("upstream status %d: %s", w.Code, w.Body.String())
	}

	// Second connection to poll for the async collector flush.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db reader: %v", err)
	}
	defer db.Close()

	var count int
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_ = db.QueryRow("SELECT COUNT(*) FROM usage_events").Scan(&count)
		if count > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// L1 existence — HTTP 200 with 0 rows would mean a constraint swallowed the write.
	if count < 1 {
		t.Fatalf("L1 FAIL: usage_events COUNT=%d, want >=1 (HTTP 200 but no persisted row = swallowed)", count)
	}

	// L2 content — assert to SPECIFIC values (not "has a value").
	var reqModel, effModel, resolvedProv, provider string
	if err := db.QueryRow(
		"SELECT requested_model, model, resolved_provider, provider FROM usage_events ORDER BY id DESC LIMIT 1",
	).Scan(&reqModel, &effModel, &resolvedProv, &provider); err != nil {
		t.Fatalf("L2 query: %v", err)
	}
	t.Logf("PERSISTED usage_events row (real SQLite, fake upstream): L1 COUNT=%d | requested_model=%q | model(effective)=%q | resolved_provider=%q | provider=%q",
		count, reqModel, effModel, resolvedProv, provider)

	if reqModel != "claude-opus-4-8" {
		t.Errorf("L2 requested_model=%q, want claude-opus-4-8", reqModel)
	}
	if effModel != "glm-4.6" {
		t.Errorf("L2 effective model=%q, want glm-4.6", effModel)
	}
	if resolvedProv != "zhipu" && provider != "zhipu" {
		t.Errorf("L2 provider attribution: resolved_provider=%q provider=%q, want zhipu in one of them", resolvedProv, provider)
	}
}
