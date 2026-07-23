package proxy

// Live L1/L2 acceptance harness (model-mapping-egress task 7.1).
// Fires ONE fresh claude-opus-4-8 request through the full proxy serveRoute funnel
// to the REAL GLM /api/anthropic endpoint, and asserts the row that lands in the
// REAL SQLite usage_events store (not a mock capture):
//   L1 existence  : SELECT COUNT(*) FROM usage_events  >= 1  (HTTP 200 + 0 rows = swallowed)
//   L2 requested  : requested_model == claude-opus-4-8
//   L2 effective  : model           == glm-4.6
//   L2 provider   : resolved_provider/provider attribution == zhipu
// Env-gated on AIKEY_LIVE_GLM_KEY (skips without a key), same as live_glm_test.go.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"

	_ "modernc.org/sqlite"
)

func TestLive_PersistedUsageEventSQLite(t *testing.T) {
	key := liveGLMKey(t)

	dbPath := filepath.Join(t.TempDir(), "events.db")
	store, err := events.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open events store: %v", err)
	}
	// Close the store handle before t.TempDir cleanup so Windows (which cannot
	// unlink an open file) can remove the WAL/db files. Registered after
	// t.TempDir()'s own removal cleanup, so it runs first (LIFO).
	t.Cleanup(func() { _ = store.Close() })
	// setupTestProxyWithStore wraps the store in a collector (batch=1, 5ms flush)
	// and Closes it at t.Cleanup — the real production persistence path.
	p := setupTestProxyWithStore(t, "http://dummy.invalid", store)

	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	// Customer symptom (e): binding DECLARED anthropic, base_url is GLM's endpoint.
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-glm-persist", Provider: "anthropic", ProviderCode: "anthropic",
		BaseURL: glmAnthropicBase, ProtocolType: "anthropic", PlaintextKey: key,
	}
	const clientModel = "claude-opus-4-8"
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(liveBody(clientModel))))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-aikey-model", clientModel)
	w := httptest.NewRecorder()

	p.serveRoute(w, req, route, prov, key, "aikey_team_vk-glm-persist", time.Now(), discardLogger())
	if w.Code != http.StatusOK {
		t.Fatalf("upstream status %d: %s", w.Code, w.Body.String())
	}

	// Open a second connection to the same DB file and poll for the async flush.
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

	// L1 existence.
	if count < 1 {
		t.Fatalf("L1 FAIL: usage_events COUNT=%d, want >=1 (HTTP 200 but no persisted row = constraint swallowed the error)", count)
	}

	// L2 content — assert to SPECIFIC values (not "has a value").
	var reqModel, effModel, resolvedProv, provider string
	if err := db.QueryRow(
		"SELECT requested_model, model, resolved_provider, provider FROM usage_events ORDER BY id DESC LIMIT 1",
	).Scan(&reqModel, &effModel, &resolvedProv, &provider); err != nil {
		t.Fatalf("L2 query: %v", err)
	}
	t.Logf("PERSISTED usage_events row (real SQLite): L1 COUNT=%d | requested_model=%q | model(effective)=%q | resolved_provider=%q | provider=%q",
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
