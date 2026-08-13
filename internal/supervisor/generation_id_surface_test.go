package supervisor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// FENCE — the generation identity of a hot-reloadable proxy must be externally
// readable (CLAUDE.md「健康信号必须可被外部读取」).
//
// WHY this fence exists. `aikey-proxy` reloads IN-PROCESS: a config or vault
// change makes the supervisor build a NEW generation (buildGeneration → a brand
// new *proxy.Proxy) and swap it in behind the same listener. The PID never
// changes and the process uptime never resets, but every runtime counter served
// by /v1/diagnostics/pipeline lives on the Proxy that was just replaced, so all
// of them silently restart at zero.
//
// Until 2026-08-11 nothing published which generation those numbers belonged to,
// and the MaskRestoreHealth doc comment actively asserted the opposite
// ("cumulative for the process lifetime"). Any release assertion that polled the
// endpoint could therefore read a freshly-zeroed counter as a lifetime total —
// and it fails in the reassuring direction, because zero placeholders issued
// reads as "nothing is degraded".
//
// The fence deliberately lives at the SUPERVISOR level, not in package proxy. A
// proxy-only test could only prove that SetGenerationID stores what it is given;
// it could not prove that the production build path ever calls it, which is the
// half that actually makes the endpoint honest.
//
// 能红 (verified by construction — each bullet is a single-line deletion):
//   - drop `p.SetGenerationID(...)` from buildGeneration → both generations
//     report 0 and the "distinct + monotonic" assertions fail.
//   - drop `GenerationID` from the PipelineDiagnostics literal in
//     diagnostics.go → the JSON key disappears and the decode assertion fails.
//   - make the counters process-global instead of per-generation → the
//     "counters are generation-scoped" assertion fails.
func TestBuildGeneration_PublishesGenerationIDOnDiagnostics(t *testing.T) {
	dbPath, _ := newOpenableVault(t, nil)

	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Vault.Path = dbPath
	cfg.Events.DBPath = filepath.Join(dir, "events.db")
	cfg.Events.WALDir = filepath.Join(dir, "wal")
	// config.Load applies these defaults; a hand-built Config must too, or the
	// collector goroutine panics on a zero ticker interval.
	cfg.Events.BatchSize = config.DefaultEventsBatchSize
	cfg.Events.FlushInterval = config.DefaultEventsFlushInterval

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Supervisor{
		cfg:              cfg,
		password:         "pw",
		ctx:              ctx,
		routingOverrides: proxy.NewRoutingOverrideCache(),
		pathHealth:       proxy.NewProviderPathHealthManager(),
	}

	// Two generations in the SAME process — this is what a hot reload is.
	g1, err := s.buildGeneration()
	if err != nil {
		t.Fatalf("buildGeneration #1: %v", err)
	}
	defer g1.close()
	g2, err := s.buildGeneration()
	if err != nil {
		t.Fatalf("buildGeneration #2: %v", err)
	}
	defer g2.close()

	id1 := readDiagnosticsGenerationID(t, g1.proxy)
	id2 := readDiagnosticsGenerationID(t, g2.proxy)

	// 1. The supervisor's generation id reaches the endpoint at all.
	if id1 != int64(g1.id) {
		t.Errorf("generation #1: diagnostics generation_id=%d, supervisor gen.id=%d — "+
			"buildGeneration must stamp the proxy with its own generation", id1, g1.id)
	}
	if id2 != int64(g2.id) {
		t.Errorf("generation #2: diagnostics generation_id=%d, supervisor gen.id=%d", id2, g2.id)
	}

	// 2. It is never the "unwired" sentinel in production build paths.
	if id1 == 0 || id2 == 0 {
		t.Fatalf("generation_id must be non-zero for supervisor-built proxies, got %d and %d — "+
			"0 means nothing called SetGenerationID, so an external reader cannot detect a reload", id1, id2)
	}

	// 3. A reload is DISTINGUISHABLE from the outside. This is the whole point:
	//    two reads of the endpoint with different generation_id values tell the
	//    caller the counters in between were zeroed.
	if id1 == id2 {
		t.Errorf("two generations reported the same generation_id=%d — a reload would be invisible", id1)
	}
	if id2 <= id1 {
		t.Errorf("generation_id must advance across a reload: #1=%d #2=%d", id1, id2)
	}

	// 4. The reason the ID is not decoration: a reload really does hand out a
	//    DIFFERENT *Proxy. Every counter the endpoint serves (mapping
	//    applied/rejected/passthrough, mask placeholders issued/restored) is a
	//    by-value field of that struct, so a distinct instance is a distinct —
	//    and freshly zeroed — set of counters. The per-instance independence is
	//    asserted directly in package proxy
	//    (TestPipelineDiagnostics_CountersAreGenerationScopedNotProcessScoped).
	if g1.proxy == g2.proxy {
		t.Errorf("both generations share one *proxy.Proxy — then the counters would in fact be " +
			"process-scoped and this fence's premise is stale; re-derive the doc comments on " +
			"MaskRestoreHealth and PipelineDiagnostics.GenerationID before relaxing anything")
	}
}

// readDiagnosticsGenerationID drives the REAL endpoint (not the struct field) so
// the fence covers the JSON contract an external reader actually consumes.
func readDiagnosticsGenerationID(t *testing.T, p *proxy.Proxy) int64 {
	t.Helper()
	rec := httptest.NewRecorder()
	p.Handle(rec, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/diagnostics/pipeline HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode diagnostics: %v (body=%s)", err, rec.Body.String())
	}
	raw, ok := body["generation_id"]
	if !ok {
		t.Fatalf("/v1/diagnostics/pipeline has no `generation_id` field — the counters it serves are "+
			"generation-scoped, so without it a reader cannot tell a reset apart from a genuine low "+
			"reading. body=%s", rec.Body.String())
	}
	var id int64
	if err := json.Unmarshal(raw, &id); err != nil {
		t.Fatalf("generation_id is not a number: %s", string(raw))
	}
	return id
}
