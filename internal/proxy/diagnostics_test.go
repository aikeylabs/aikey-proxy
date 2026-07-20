package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 7.9/3.5 fence: the read-only diagnostics endpoint reports the embedded registry
// provenance and the model-mapping health verdict. GET-only, no mutation.
func TestDiagnosticsPipeline_RegistryProvenanceAndHealth(t *testing.T) {
	p := &Proxy{}

	req := httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil)
	rec := httptest.NewRecorder()
	p.Handle(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got PipelineDiagnostics
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}

	// Registry provenance: a digest, real route rows, and GLM/zhipu carries a map.
	if len(got.Registry.Digest) < 8 {
		t.Errorf("registry digest missing/short: %q", got.Registry.Digest)
	}
	if got.Registry.RouteRows <= 0 {
		t.Errorf("route_rows = %d, want > 0", got.Registry.RouteRows)
	}
	foundZhipu := false
	for _, pr := range got.Registry.ProvidersWithModelMap {
		if pr == "zhipu" {
			foundZhipu = true
		}
	}
	if !foundZhipu {
		t.Errorf("zhipu must carry a model_map; got providers=%v", got.Registry.ProvidersWithModelMap)
	}

	// Health with no traffic: mappings ARE configured (embedded registry) and no
	// miss has been seen → "ok".
	if got.ModelMapping.Status != MappingOK {
		t.Errorf("fresh health = %q, want ok", got.ModelMapping.Status)
	}
}

// 7.9/3.5 fence: mappingHealth flips to "degraded" once a configured-but-missing
// occurrence is recorded — the single source-of-truth the four surfaces read.
// This MUST go red if a caller stops feeding the counters (mapping silently
// ineffective would then read as healthy — the exact "system lies to the user" bug).
func TestMappingHealth_DegradedWhenConfiguredButMissed(t *testing.T) {
	p := &Proxy{}

	if got := p.mappingHealth().Status; got != MappingOK {
		t.Fatalf("precondition: fresh status = %q, want ok", got)
	}

	// Simulate a provider that HAS a model_map but a request that didn't match it.
	p.mapPassthrough.Add(1)
	p.recordMappingMiss("zhipu", "some-unmapped-model")

	h := p.mappingHealth()
	if h.Status != MappingDegraded {
		t.Fatalf("after a miss, status = %q, want degraded", h.Status)
	}
	if h.LastMiss == nil || h.LastMiss.Provider != "zhipu" {
		t.Fatalf("last_miss must record the provider; got %+v", h.LastMiss)
	}
	if h.Reason == "" {
		t.Errorf("degraded verdict must carry a surface-agnostic reason")
	}
}

// GET-only: a mutating method is rejected read-only.
func TestDiagnosticsPipeline_RejectsNonGet(t *testing.T) {
	p := &Proxy{}
	req := httptest.NewRequest(http.MethodPost, "/v1/diagnostics/pipeline", nil)
	rec := httptest.NewRecorder()
	p.Handle(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}
