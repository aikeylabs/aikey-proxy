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

// 7.9/3.5 fence: the mapping-health verdict is a RECOVERABLE transition, not a
// monotonic latch (health-signal-surface: assert transition, not terminal).
// Drives the full ok → degraded → ok cycle:
//   - degraded requires a passthrough-miss stamped MORE RECENTLY than the last
//     successful apply (the CURRENT state). This ALSO keeps the "must go red if
//     the passthrough site stops feeding the counter/clock" fence: a silently-
//     ineffective mapping would otherwise read healthy — the "system lies to the
//     user" bug.
//   - a later successful apply (applyNano advances past missNano) flips it back
//     to ok, proving the verdict reflects current state and recovers.
func TestMappingHealth_TransitionOkDegradedRecovered(t *testing.T) {
	p := &Proxy{}

	// ok: fresh — mappings ARE configured (embedded zhipu) and no miss seen.
	if got := p.mappingHealth().Status; got != MappingOK {
		t.Fatalf("precondition: fresh status = %q, want ok", got)
	}

	// degraded: a provider that HAS a model_map but a request that slipped past
	// unchanged (passthrough policy, no rule matched). Mirrors the passthrough
	// site: bump the counter, stamp the miss clock, record the last miss.
	// Explicit monotonic nano stamps keep the transition deterministic.
	p.mapPassthrough.Add(1)
	p.lastMapMissNano.Store(200)
	p.recordMappingMiss("zhipu", "some-unmapped-model")

	h := p.mappingHealth()
	if h.Status != MappingDegraded {
		t.Fatalf("after a passthrough-miss, status = %q, want degraded", h.Status)
	}
	if h.LastMiss == nil || h.LastMiss.Provider != "zhipu" {
		t.Fatalf("last_miss must record the provider; got %+v", h.LastMiss)
	}
	if h.PassthroughMissing != 1 {
		t.Errorf("passthrough_missing must surface in the payload; got %d", h.PassthroughMissing)
	}
	if h.Reason == "" {
		t.Errorf("degraded verdict must carry a surface-agnostic reason")
	}

	// recovered: a LATER successful apply (applyNano > missNano) flips it back
	// to ok. A monotonic latch would stay degraded here — that's the regression
	// this asserts against.
	p.mapApplied.Add(1)
	p.lastMapApplyNano.Store(300)
	if got := p.mappingHealth().Status; got != MappingOK {
		t.Fatalf("after a later successful apply, status = %q, want ok (recovered)", got)
	}
}

// 7.9/3.5 fence: a `reject` means the unmatched=reject policy WORKED (the client
// asked for a model the map doesn't allow and the proxy correctly refused). It
// must NOT trip degraded. Pre-fix the verdict was `rejected+passthrough > 0`, so
// this test goes RED on that old logic — the behavior-change guard.
func TestMappingHealth_RejectPolicyIsNotDegraded(t *testing.T) {
	p := &Proxy{}

	// Simulate the reject path: counter bumped + last-miss recorded, but the
	// degrade clock (lastMapMissNano) deliberately NOT stamped.
	p.mapRejected.Add(1)
	p.recordMappingMiss("zhipu", "rejected-model")

	h := p.mappingHealth()
	if h.Status != MappingOK {
		t.Fatalf("a working reject policy must stay ok, got %q", h.Status)
	}
	if h.Rejected != 1 {
		t.Errorf("rejected count must still surface in the payload for visibility; got %d", h.Rejected)
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
