package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Task 7.9 evidence dump: print the read-only /v1/diagnostics/pipeline body so
// the embedded-registry provenance (digest, route rows, providers carrying a
// model_map) is captured as a real measured value, and show the health state
// TRANSITION ok → degraded when a configured mapping is missed (the signal a
// release-E2E asserts, not a terminal state).
func TestDump_DiagnosticsPipeline_Evidence(t *testing.T) {
	p := &Proxy{}

	req := httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil)
	rec := httptest.NewRecorder()
	p.Handle(rec, req)
	t.Logf("7.9 /v1/diagnostics/pipeline (fresh, no traffic) HTTP %d:\n%s", rec.Code, rec.Body.String())

	// Transition: feed a configured-but-missed occurrence → health flips to degraded.
	before := p.mappingHealth().Status
	p.mapPassthrough.Add(1)
	p.recordMappingMiss("zhipu", "some-unmapped-model")
	after := p.mappingHealth().Status

	rec2 := httptest.NewRecorder()
	p.Handle(rec2, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil))
	t.Logf("7.9 health TRANSITION: %s -> %s (after a configured-but-missed mapping)", before, after)
	t.Logf("7.9 /v1/diagnostics/pipeline (after miss) body:\n%s", rec2.Body.String())
}
