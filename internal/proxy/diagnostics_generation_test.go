package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// FENCE — /v1/diagnostics/pipeline must publish the generation its counters
// belong to, and those counters must be per-generation.
//
// Background (why this is a correctness property, not cosmetics): the proxy
// hot-reloads in-process. The supervisor builds a NEW *Proxy and swaps it in
// behind the same PID and listener, so `model_mapping.*` and `mask_restore.*`
// restart at zero without anything externally visible happening. A release
// assertion polling this endpoint would read the reset values as lifetime
// totals — and the mistake is silent AND reassuring (0 issued placeholders
// reads as "nothing degraded"). Publishing `generation_id` is what makes the
// reset detectable: same ID → two samples are comparable, changed ID → the
// earlier sample must be discarded.
//
// The MaskRestoreHealth doc comment claimed "cumulative for the process
// lifetime" until 2026-08-11. It was wrong, and a wrong comment is an input to
// the next implementer, so the contract is pinned here in a test rather than
// left to prose.
//
// 能红: delete `GenerationID: p.GenerationID(),` from the handler literal and
// the field-presence assertion fails; make maskFidelity a package-level counter
// and the per-instance isolation assertion fails.
func TestPipelineDiagnostics_ExposesGenerationID(t *testing.T) {
	p := New(nil, nil, nil, nil, nil)

	// Unwired (no supervisor) reports the documented 0 sentinel, and the key is
	// present even then — an absent key is indistinguishable from "0" for a
	// reader doing a raw JSON diff.
	if got := decodeGenerationID(t, p); got != 0 {
		t.Errorf("fresh proxy generation_id=%d, want 0 (the documented not-wired sentinel)", got)
	}

	p.SetGenerationID(3)
	if got := decodeGenerationID(t, p); got != 3 {
		t.Errorf("after SetGenerationID(3), diagnostics generation_id=%d, want 3", got)
	}
	if got := p.GenerationID(); got != 3 {
		t.Errorf("GenerationID()=%d, want 3", got)
	}
	// The config_version stamped on usage events and the ID on this endpoint are
	// two renderings of ONE fact; keep them derived from the same setter so a
	// future edit cannot desynchronise them.
	if got, want := p.proxyConfigVersion, GenerationLabel(3); got != want {
		t.Errorf("proxyConfigVersion=%q, want %q — the event label and the diagnostics ID must "+
			"describe the same generation", got, want)
	}
}

// TestPipelineDiagnostics_CountersAreGenerationScopedNotProcessScoped pins the
// premise that makes generation_id necessary. If this ever goes green-by-
// accident (counters made process-global), the doc comments on
// MaskRestoreHealth and PipelineDiagnostics.GenerationID must be rewritten
// before anything is relaxed.
func TestPipelineDiagnostics_CountersAreGenerationScopedNotProcessScoped(t *testing.T) {
	gen1 := New(nil, nil, nil, nil, nil)
	gen1.SetGenerationID(1)
	gen2 := New(nil, nil, nil, nil, nil) // what a hot reload produces
	gen2.SetGenerationID(2)

	gen1.maskFidelity.issued.Add(9)
	gen1.maskFidelity.restored.Add(9)
	gen1.mapApplied.Add(4)

	if got := gen2.maskFidelity.issued.Load(); got != 0 {
		t.Errorf("new generation inherited placeholders_issued=%d, want 0", got)
	}
	if got := gen2.mapApplied.Load(); got != 0 {
		t.Errorf("new generation inherited mapping applied=%d, want 0", got)
	}

	// And the endpoint reports the reset numbers under a DIFFERENT id, which is
	// the exact evidence an external reader needs.
	var d1, d2 PipelineDiagnostics
	decodeDiagnostics(t, gen1, &d1)
	decodeDiagnostics(t, gen2, &d2)
	if d1.GenerationID == d2.GenerationID {
		t.Fatalf("both generations reported generation_id=%d", d1.GenerationID)
	}
	if d1.MaskRestore.Issued == d2.MaskRestore.Issued {
		t.Errorf("counters did not reset across generations (both %d) — premise stale",
			d1.MaskRestore.Issued)
	}
}

func decodeDiagnostics(t *testing.T, p *Proxy, out *PipelineDiagnostics) {
	t.Helper()
	rec := httptest.NewRecorder()
	p.handleDiagnosticsPipeline(rec, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
}

// decodeGenerationID reads the raw JSON so a renamed or dropped key reds here
// instead of silently decoding to the zero value of a struct field.
func decodeGenerationID(t *testing.T, p *Proxy) int64 {
	t.Helper()
	rec := httptest.NewRecorder()
	p.handleDiagnosticsPipeline(rec, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, ok := body["generation_id"]
	if !ok {
		t.Fatalf("no `generation_id` key in /v1/diagnostics/pipeline — the counters served here are "+
			"generation-scoped and a reload zeroes them under an unchanged PID, so an external "+
			"reader has no way to spot the reset. body=%s", rec.Body.String())
	}
	var id int64
	if err := json.Unmarshal(raw, &id); err != nil {
		t.Fatalf("generation_id not a number: %s", string(raw))
	}
	return id
}
