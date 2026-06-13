package proxy

import "testing"

// Fences the diagnostic helpers behind the proxy.filter.skipped log so the
// link-level skip trace stays informative (2026-06-13 form-② RCA).
func TestFilterDiagHelpers(t *testing.T) {
	// Nil-safe (body_not_json path passes parsed=nil).
	if topLevelKeys(nil) != nil || messageCount(nil) != 0 {
		t.Fatal("nil parsed must yield empty diagnostics")
	}
	// Anthropic-shaped body: keys + message count surface.
	pieces, parsed, ok := extractFilterableContent([]byte(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if !ok {
		t.Fatal("valid JSON must parse ok")
	}
	_ = pieces
	if messageCount(parsed) != 1 {
		t.Errorf("messageCount: got %d want 1", messageCount(parsed))
	}
	if parsed["stream"] != true {
		t.Errorf("stream flag must surface for the skip diagnostic")
	}
	keys := topLevelKeys(parsed)
	if len(keys) != 3 {
		t.Errorf("top_keys: got %v want 3 (model,stream,messages)", keys)
	}
}
