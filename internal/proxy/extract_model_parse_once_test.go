package proxy

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// Parse-once: a repeat extractModel call this request reuses the context-cached
// model instead of re-reading + re-unmarshaling the body. Proven by corrupting
// r.Body after the first call — the second call must still return the original
// model, i.e. it never touched the now-garbage body.
func TestExtractModel_ParseOnceReusesCache(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{"model":"claude-real"}`))
	if got := extractModel(req); got != "claude-real" {
		t.Fatalf("first extractModel=%q want claude-real", got)
	}
	// If the 2nd call re-parsed, it would read this garbage and return "".
	req.Body = io.NopCloser(strings.NewReader(`GARBAGE NOT JSON`))
	if got := extractModel(req); got != "claude-real" {
		t.Fatalf("second extractModel=%q want cached claude-real (must not re-parse body)", got)
	}
}

// Security: a client-injected x-aikey-model header must NOT be trusted. The
// first extractModel parses the REAL body and overwrites the header, so the
// model allowlist (handle_dispatch.go) cannot be bypassed by spoofing the
// internal header. This is the reason the parse-once cache keys on the context,
// not the header.
func TestExtractModel_IgnoresClientInjectedHeader(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{"model":"real-model"}`))
	req.Header.Set("x-aikey-model", "fake-allowed-model") // client spoof attempt

	got := extractModel(req)
	if got != "real-model" {
		t.Fatalf("extractModel=%q want real-model (client-injected header must not be trusted)", got)
	}
	if h := req.Header.Get("x-aikey-model"); h != "real-model" {
		t.Fatalf("x-aikey-model header=%q want overwritten to real-model", h)
	}
	// Repeat call returns the same real model from cache.
	if got2 := extractModel(req); got2 != "real-model" {
		t.Fatalf("repeat extractModel=%q want real-model", got2)
	}
}

// A body with no model parses to "" and is still cached — the repeat call
// returns "" without re-parsing (behavior unchanged vs the pre-cache code,
// which also returned "").
func TestExtractModel_EmptyModelStillParseOnce(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	if got := extractModel(req); got != "" {
		t.Fatalf("extractModel=%q want empty (no model field)", got)
	}
	req.Body = io.NopCloser(strings.NewReader(`{"model":"sneaky"}`))
	if got := extractModel(req); got != "" {
		t.Fatalf("second extractModel=%q want cached empty (must not re-parse to pick up sneaky)", got)
	}
}
