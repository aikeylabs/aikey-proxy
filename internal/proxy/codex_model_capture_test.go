// Tests for the deferred-persist Codex model capture (2026-06-09 bugfix).
//
// The state-poisoning bug we're guarding against:
//  1. some client sends `model: gpt-4o` through aikey-proxy Codex OAuth
//  2. ChatGPT-account Codex returns 400 (gpt-4o not supported there)
//  3. pre-fix, the model was written to disk BEFORE forwarding — so
//     `gpt-4o` stayed in ~/.aikey/state/codex_last_model and every
//     subsequent connectivity probe re-failed against it
//  4. post-fix, the write is gated on response status 2xx
//
// These tests pin the gating contract end-to-end via the two public
// hooks: captureCodexModel (request-leg stash) and
// persistCodexLastModelIfSuccessful (response-leg gated write).
package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTmpHome redirects HOME to a fresh tempdir for the duration of the
// test so writeCodexLastModel writes into a sandbox; original HOME is
// restored on cleanup. Returns the sandbox HOME so the caller can
// assert on the state file directly.
func withTmpHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func readStateFile(t *testing.T, home string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".aikey", "state", "codex_last_model"))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read state file: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func TestCaptureCodexModel_StashesIntoContextButDoesNotWrite(t *testing.T) {
	home := withTmpHome(t)
	body := []byte(`{"model":"gpt-5.5","input":"hi"}`)
	r := httptest.NewRequest(http.MethodPost, "/openai/responses", bytes.NewReader(body))
	r2 := captureCodexModel(r)

	// Request leg MUST NOT touch the disk — this is the whole point of
	// the deferred-persist redesign.
	if got := readStateFile(t, home); got != "" {
		t.Errorf("state file was written on request leg: got %q, want empty", got)
	}

	// But the model must be staged in context for ModifyResponse.
	if v, _ := r2.Context().Value(ctxKeyCodexCandidateModel).(string); v != "gpt-5.5" {
		t.Errorf("ctxKeyCodexCandidateModel = %q, want %q", v, "gpt-5.5")
	}

	// Body must be re-buffered so downstream forwarding still works.
	got, _ := io.ReadAll(r2.Body)
	if !bytes.Equal(got, body) {
		t.Errorf("request body lost after capture: got %s, want %s", got, body)
	}
}

func TestCaptureCodexModel_NoModelField_NoStash(t *testing.T) {
	home := withTmpHome(t)
	// Bodies without a `model` field shouldn't poison context with an
	// empty string — that would later cause persistCodex... to "write
	// nothing" via the early-return-on-empty guard. Empty-string ≠
	// "model accepted by upstream"; treat it as "nothing observed".
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"input":"hi"}`))
	r2 := captureCodexModel(r)
	if v, ok := r2.Context().Value(ctxKeyCodexCandidateModel).(string); ok && v != "" {
		t.Errorf("expected no stash for body-without-model; got %q", v)
	}
	if got := readStateFile(t, home); got != "" {
		t.Errorf("state file written despite no model field: %q", got)
	}
}

func TestCaptureCodexModel_NonJSONBody_NoStashNoPanic(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not-json"))
	// Just must not panic; staging an empty value is also acceptable.
	_ = captureCodexModel(r)
}

func TestPersistCodexLastModel_2xx_Writes(t *testing.T) {
	home := withTmpHome(t)
	body := []byte(`{"model":"gpt-5.5"}`)
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r = captureCodexModel(r)

	persistCodexLastModelIfSuccessful(r, 200)
	if got := readStateFile(t, home); got != "gpt-5.5" {
		t.Errorf("state file = %q after 200, want %q", got, "gpt-5.5")
	}
}

func TestPersistCodexLastModel_4xx_DoesNotWrite(t *testing.T) {
	home := withTmpHome(t)
	// Simulate the actual bug: gpt-4o through Codex OAuth → 400 BadRequest.
	body := []byte(`{"model":"gpt-4o"}`)
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r = captureCodexModel(r)

	persistCodexLastModelIfSuccessful(r, 400)
	if got := readStateFile(t, home); got != "" {
		t.Errorf("state file = %q after 400, want empty (the whole point of 2xx-gating)", got)
	}
}

func TestPersistCodexLastModel_5xx_DoesNotWipeExisting(t *testing.T) {
	home := withTmpHome(t)
	// Pre-seed a known-good model from an earlier successful request.
	if err := writeCodexLastModel("gpt-5.5"); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if got := readStateFile(t, home); got != "gpt-5.5" {
		t.Fatalf("seed read: got %q", got)
	}

	// A new request with a different model gets a 502 from upstream.
	// The previously-good value must SURVIVE — we don't want a transient
	// upstream outage to drop the model the CLI probe is using.
	body := []byte(`{"model":"gpt-5.6"}`)
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r = captureCodexModel(r)
	persistCodexLastModelIfSuccessful(r, 502)

	if got := readStateFile(t, home); got != "gpt-5.5" {
		t.Errorf("state file = %q after 502, want %q (pre-existing should survive)", got, "gpt-5.5")
	}
}

func TestPersistCodexLastModel_NoCandidate_Noop(t *testing.T) {
	home := withTmpHome(t)
	// Response leg without a request that ever went through captureCodexModel
	// (e.g. non-OAuth path) must not write anything.
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	persistCodexLastModelIfSuccessful(r, 200)
	if got := readStateFile(t, home); got != "" {
		t.Errorf("state file = %q for no-candidate request, want empty", got)
	}
}
