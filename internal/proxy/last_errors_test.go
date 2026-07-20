package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestWrapLastErrorCapture_RecordsErrorsNotSuccess pins P2 (2026-07-19): the
// capture wrapper records error responses (>=400) with their P1 origin/path/code
// into the ring file, and does NOT record successes. 能红: remove the status<400
// early-return → a 200 gets recorded and the "success not recorded" assertion
// fails; drop setErrorOrigin upstream → origin is empty.
func TestWrapLastErrorCapture_RecordsErrorsNotSuccess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AIKEY_RUN_DIR", dir)
	// Fresh ring for the test (package global is otherwise shared).
	prevRing := lastErrors
	t.Cleanup(func() { lastErrors = prevRing })
	lastErrors = &lastErrorsRing{nowMs: func() int64 { return 1700000000000 }}

	prevComp := errorOriginComponent
	t.Cleanup(func() { errorOriginComponent = prevComp })
	SetErrorOriginComponent("") // local-proxy

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openai/responses":
			writeJSONError(w, 400, "invalid_request_error", "OAUTH_RESPONSES_ONLY", "responses only")
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
		}
	})
	h := WrapLastErrorCapture(inner)

	// A success — must NOT be recorded.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/openai/v1/chat", nil))
	// An error — must be recorded with origin.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/openai/responses", nil))

	body := readRing(t, filepath.Join(dir, "last-errors.json"))
	if len(body.Entries) != 1 {
		t.Fatalf("ring has %d entries, want exactly 1 (only the error)", len(body.Entries))
	}
	e := body.Entries[0]
	if e.Status != 400 {
		t.Errorf("status = %d, want 400", e.Status)
	}
	if e.Origin != "local-proxy.OAUTH_RESPONSES_ONLY" {
		t.Errorf("origin = %q, want local-proxy.OAUTH_RESPONSES_ONLY", e.Origin)
	}
	if e.Path != "local-proxy" {
		t.Errorf("path = %q, want local-proxy", e.Path)
	}
	if e.Code != "OAUTH_RESPONSES_ONLY" {
		t.Errorf("code = %q, want OAUTH_RESPONSES_ONLY", e.Code)
	}
	if e.RequestPath != "/openai/responses" {
		t.Errorf("request_path = %q, want /openai/responses", e.RequestPath)
	}
}

// TestLastErrorsRing_BoundedToMax pins the ring cap: never grows past maxLastErrors.
func TestLastErrorsRing_BoundedToMax(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AIKEY_RUN_DIR", dir)
	r := &lastErrorsRing{nowMs: func() int64 { return 1 }}
	for i := 0; i < maxLastErrors+15; i++ {
		r.record(lastErrorEntry{Status: 500, Code: "X"})
	}
	body := readRing(t, filepath.Join(dir, "last-errors.json"))
	if len(body.Entries) != maxLastErrors {
		t.Fatalf("ring size = %d, want capped at %d", len(body.Entries), maxLastErrors)
	}
}

func readRing(t *testing.T, path string) lastErrorsBody {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ring file: %v", err)
	}
	var b lastErrorsBody
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse ring file: %v", err)
	}
	return b
}
