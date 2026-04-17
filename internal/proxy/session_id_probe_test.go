package proxy

// P0d automated probe — verifies that the X-Claude-Code-Session-Id HTTP
// header flows all the way to the WAL's event_json.session_id field.
// This is the proxy-side half of the 费用小票-实施方案 v5 §14.3 probe;
// the CLI-side half lives at aikey-cli/scripts/probe-statusline.sh.
//
// What this test proves
//   Claude Code (or any client) sends `X-Claude-Code-Session-Id: <uuid>`
//   → aikey-proxy forwards the request AND records a WAL entry whose
//   event_json.session_id equals that UUID.  Without this, statusline's
//   precise-match fallback can't work.
//
// What this test does NOT prove
//   Whether the Claude Code CLI's statusline-stdin `session_id` is the
//   same UUID as its HTTP header session_id.  That requires a real
//   Claude Code session with tcpdump — see §14.3 of the design doc for
//   the manual steps.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

func TestSessionIDHeaderPropagatedToWAL(t *testing.T) {
	// 1. Fake upstream returning a minimal OpenAI-style JSON so the proxy
	// goes through the non-streaming happy path (synchronous reportUsage).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-probe","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`))
	}))
	defer upstream.Close()

	// 2. Proxy + standalone WAL (no reporter — exercises the offline path
	// where proxy.wal.Append is called directly).  The temp dir is
	// cleaned up by t.TempDir automatically.
	walDir := t.TempDir()
	wal, err := events.NewWALWriter(walDir)
	if err != nil {
		t.Fatalf("NewWALWriter: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	p := setupTestProxy(t, upstream.URL)
	p.SetWAL(wal)
	// SetReporter(nil, ...) with identity fields so reportUsage has a
	// proxyInstanceID / clientVersion even without a reporter.
	p.SetReporter(nil, "proxy-probe", "test", "gen-probe", 0, "acc-probe")

	// 3. Request with the session id header set to a known UUID.
	const probeSession = "probe-sess-f47ac10b-58cc-4372-a567-0e02b2c3d479"
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_vk_openai_test")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Claude-Code-Session-Id", probeSession)

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != 200 {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected 200, got %d: %s", w.Code, string(respBody))
	}

	// 4. Flush + close the WAL so file contents are visible.
	if err := wal.Close(); err != nil {
		t.Fatalf("wal.Close: %v", err)
	}

	// 5. Read the one usage-*.jsonl file in the temp dir and parse the
	// last line.  Multiple lines can exist if the test ever runs more than
	// one request; take the last to match "newest event".
	entry := readLastWALEntry(t, walDir)

	if got := entry.EventJSON.SessionID; got != probeSession {
		t.Fatalf("event.session_id mismatch: want %q, got %q", probeSession, got)
	}

	// Sanity on the v5 companion fields — these should also be populated
	// via the same code path.  key_label matches our test route's
	// alias-derived value; completion is "complete" for the 200 happy path.
	if entry.EventJSON.KeyLabel == "" {
		t.Errorf("event.key_label should be non-empty (route alias fallback)")
	}
	if entry.EventJSON.Completion != "complete" {
		t.Errorf("event.completion = %q, want %q", entry.EventJSON.Completion, "complete")
	}
	if entry.EventJSON.RouteSource == "" {
		t.Errorf("event.route_source should be non-empty (registry-assigned)")
	}
}

// TestSessionIDEmptyWhenHeaderAbsent confirms that non-Claude-Code callers
// (Kimi CLI, curl, anything that doesn't send the header) get an empty
// session_id — the statusline fallback path relies on this so it doesn't
// mis-attribute generic traffic to some Claude Code session.
func TestSessionIDEmptyWhenHeaderAbsent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-noheader","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer upstream.Close()

	walDir := t.TempDir()
	wal, err := events.NewWALWriter(walDir)
	if err != nil {
		t.Fatalf("NewWALWriter: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	p := setupTestProxy(t, upstream.URL)
	p.SetWAL(wal)
	p.SetReporter(nil, "proxy-probe", "test", "gen-probe", 0, "acc-probe")

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_vk_openai_test")
	req.Header.Set("Content-Type", "application/json")
	// Deliberately NOT setting X-Claude-Code-Session-Id.

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	_ = wal.Close()

	entry := readLastWALEntry(t, walDir)
	if entry.EventJSON.SessionID != "" {
		t.Fatalf("expected empty session_id for non-Claude-Code request, got %q",
			entry.EventJSON.SessionID)
	}
}

// walEntryEnvelope mirrors the on-disk shape: {"wal_seq":...,"event_json":{...}}
type walEntryEnvelope struct {
	EventJSON events.ReportableEvent `json:"event_json"`
}

// readLastWALEntry finds the single usage-*.jsonl file the test wrote, parses
// its final line as a WAL envelope, and returns the inner event.  Fails the
// test with a clear message rather than panicking on any step that might go
// wrong — helps diagnose environmental issues (e.g. "test wal dir is empty,
// proxy probably errored before writing").
func readLastWALEntry(t *testing.T, walDir string) walEntryEnvelope {
	t.Helper()
	var walPath string
	ents, err := os.ReadDir(walDir)
	if err != nil {
		t.Fatalf("read wal dir %s: %v", walDir, err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			walPath = filepath.Join(walDir, e.Name())
			break
		}
	}
	if walPath == "" {
		t.Fatalf("no usage-*.jsonl file found in %s; proxy did not append to WAL", walDir)
	}
	raw, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read %s: %v", walPath, err)
	}
	var last []byte
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			last = append(last[:0], scanner.Bytes()...)
		}
	}
	if len(last) == 0 {
		t.Fatalf("%s is empty; proxy did not write any WAL entries", walPath)
	}
	var entry walEntryEnvelope
	if err := json.Unmarshal(last, &entry); err != nil {
		t.Fatalf("parse last WAL line: %v\nline: %s", err, string(last))
	}
	return entry
}
