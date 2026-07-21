package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// last_errors.go — P2 of the error-origin traceability plan
// (20260719-错误产地标签方案). A small ring buffer of the most-recent error
// RESPONSES the proxy produced/relayed, persisted to a state file so
// `aikey doctor --last-errors` can render a caused-by view WITHOUT the user
// SSH-grepping logs across hops.
//
// Design (mirrors the statusline sync-health / group-login bypass files):
//   - SUMMARY only, never the body — an error body can carry sensitive upstream
//     text or user prompt fragments (security > observability). We keep the
//     structured discriminators (status, origin, path, code, trace_id) that say
//     WHERE to look, not WHAT was said.
//   - Best-effort, main-path zero-dependency: capture runs in a wrapping
//     handler; a write failure is swallowed (the request response is already
//     sent). Read failures on the CLI side fall back to empty.
//   - Fixed ring N=maxLastErrors (no config knob — 简洁性优先).

const (
	maxLastErrors        = 20
	lastErrorsFilename   = "last-errors.json"
	headerErrorSourceKey = HeaderAikeyErrorSource // the aikey error code
)

// lastErrorEntry is one ring slot. JSON tags match the CLI reader
// (aikey-cli connectivity/last_errors).
type lastErrorEntry struct {
	AtMs        int64  `json:"at_ms"`
	Status      int    `json:"status"`
	Origin      string `json:"origin,omitempty"`       // X-Aikey-Error-Origin: <component>.<code> | upstream:<provider>
	Path        string `json:"path,omitempty"`         // X-Aikey-Error-Path joined "a, b"
	Code        string `json:"code,omitempty"`         // X-Aikey-Error-Source (aikey error code)
	TraceID     string `json:"trace_id,omitempty"`     // grep anchor into THIS hop's JSONL log
	RequestPath string `json:"request_path,omitempty"` // inbound URL path (no query)
	// UpstreamReqID is the provider's own request id (P3 correlation key) — the
	// anchor that crosses the aikey↔provider boundary, for a cross-store JOIN or
	// a provider support ticket. Empty on aikey self-generated errors.
	UpstreamReqID string `json:"upstream_request_id,omitempty"`
}

type lastErrorsBody struct {
	Entries   []lastErrorEntry `json:"entries"`
	WrittenAt int64            `json:"written_at"`
}

// lastErrorsRing is the process-global recorder. Package-level (like
// errorOriginComponent) because a proxy process has exactly one run dir; the
// mutex guards the in-memory ring + the file write.
type lastErrorsRing struct {
	mu      sync.Mutex
	entries []lastErrorEntry
	nowMs   func() int64 // injectable clock for tests
}

func nowUnixMilli() int64 { return time.Now().UnixMilli() }

var lastErrors = &lastErrorsRing{nowMs: nowUnixMilli}

func lastErrorsPath() (string, error) {
	if dir := os.Getenv("AIKEY_RUN_DIR"); dir != "" {
		return filepath.Join(dir, lastErrorsFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aikey", "run", lastErrorsFilename), nil
}

// record appends an entry (dropping the oldest past maxLastErrors) and rewrites
// the state file. Best-effort: a write error is WARN-logged, never propagated.
func (r *lastErrorsRing) record(e lastErrorEntry) {
	r.mu.Lock()
	r.entries = append(r.entries, e)
	if len(r.entries) > maxLastErrors {
		r.entries = r.entries[len(r.entries)-maxLastErrors:]
	}
	snapshot := make([]lastErrorEntry, len(r.entries))
	copy(snapshot, r.entries)
	r.mu.Unlock()
	r.persist(snapshot)
}

func (r *lastErrorsRing) persist(entries []lastErrorEntry) {
	path, err := lastErrorsPath()
	if err != nil {
		return // no home dir → silently skip (same posture as sync-health)
	}
	data, err := json.Marshal(lastErrorsBody{Entries: entries, WrittenAt: r.nowMs()})
	if err != nil {
		return
	}
	if err := func() error {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return mkErr
		}
		tmp := path + ".tmp"
		if wErr := os.WriteFile(tmp, data, 0o600); wErr != nil {
			return wErr
		}
		return os.Rename(tmp, path)
	}(); err != nil {
		slog.Warn("last-errors state file update failed — `aikey doctor --last-errors` may be stale",
			"event.name", "proxy.last_errors.file_failed", "error", err.Error())
	}
}

// captureWriter records the final status so the wrapper can read it after the
// handler returns. Headers are read straight off the underlying ResponseWriter
// (writeJSONError sets X-Aikey-Error-* BEFORE WriteHeader).
type captureWriter struct {
	http.ResponseWriter
	status int
}

func (c *captureWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

// Flush/Unwrap passthrough so SSE streaming + ReverseProxy hijack still work.
func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// WrapLastErrorCapture wraps the data-plane handler and records every error
// response (status >= 400) into the ring. Reuses the X-Aikey-Error-* headers P1
// already set — RESPONSE direction only, so this never touches the upstream
// request. Wire it around the data handler in app.Run.
func WrapLastErrorCapture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(cw, r)
		if cw.status < 400 {
			return
		}
		h := cw.Header()
		lastErrors.record(lastErrorEntry{
			AtMs:          lastErrors.nowMs(),
			Status:        cw.status,
			Origin:        h.Get(HeaderAikeyErrorOrigin),
			Path:          joinHeader(h.Values(HeaderAikeyErrorPath)),
			Code:          h.Get(headerErrorSourceKey),
			TraceID:       observability.ExtractOrCreate(r).TraceID,
			RequestPath:   r.URL.Path,
			UpstreamReqID: firstNonEmptyStr(h.Get(HeaderAikeyUpstreamRequestID), upstreamRequestIDFromHeader(h)),
		})
	})
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func joinHeader(vals []string) string {
	out := ""
	for i, v := range vals {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
