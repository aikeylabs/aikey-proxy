// codex_model_capture.go — observe the `model` field on Codex OAuth
// requests as they pass through aikey-proxy, and persist it to a small
// state file the CLI's connectivity probe reads.
//
// 2026-06-05: aikey-cli's Codex probe used to hardcode the model name
// (`gpt-5.4`), which silently broke whenever OpenAI retired a model —
// the probe would 404 even though the user's real codex CLI happily
// worked against the new model. The fix uses a 3-layer resolution
// chain in the CLI (see aikey-cli/src/connectivity/protocol_addons.rs
// codex_probe_model): proxy-observed > ~/.codex/config.toml > hardcoded.
// This file is the writer for the first (highest-priority) layer.
//
// File layout: `~/.aikey/state/codex_last_model`, single line, just the
// model name (e.g. `gpt-5.5`). Atomic write via temp + rename so a
// reader never sees a torn line.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
)

// captureCodexModel sniffs the request body for `model` and STAGES it
// in the request context for later persistence. Actual write to
// ~/.aikey/state/codex_last_model happens in `persistCodexLastModelIfSuccessful`,
// which runs in `ModifyResponse` and ONLY persists when upstream
// returned 2xx. The request body is reset to its original bytes so
// downstream forwarding is unaffected.
//
// 2026-06-09 deferred-persist redesign: previously this function wrote
// the file unconditionally on the request leg — a single bad request
// (e.g. `model: gpt-4o` against the ChatGPT-account Codex endpoint,
// which returns 400 BadRequest) poisoned the state with a value that
// all subsequent connectivity probes inherited and re-failed against.
// By gating on the response status code we only remember models the
// upstream actually accepted.
//
// Errors are silent: this is a best-effort observability hook, NOT a
// request-blocking path. If we can't read/parse the body the proxy
// still forwards normally; the CLI probe falls back to the
// `CODEX_PROBE_FALLBACK_MODEL` constant.
//
// Called at the single point where we already know:
//   - canonicalCode == "openai"
//   - credential kind is OAuth
//   - we're about to forward to chatgpt.com/backend-api/codex
// (forward_and_resolve.go's OAuth branch). Calling it elsewhere would
// pick up API-key requests too, contaminating the state with the wrong
// model name.
func captureCodexModel(r *http.Request) *http.Request {
	if r == nil || r.Body == nil {
		return r
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return r
	}
	_ = r.Body.Close()
	// Always reset the body — even on parse-failure — so downstream
	// forwarding sees the unmodified request.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	var parsed struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return r // not JSON / wrong shape — nothing to observe
	}
	if parsed.Model == "" {
		return r
	}

	// Stash for ModifyResponse. Returning the new request lets the
	// caller swap the request (Go's `*http.Request` is value-mutating
	// via WithContext which doesn't mutate the receiver).
	return r.WithContext(context.WithValue(r.Context(), ctxKeyCodexCandidateModel, parsed.Model))
}

// persistCodexLastModelIfSuccessful is called from ModifyResponse on
// the Codex-OAuth response leg. It reads the candidate model staged by
// `captureCodexModel` and writes it to disk ONLY when the upstream
// status code indicates the model was actually accepted (2xx).
//
// 4xx/5xx responses are dropped silently: we don't want a transient
// upstream failure (rate limit, internal error) to wipe a previously-
// valid model either, so we leave the state file untouched. The next
// successful request overwrites it. The 2xx gate is a pure write-or-
// noop decision — no read-modify-write of the existing file.
func persistCodexLastModelIfSuccessful(req *http.Request, statusCode int) {
	if req == nil {
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		return
	}
	model, _ := req.Context().Value(ctxKeyCodexCandidateModel).(string)
	if model == "" {
		return
	}
	if err := writeCodexLastModel(model); err != nil {
		slog.Warn("codex_model_capture.write_failed",
			"model", model,
			"error", err.Error(),
		)
	}
}

// writeCodexLastModel atomically writes the model name to
// ~/.aikey/state/codex_last_model. The temp+rename pattern means a
// reader either sees the OLD content (pre-rename) or the NEW content
// (post-rename) — never a torn line. mkdir -p is invoked so a fresh
// install without ~/.aikey/state still works.
func writeCodexLastModel(model string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".aikey", "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	finalPath := filepath.Join(dir, "codex_last_model")
	tmp, err := os.CreateTemp(dir, ".codex_last_model.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op if rename succeeded
	if _, err := tmp.WriteString(model + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}
