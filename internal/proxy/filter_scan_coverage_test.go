package proxy

// filter_scan_coverage_test.go — regression suite for bugfix 2026-08-13
// `20260813-pipe-input-cap-truncates-silently`.
//
// WHAT THE BUG WAS: a content piece longer than pipeInputCap (16 KiB) is cut
// before the detector pipe and the tail is forwarded to the upstream LLM
// verbatim, never inspected. The CUT is correct and deliberate (see the
// pipeInputCap doc comment) — what was wrong is that it happened with zero
// signal. Same text, key at 15 KB → 8 findings; key at 16 KB → 0 findings, and
// nothing anywhere said why. No log, no counter, no event.
//
// WHAT THESE TESTS PIN: the signal, not the behavior. Every case below asserts
// the WARN path (mandated by 日志规范: WARN 路径必须断言) and/or the externally
// readable counters. If someone deletes the WARN or the counters while keeping
// the cut, these go red — which is the exact regression that produced the bug.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// ─────────────────────────────────────────────────────────────────────────────
// fixture: a slog.Handler that captures whole records INCLUDING the attrs the
// caller pre-bound with logger.With(...).
//
// Accumulating WithAttrs is the point, not incidental plumbing: handle_dispatch
// binds trace_id / span_id / request_id once via slog.With and every WARN in the
// filter path inherits them. A handler that dropped those would let a regression
// to the package-level slog default (which carries no correlation ids at all)
// pass unnoticed — and correlation ids on WARN/ERROR are a 日志规范 hard rule.
// ─────────────────────────────────────────────────────────────────────────────

type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]slog.Value
}

func (c capturedRecord) str(k string) string { return c.attrs[k].String() }
func (c capturedRecord) num(k string) int64  { return c.attrs[k].Int64() }

type logCapture struct {
	mu      *sync.Mutex
	records *[]capturedRecord
	bound   []slog.Attr // attrs inherited from logger.With(...)
}

func newLogCapture() *logCapture {
	return &logCapture{mu: &sync.Mutex{}, records: &[]capturedRecord{}}
}

func (h *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h *logCapture) WithAttrs(as []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.bound)+len(as))
	merged = append(merged, h.bound...)
	merged = append(merged, as...)
	return &logCapture{mu: h.mu, records: h.records, bound: merged}
}

func (h *logCapture) WithGroup(string) slog.Handler { return h }

func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]slog.Value{}}
	for _, a := range h.bound {
		rec.attrs[a.Key] = a.Value
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.records = append(*h.records, rec)
	return nil
}

// withEvent returns every captured record carrying the given event.name.
//
// name stays a parameter even though this file only ever asks for one event:
// logCapture is a generic slog sink, and hardcoding the single event it is
// currently queried for would turn a reusable helper into a one-off — the next
// event added to this suite would have to re-add the parameter.
//
//nolint:unparam // deliberate: see above
func (h *logCapture) withEvent(name string) []capturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []capturedRecord
	for _, r := range *h.records {
		if r.attrs["event.name"].String() == name {
			out = append(out, r)
		}
	}
	return out
}

// correlatedLogger mirrors what handle_dispatch hands down the filter path:
// a logger with the W3C correlation ids already bound.
func correlatedLogger(h slog.Handler) *slog.Logger {
	return slog.New(h).With(
		"trace_id", "trace-abc123",
		"span_id", "span-def456",
		"request_id", "req-789",
	)
}

// userBody builds a request envelope with one user message per content string.
func userBody(t *testing.T, contents ...string) string {
	t.Helper()
	msgs := make([]map[string]string, 0, len(contents))
	for _, c := range contents {
		msgs = append(msgs, map[string]string{"role": "user", "content": c})
	}
	b, err := json.Marshal(map[string]any{"model": "m", "messages": msgs})
	if err != nil {
		t.Fatalf("build body: %v", err)
	}
	return string(b)
}

// allowHook is the dangerous steady state this bug lived in: the detector says
// "nothing found" for the head it was given, the request is forwarded, and the
// unscanned tail rides along looking exactly like a clean scan.
func allowHook() *stubHook {
	return &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 1 — over the cap ⇒ a WARN with the full field set.
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyInboundFilter_InputTruncated_EmitsWarnWithFields(t *testing.T) {
	const overBy = 5000
	piece := strings.Repeat("A", pipeInputCap+overBy)

	hook := allowHook()
	p := &Proxy{filterHook: hook}
	logs := newLogCapture()
	r := newReq(userBody(t, piece))
	w := httptest.NewRecorder()

	if proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", correlatedLogger(logs)); !proceed {
		t.Fatal("truncation must never fail the request (fail-open, §6 #11)")
	}

	recs := logs.withEvent(observability.EventProxyFilterInputTruncated)
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 %s record, got %d", observability.EventProxyFilterInputTruncated, len(recs))
	}
	rec := recs[0]

	// It must be a WARN. This content is never examined at all — no mask, no
	// compliance event, no audit row — so INFO would bury a real coverage hole
	// among routine chatter (失败要显眼).
	if rec.level != slog.LevelWarn {
		t.Errorf("level = %v, want WARN", rec.level)
	}
	// The message must state the consequence, not just the mechanism: an operator
	// grepping logs has to see that content reached the upstream unscanned.
	if !strings.Contains(rec.msg, "UNSCANNED") {
		t.Errorf("message does not surface the consequence: %q", rec.msg)
	}

	// Correlation ids (日志规范 hard rule) — inherited from the caller's logger,
	// which is what proves the WARN is emitted on `logger` and not on the
	// package-level slog default.
	for _, k := range []string{"trace_id", "span_id", "request_id"} {
		if rec.str(k) == "" {
			t.Errorf("WARN missing %s — WARN/ERROR must carry correlation ids", k)
		}
	}
	if got := rec.str("trace_id"); got != "trace-abc123" {
		t.Errorf("trace_id = %q, want the caller's trace-abc123", got)
	}

	// Quantitative fields: an operator must be able to answer "how much was
	// skipped" from the line itself, without a rebuild.
	checks := map[string]int64{
		"pieces_truncated":  1,
		"pieces_total":      1,
		"first_piece_index": 0,
		"cap_bytes":         pipeInputCap,
		"total_bytes":       int64(len(piece)),
		"scanned_bytes":     pipeInputCap,
		"skipped_bytes":     overBy,
	}
	for k, want := range checks {
		if got := rec.num(k); got != want {
			t.Errorf("field %s = %d, want %d", k, got, want)
		}
	}
	// Internal consistency: the accounting must add up, or the number an operator
	// acts on is fiction.
	if rec.num("scanned_bytes")+rec.num("skipped_bytes") != rec.num("total_bytes") {
		t.Errorf("scanned+skipped != total: %d+%d != %d",
			rec.num("scanned_bytes"), rec.num("skipped_bytes"), rec.num("total_bytes"))
	}

	// Privacy: counts only. The piece content must never reach the log line.
	for k, v := range rec.attrs {
		if strings.Contains(v.String(), "AAAA") {
			t.Errorf("attr %s leaked piece content: %q", k, v.String())
		}
	}

	// The health counters move in the same breath as the log line.
	if got := p.scanCoverage.truncatedPieces.Load(); got != 1 {
		t.Errorf("scanCoverage.truncatedPieces = %d, want 1", got)
	}
	if got := p.scanCoverage.skippedBytes.Load(); got != overBy {
		t.Errorf("scanCoverage.skippedBytes = %d, want %d", got, overBy)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 2 — many truncated pieces in ONE request ⇒ ONE aggregated WARN.
//
// This is the rate-limit contract. Agent turns carry several large tool payloads
// at once; a line per piece would turn the signal into spam and get the whole
// event muted by operators, which is functionally the same as not logging it.
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyInboundFilter_InputTruncated_OneAggregatedWarnPerRequest(t *testing.T) {
	const (
		overA = 1000
		overB = 2000
		overC = 3000
	)
	big1 := strings.Repeat("A", pipeInputCap+overA)
	big2 := strings.Repeat("B", pipeInputCap+overB)
	big3 := strings.Repeat("C", pipeInputCap+overC)
	small := "short and harmless"

	hook := allowHook()
	p := &Proxy{filterHook: hook}
	logs := newLogCapture()
	// small piece FIRST so first_piece_index proves it is the first TRUNCATED
	// piece, not merely the first piece.
	r := newReq(userBody(t, small, big1, big2, big3))
	w := httptest.NewRecorder()

	p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", correlatedLogger(logs))

	recs := logs.withEvent(observability.EventProxyFilterInputTruncated)
	if len(recs) != 1 {
		t.Fatalf("3 truncated pieces must produce exactly 1 aggregated WARN, got %d records", len(recs))
	}
	rec := recs[0]

	want := map[string]int64{
		"pieces_truncated":  3,
		"pieces_total":      4,
		"first_piece_index": 1, // index 0 is the small piece
		"skipped_bytes":     overA + overB + overC,
		"scanned_bytes":     3 * pipeInputCap,
		"total_bytes":       int64(len(big1) + len(big2) + len(big3)),
	}
	for k, v := range want {
		if got := rec.num(k); got != v {
			t.Errorf("field %s = %d, want %d", k, got, v)
		}
	}

	// Counters aggregate the same way — one request, three pieces.
	if got := p.scanCoverage.truncatedPieces.Load(); got != 3 {
		t.Errorf("truncatedPieces = %d, want 3", got)
	}
	if got := p.scanCoverage.skippedBytes.Load(); got != overA+overB+overC {
		t.Errorf("skippedBytes = %d, want %d", got, overA+overB+overC)
	}

	// Counters are cumulative across requests (they answer "how much has this
	// deployment skipped", not "how much did the last request skip").
	r2 := newReq(userBody(t, big1))
	p.applyInboundFilter(httptest.NewRecorder(), r2, "m", "personal", "", "", "", "", "", correlatedLogger(logs))
	if got := p.scanCoverage.truncatedPieces.Load(); got != 4 {
		t.Errorf("truncatedPieces after a 2nd request = %d, want 4 (cumulative)", got)
	}
	if got := len(logs.withEvent(observability.EventProxyFilterInputTruncated)); got != 2 {
		t.Errorf("a second truncating request must emit its own aggregated WARN; got %d total", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 3 — at or under the cap ⇒ silence.
//
// A signal that fires when nothing is wrong gets ignored when something is. The
// boundary matters: the cut is `len > cap`, so exactly-at-cap is fully scanned.
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyInboundFilter_WithinCap_NoTruncationSignal(t *testing.T) {
	for name, piece := range map[string]string{
		"well under cap": strings.Repeat("A", 100),
		"one byte under": strings.Repeat("A", pipeInputCap-1),
		"exactly at cap": strings.Repeat("A", pipeInputCap),
	} {
		t.Run(name, func(t *testing.T) {
			hook := allowHook()
			p := &Proxy{filterHook: hook}
			logs := newLogCapture()
			r := newReq(userBody(t, piece))

			p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", correlatedLogger(logs))

			if recs := logs.withEvent(observability.EventProxyFilterInputTruncated); len(recs) != 0 {
				t.Errorf("no truncation happened but %d WARN(s) were emitted: %+v", len(recs), recs)
			}
			if got := p.scanCoverage.truncatedPieces.Load(); got != 0 {
				t.Errorf("truncatedPieces = %d, want 0", got)
			}
			if got := p.scanCoverage.skippedBytes.Load(); got != 0 {
				t.Errorf("skippedBytes = %d, want 0", got)
			}
			// And the detector really did see the whole piece.
			if len(hook.gotPayload) != len(piece) {
				t.Errorf("detector got %d bytes, want the full %d", len(hook.gotPayload), len(piece))
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 4 — the cap is a BYTE budget, and CJK hits it ~3x sooner.
//
// Called out separately because the misreading is the dangerous part: "16KB"
// reads as "about 16,000 characters", but Chinese is 3 bytes/char, so a Chinese
// prompt runs out of coverage at ~5,460 characters. A reviewer reasoning in
// characters would conclude a 8,000-character Chinese prompt is fully scanned
// when in fact a third of it is not. This case makes the byte semantics an
// executable assertion rather than a comment.
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyInboundFilter_InputTruncated_ChineseIsBytesNotRunes(t *testing.T) {
	const chars = 8000 // well under "16,000 characters", far OVER 16 KiB
	piece := strings.Repeat("密", chars)
	totalBytes := len(piece)
	if totalBytes != chars*3 {
		t.Fatalf("fixture assumption broken: %q is %d bytes/char", "密", totalBytes/chars)
	}
	if totalBytes <= pipeInputCap {
		t.Fatalf("fixture must exceed the cap: %d bytes vs cap %d", totalBytes, pipeInputCap)
	}

	hook := allowHook()
	p := &Proxy{filterHook: hook}
	logs := newLogCapture()
	r := newReq(userBody(t, piece))

	p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", correlatedLogger(logs))

	recs := logs.withEvent(observability.EventProxyFilterInputTruncated)
	if len(recs) != 1 {
		t.Fatalf("an %d-character Chinese prompt MUST truncate (%d bytes > %d cap), got %d WARN(s)",
			chars, totalBytes, pipeInputCap, len(recs))
	}
	rec := recs[0]

	if got := rec.num("total_bytes"); got != int64(totalBytes) {
		t.Errorf("total_bytes = %d, want %d (bytes, not characters)", got, totalBytes)
	}
	if got := rec.num("scanned_bytes"); got > pipeInputCap {
		t.Errorf("scanned_bytes = %d exceeds the cap %d", got, pipeInputCap)
	}
	// The cut is snapped to a rune boundary — a split multibyte character would
	// hand the detector invalid UTF-8 and could corrupt the spliced-back tail.
	if !utf8.Valid(hook.gotPayload) {
		t.Error("detector payload is not valid UTF-8 — the cut split a multibyte character")
	}

	// The headline number: how many Chinese characters actually got scanned.
	scannedRunes := utf8.RuneCount(hook.gotPayload)
	wantRunes := pipeInputCap / 3 // 5461
	if scannedRunes != wantRunes {
		t.Errorf("scanned %d Chinese characters, want %d (cap %d bytes ÷ 3 bytes/char)",
			scannedRunes, wantRunes, pipeInputCap)
	}
	t.Logf("byte-vs-character口径: a %d-character Chinese prompt got %d characters scanned "+
		"(%d bytes) and %d characters (%d bytes) forwarded UNSCANNED",
		chars, scannedRunes, rec.num("scanned_bytes"),
		chars-scannedRunes, rec.num("skipped_bytes"))

	if got := p.scanCoverage.skippedBytes.Load(); got != int64(totalBytes)-int64(pipeInputCap/3*3) {
		t.Errorf("skippedBytes = %d, want %d", got, int64(totalBytes)-int64(pipeInputCap/3*3))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 5 — the counters are readable from OUTSIDE the process.
//
// health-signal-surface: a counter nobody can poll is not a health signal. The
// per-request WARN alone is not enough — a private deployment may ship its logs
// nowhere, and the question operators actually ask ("how much of my traffic goes
// unscanned?") is an aggregate one.
// ─────────────────────────────────────────────────────────────────────────────

func TestDiagnosticsPipeline_ExposesScanCoverage(t *testing.T) {
	const overBy = 4096
	hook := allowHook()
	p := &Proxy{filterHook: hook}

	// Baseline: the fields must be present and zero BEFORE anything truncates —
	// absent-vs-zero is exactly the ambiguity that made the bug invisible, and a
	// deployment that never masks anything (mask_restore status=inactive, the
	// common case) must still report its coverage.
	body := readPipelineDiagnostics(t, p)
	for _, want := range []string{`"scan_truncated_pieces":0`, `"scan_skipped_bytes":0`} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %s before any traffic:\n%s", want, body)
		}
	}

	r := newReq(userBody(t, strings.Repeat("A", pipeInputCap+overBy)))
	p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger())

	body = readPipelineDiagnostics(t, p)
	for _, want := range []string{`"scan_truncated_pieces":1`, `"scan_skipped_bytes":4096`} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics did not surface the skipped bytes, missing %s:\n%s", want, body)
		}
	}

	// Decoded read: the counters must sit in the block an operator already polls
	// for compliance scan scope, next to scan_roles / tool_block_scan.
	var d struct {
		MaskRestore MaskRestoreHealth `json:"mask_restore"`
	}
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("undecodable diagnostics: %v", err)
	}
	if d.MaskRestore.TruncatedPieces != 1 || d.MaskRestore.SkippedBytes != overBy {
		t.Errorf("mask_restore coverage = pieces:%d bytes:%d, want 1/%d",
			d.MaskRestore.TruncatedPieces, d.MaskRestore.SkippedBytes, overBy)
	}
	// Truncation deliberately does NOT rewrite the placeholder-fidelity verdict —
	// four surfaces render that status and folding a second failure mode into it
	// would change what their existing green/red means. (Whether truncation
	// deserves a verdict of its own is an open decision; see the bugfix record.)
	if d.MaskRestore.Status != MaskRestoreInactive {
		t.Errorf("status = %q, want %q — truncation must not hijack the fidelity verdict",
			d.MaskRestore.Status, MaskRestoreInactive)
	}
}

func readPipelineDiagnostics(t *testing.T, p *Proxy) string {
	t.Helper()
	w := httptest.NewRecorder()
	p.handleDiagnosticsPipeline(w, httptest.NewRequest("GET", "/v1/diagnostics/pipeline", nil))
	if w.Code != 200 {
		t.Fatalf("diagnostics status = %d", w.Code)
	}
	return w.Body.String()
}
