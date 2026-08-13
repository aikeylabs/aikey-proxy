package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/aikeytime"
)

// complianceIngestPath is the master-side compliance intake route. Declared
// once so the live upload and the dead-letter replay can never drift apart.
const complianceIngestPath = "/v1/compliance/events"

// complianceDeadLetterMaxBytes bounds how large dead_letter.jsonl may grow
// before the compliance lane stops appending to it.
//
// WHY a bound at all: unlike usage events — which are conserved in the WAL
// outbox and re-read on the next drain — a compliance event has NO second
// copy anywhere on the box. The dead letter is its only conservation point,
// so this lane writes on EVERY failure (not just terminal ones). A master
// that stays unreachable for weeks would otherwise grow the file without
// limit on an employee laptop, which trades an audit gap for a disk-full
// incident (稳定 > UX: a full disk breaks the user's main request path,
// a delayed audit event does not).
//
// WHY drop-newest instead of rotating out the oldest: the oldest entries are
// the ones whose original delivery window is longest gone, i.e. the ones an
// operator is least able to reconstruct from anywhere else. Rotation would
// silently destroy them; refusing the newest append is loud (see
// EventComplianceDeadLetterOverflow) and leaves the recoverable history
// intact. 64 MiB is ~4 orders of magnitude above the expected steady state —
// compliance events are emitted only for FLAGGED content, and clean "allow"
// turns are dropped at the detector before they ever reach this path.
const complianceDeadLetterMaxBytes = 64 << 20

// UploadComplianceEvents POSTs compliance event JSONs to the per-RouteSource
// compliance ingest endpoint (`<route>/v1/compliance/events`), reusing the SAME
// destination URL + credential as usage reporting — single source of truth (see
// update doc 20260603 §3). The proxy calls this for team-routed compliance
// events the detector handed back over the pipe; the credential/URL never leave
// the proxy, only the event JSON crosses the IPC boundary.
//
// Delivery model (2026-08-10): a failed upload is DEFERRED, not dropped. Every
// failure — transport, 5xx, 429, and terminal 4xx alike — is conserved in the
// shared dead_letter.jsonl and re-delivered by the same replay pass that
// already recovers usage batches (automatic on upload recovery, manual via
// POST /admin/replay-dead-letter).
//
// WHY every failure and not just the terminal ones (this is the one place the
// compliance lane deliberately diverges from the usage lane): usage events live
// in the WAL, which IS the upload outbox — a retryable failure needs no
// dead-letter because the next drain re-reads the same rows. Compliance events
// have no WAL. The bytes in this call are the only copy in the process, and the
// caller is a fire-and-forget goroutine that returns immediately. Not writing
// them here means losing them.
//
// WHY a 400 is worth keeping rather than discarding as "malformed forever": the
// 400 this lane actually meets in the field is a VERSION-SKEW 400 — a new proxy
// stamping a wire field (trace_id, detect_latency_ms, …) that an older master's
// DisallowUnknownFields decoder refuses. The very same bytes succeed once the
// master is upgraded, and in Production the proxy sits on an employee laptop
// that upgrades on nobody's schedule. Treating it as permanent turns a routine
// rollout ordering into permanent audit loss.
//
// Still fail-loud: the error is returned so the caller logs it. The dead letter
// changes the outcome from "lost" to "late", not from "loud" to "quiet".
// Failures to write the dead letter itself are logged and swallowed — this runs
// on a bypass goroutine and must never affect the user's request path.
func (r *Reporter) UploadComplianceEvents(ctx context.Context, routeSource string, eventJSONs [][]byte) error {
	if len(eventJSONs) == 0 {
		return nil
	}
	upErr := r.postComplianceEvents(ctx, routeSource, eventJSONs)
	if upErr == nil {
		return nil
	}
	r.deadLetterCompliance(routeSource, eventJSONs, upErr)
	return upErr
}

// postComplianceEvents performs ONE POST of a compliance batch and classifies
// the outcome. It deliberately does NOT touch the dead letter, so
// ReplayDeadLetter can reuse it to re-deliver an entry without re-appending
// that entry to the file it is currently rewriting.
func (r *Reporter) postComplianceEvents(ctx context.Context, routeSource string, eventJSONs [][]byte) *uploadError {
	base := r.urlForRouteSource(routeSource)
	if base == "" {
		// Not a transport failure — there is simply nowhere to send this yet
		// (e.g. the member logged out, or the team route has not synced). Same
		// treatment as a failed upload: conserve and retry on the next replay,
		// by which time a route may exist.
		return &uploadError{Err: fmt.Errorf("compliance upload: no route URL for source %q", routeSource)}
	}
	url := strings.TrimRight(base, "/") + complianceIngestPath

	var buf bytes.Buffer
	buf.WriteString(`{"events":[`)
	for i, e := range eventJSONs {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(e)
	}
	buf.WriteString(`]}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return &uploadError{Err: fmt.Errorf("compliance upload: build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	if cred := r.credentialForRouteSource(routeSource); cred != nil {
		bearer, bErr := cred.Bearer(ctx)
		if bErr != nil {
			return &uploadError{Err: fmt.Errorf("compliance upload: credential for %q: %w", routeSource, bErr)}
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
	}

	resp, err := r.client.Get().Do(req)
	if err != nil {
		return &uploadError{Err: fmt.Errorf("compliance upload: POST %s: %w", url, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &uploadError{
			StatusCode:   resp.StatusCode,
			ResponseBody: string(body),
			Err:          fmt.Errorf("compliance upload: %s -> %d: %s", url, resp.StatusCode, string(body)),
		}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// complianceEventIDs best-effort extracts each payload's event_id so an
// operator reading dead_letter.jsonl can correlate an entry with what did (or
// did not) land in compliance_events — the same diagnostic the usage lane gets
// from ReportableEvent.EventID. A payload we cannot parse contributes nothing
// rather than failing the write: the payload itself is still stored verbatim.
func complianceEventIDs(eventJSONs [][]byte) []string {
	ids := make([]string, 0, len(eventJSONs))
	for _, p := range eventJSONs {
		var head struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(p, &head); err != nil || head.EventID == "" {
			continue
		}
		ids = append(ids, head.EventID)
	}
	return ids
}

// deadLetterCompliance conserves a failed compliance batch in the shared
// dead_letter.jsonl and records the failure for /admin/audit/status.
//
// PRIVACY (DC5): the stored payloads are byte-identical to what was already on
// the wire to master — content-free structural metadata (ids, offsets,
// category/severity, and under Tier-2 the planner-MASKED snippet). No raw
// prompt text is introduced here, and the file inherits the owner-only ACL the
// reporter applies to the dead-letter directory at startup.
func (r *Reporter) deadLetterCompliance(routeSource string, eventJSONs [][]byte, upErr *uploadError) {
	reason := "retryable"
	if upErr.StatusCode != 0 && classifyUploadError(upErr.StatusCode) == terminalFailure {
		reason = "terminal"
	}

	r.mu.Lock()
	r.complianceLastFailureAt = aikeytime.Now()
	r.complianceLastFailureCode = upErr.StatusCode
	r.complianceLastFailureReason = upErr.Error()
	r.mu.Unlock()

	if r.dlw == nil {
		slog.Warn("compliance upload failed and no dead-letter writer is configured — the events are lost",
			"event.name", observability.EventComplianceUploadDeadLettered,
			"error.code", "COMPLIANCE_DEAD_LETTER_UNAVAILABLE",
			"route_source", routeSource,
			"count", len(eventJSONs),
			"status", upErr.StatusCode,
			"error", upErr.Error())
		return
	}

	if fi, statErr := os.Stat(r.dlw.path); statErr == nil && fi.Size() >= complianceDeadLetterMaxBytes {
		slog.Error("compliance dead-letter is at its size cap — this batch is dropped; replay the queue to drain it",
			"event.name", observability.EventComplianceDeadLetterOverflow,
			"error.code", "COMPLIANCE_DEAD_LETTER_FULL",
			"path", r.dlw.path,
			"size_bytes", fi.Size(),
			"cap_bytes", int64(complianceDeadLetterMaxBytes),
			"dropped_events", len(eventJSONs),
			"route_source", routeSource)
		return
	}

	payloads := make([]json.RawMessage, 0, len(eventJSONs))
	for _, e := range eventJSONs {
		payloads = append(payloads, json.RawMessage(e))
	}

	r.dlw.write(&deadLetterEntry{
		Kind:         deadLetterKindCompliance,
		RouteSource:  routeSource,
		DeadAt:       aikeytime.Now(),
		Reason:       reason,
		ErrorCode:    upErr.StatusCode,
		ErrorMsg:     upErr.Error(),
		ResponseBody: upErr.ResponseBody,
		CollectorURL: strings.TrimRight(r.urlForRouteSource(routeSource), "/") + complianceIngestPath,
		ConfigHash:   r.cfg.ConfigHash,
		AttemptCount: 1,
		BatchSize:    len(eventJSONs),
		EventIDs:     complianceEventIDs(eventJSONs),
		Payloads:     payloads,
	})

	slog.Warn("compliance upload failed — events deferred to the dead letter, not dropped; they replay when the pipe recovers",
		"event.name", observability.EventComplianceUploadDeadLettered,
		"error.code", "COMPLIANCE_UPLOAD_FAILED",
		"route_source", routeSource,
		"reason", reason,
		"status", upErr.StatusCode,
		"count", len(eventJSONs),
		"error", upErr.Error(),
		"response", upErr.ResponseBody)
}
