package events

// mcp_call_store.go — the proxy's own copy of every MCP tool call.
//
// # 🔴 Why the proxy keeps a copy at all
//
// Three reasons, and any one of them alone would be enough:
//
//  1. Personal edition has NO control plane. Without a local table there is no
//     record of a tool call anywhere, so "which tools did I use" is a question
//     the product cannot answer for its simplest edition.
//  2. It IS the outbox. A record written here and shipped later means a control
//     plane that is down for an hour costs a delay, not an audit gap — and the
//     recovery needs no replay log, because the rows themselves are the queue.
//  3. It decouples the customer's tool call from our control plane's
//     availability. Posting synchronously would put every tools/call behind an
//     HTTP round trip to us, which is exactly the coupling the MCP plane's
//     isolation shell exists to prevent.
//
// # 🔴 Why the outbox is a COLUMN and not a second table
//
// `reported_at_ms = 0` means "not yet delivered". A separate queue table would
// hold a second copy of every row, and the two would drift the first time a
// delivery succeeded and the bookkeeping write did not. One row, one truth: the
// drain is `WHERE reported_at_ms = 0`, and the control plane's ingest is
// idempotent on call_id, so a re-send after a lost response costs nothing.
//
// spec: workflow/CI/requirements/2026-08-20-mcp-gateway.md R10 / R27
//
// # 🔴 What is NOT in this table
//
// No cost, no tokens. A tool call produces neither, and a column here that
// looked like money would end up in somebody's report. Refusals are stored
// exactly like successes — that is the point of R10 — and the absence of any
// cost field is what makes "recorded" and "billed" impossible to conflate.

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// migrateMCPCalls creates the local call table.
//
// 🔴 Column names, types and the value domains mirror the control plane's
// `mcp_call_event` exactly. They are two databases, but one vocabulary: an
// operator who has learned to read one reads the other, and the delivery rail
// is a straight column-for-column copy with nothing to translate (translation is
// where a status silently becomes a different status).
//
// SQLite has no ADD COLUMN IF NOT EXISTS, so later columns follow the
// pragma_table_info probe the usage table already uses.
func migrateMCPCalls(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS mcp_call_event (
			call_id             TEXT NOT NULL PRIMARY KEY,
			org_id              TEXT NOT NULL DEFAULT '',
			seat_id             TEXT NOT NULL DEFAULT '',
			virtual_server_id   TEXT NOT NULL DEFAULT '',
			tool_id             TEXT NOT NULL DEFAULT '',
			tool_name           TEXT NOT NULL DEFAULT '',
			backend_id          TEXT NOT NULL DEFAULT '',
			session_id          TEXT NOT NULL DEFAULT '',
			conversation_session_id TEXT NOT NULL DEFAULT '',
			app_slug            TEXT NOT NULL DEFAULT '',
			origin              TEXT NOT NULL DEFAULT 'agent',
			status              TEXT NOT NULL,
			error_code          TEXT NOT NULL DEFAULT '',
			duration_ms         INTEGER NOT NULL DEFAULT 0,
			args_digest         TEXT NOT NULL DEFAULT '[]',
			args_raw            TEXT,
			upstream_request_id TEXT NOT NULL DEFAULT '',
			manifest_hash       TEXT NOT NULL DEFAULT '',
			created_at_ms       INTEGER NOT NULL DEFAULT 0,
			-- 🔴 0 = not yet delivered to the control plane. See the file header
			-- for why this is a column rather than a queue table.
			reported_at_ms      INTEGER NOT NULL DEFAULT 0
		);
		-- The drain's only query. Partial index so it costs nothing once the
		-- backlog is empty, which is the steady state.
		CREATE INDEX IF NOT EXISTS idx_mcp_call_unreported
			ON mcp_call_event(created_at_ms) WHERE reported_at_ms = 0;
		CREATE INDEX IF NOT EXISTS idx_mcp_call_created ON mcp_call_event(created_at_ms);
	`); err != nil {
		return fmt.Errorf("migrate mcp_call_event: %w", err)
	}
	return nil
}

// InsertMCPCall stores one finished call.
//
// 🔴 INSERT OR IGNORE on the primary key. A duplicate call_id can only come
// from a re-record of the same call, and quietly keeping the first is right —
// but note the asymmetry with the control plane: there, IGNORE is the
// idempotency that makes at-least-once delivery safe; HERE it would mask a
// caller bug, so the caller is told how many rows landed.
func (s *Store) InsertMCPCall(rec mcpwire.CallRecord) error {
	res, err := s.db.Exec(`
		INSERT OR IGNORE INTO mcp_call_event (
			call_id, org_id, seat_id, virtual_server_id, tool_id, tool_name,
			backend_id, session_id, conversation_session_id, app_slug, origin,
			status, error_code, duration_ms, args_digest, args_raw,
			upstream_request_id, manifest_hash, created_at_ms, reported_at_ms
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)`,
		rec.CallID, rec.OrgID, rec.SeatID, rec.VirtualServerID, rec.ToolID, rec.ToolName,
		rec.BackendID, rec.SessionID, rec.ConversationSessionID, rec.AppSlug, rec.Origin,
		rec.Status, rec.ErrorCode, rec.DurationMs, rec.ArgsDigest, argsRawValue(rec.ArgsRaw),
		rec.UpstreamRequestID, rec.ManifestHash, rec.CreatedAtMs)
	if err != nil {
		return fmt.Errorf("insert mcp_call_event: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("insert mcp_call_event: call_id %q already recorded", rec.CallID)
	}
	return nil
}

// argsRawValue keeps NULL and "" distinct all the way into the column.
//
// 🔴 A plain string would store "" for "retention is off", and every later
// reader would then have to guess whether the arguments were withheld or empty.
// Fence 7.F1 asserts this column is NULL in the default configuration.
func argsRawValue(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// UnreportedMCPCalls returns the oldest undelivered records, oldest first.
//
// 🔴 Oldest first so a long outage drains in the order the calls happened. A
// newest-first drain under a persistent backlog would starve the oldest rows
// forever — the ones an incident investigation is most likely to want.
func (s *Store) UnreportedMCPCalls(limit int) ([]mcpwire.CallRecord, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`
		SELECT call_id, org_id, seat_id, virtual_server_id, tool_id, tool_name,
		       backend_id, session_id, conversation_session_id, app_slug, origin,
		       status, error_code, duration_ms, args_digest, args_raw,
		       upstream_request_id, manifest_hash, created_at_ms
		FROM mcp_call_event
		WHERE reported_at_ms = 0
		ORDER BY created_at_ms ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("select unreported mcp calls: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []mcpwire.CallRecord
	for rows.Next() {
		var rec mcpwire.CallRecord
		var raw sql.NullString
		if err := rows.Scan(&rec.CallID, &rec.OrgID, &rec.SeatID, &rec.VirtualServerID,
			&rec.ToolID, &rec.ToolName, &rec.BackendID, &rec.SessionID,
			&rec.ConversationSessionID, &rec.AppSlug, &rec.Origin, &rec.Status,
			&rec.ErrorCode, &rec.DurationMs, &rec.ArgsDigest,
			&raw, &rec.UpstreamRequestID, &rec.ManifestHash, &rec.CreatedAtMs); err != nil {
			return nil, fmt.Errorf("scan unreported mcp call: %w", err)
		}
		if raw.Valid {
			v := raw.String
			rec.ArgsRaw = &v
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// MarkMCPCallsReported stamps delivery.
//
// 🔴 Called ONLY after the control plane has accepted the batch. Stamping
// before would turn one failed POST into permanent data loss, and the loss
// would be invisible: the rows would still be there, just never sent again.
func (s *Store) MarkMCPCallsReported(ctx context.Context, callIDs []string, at time.Time) error {
	if len(callIDs) == 0 {
		return nil
	}
	args := make([]any, 0, len(callIDs)+1)
	args = append(args, at.UnixMilli())
	placeholders := make([]string, len(callIDs))
	for i, id := range callIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	q := "UPDATE mcp_call_event SET reported_at_ms = ? WHERE call_id IN (" +
		strings.Join(placeholders, ",") + ")"
	if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("mark mcp calls reported: %w", err)
	}
	return nil
}

// PruneMCPCallsOlderThan retires local rows past the retention window.
//
// 🔴 UNDELIVERED rows are deleted too, and that is deliberate rather than an
// oversight: a row that has sat undelivered past the whole retention window
// means the control plane has been unreachable for that long, and keeping it
// forever trades an audit gap for a full disk on an employee laptop. The
// project's rule is that stability outranks a delayed audit record — and the
// deletion is COUNTED, so the gap is a number an operator can see rather than
// something that quietly did not happen.
func (s *Store) PruneMCPCallsOlderThan(cutoff time.Time) (pruned, undelivered int64, err error) {
	cut := cutoff.UnixMilli()
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM mcp_call_event WHERE created_at_ms < ? AND reported_at_ms = 0`,
		cut).Scan(&undelivered); err != nil {
		return 0, 0, fmt.Errorf("count undelivered mcp calls before prune: %w", err)
	}
	res, err := s.db.Exec(`DELETE FROM mcp_call_event WHERE created_at_ms < ?`, cut)
	if err != nil {
		return 0, undelivered, fmt.Errorf("prune mcp_call_event: %w", err)
	}
	pruned, _ = res.RowsAffected()
	return pruned, undelivered, nil
}

// CountMCPCalls answers "how many, and how many still undelivered" for
// /health/mcp and for tests. 🔴 The backlog is the honest health signal: a
// growing one is an audit gap forming, and it is invisible in any aggregate the
// console renders.
func (s *Store) CountMCPCalls() (total, unreported int64, err error) {
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM mcp_call_event`).Scan(&total); err != nil {
		return 0, 0, fmt.Errorf("count mcp calls: %w", err)
	}
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM mcp_call_event WHERE reported_at_ms = 0`).Scan(&unreported); err != nil {
		return total, 0, fmt.Errorf("count unreported mcp calls: %w", err)
	}
	return total, unreported, nil
}

// MCPCallRecorder adapts the store to the MCP plane's CallSink.
//
// 🔴 It swallows no failure. The sink interface has no error return on purpose
// — a tool call must not fail because our audit write failed — so the ONLY way
// a lost record can be noticed is this WARN plus the counter behind it. Fence:
// a dropped record shows up as mcp_call_records_dropped_total on /metrics and
// as a non-zero backlog on /health/mcp.
type MCPCallRecorder struct {
	store  func() *Store
	logger *slog.Logger
	onDrop func()
}

// NewMCPCallRecorder wires a sink.
//
// store is a GETTER because the event store is rebuilt on config reload; a
// captured value would write to a closed handle after the first reload.
func NewMCPCallRecorder(store func() *Store, logger *slog.Logger, onDrop func()) *MCPCallRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &MCPCallRecorder{store: store, logger: logger, onDrop: onDrop}
}

// RecordCall implements the MCP plane's CallSink.
func (r *MCPCallRecorder) RecordCall(ctx context.Context, rec mcpwire.CallRecord) {
	var store *Store
	if r.store != nil {
		store = r.store()
	}
	if store == nil {
		r.drop(ctx, rec, "no local event store is open on this node")
		return
	}
	if err := store.InsertMCPCall(rec); err != nil {
		r.drop(ctx, rec, err.Error())
	}
}

func (r *MCPCallRecorder) drop(ctx context.Context, rec mcpwire.CallRecord, reason string) {
	if r.onDrop != nil {
		r.onDrop()
	}
	// 🔴 The tool NAME and the STATUS are logged, never the arguments. A dropped
	// record is exactly the moment somebody is tempted to dump the payload "for
	// debugging" — which would put the raw arguments in a log file, defeating
	// the entire default-digest rule the record itself obeys.
	r.logger.WarnContext(ctx, "an MCP tool call could not be recorded; the local call log is now incomplete",
		"event.name", observability.EventProxyMCPCallRecordDropped,
		"call_id", rec.CallID, "tool", rec.ToolName, "status", rec.Status, "reason", reason)
}

// CallBacklog implements the MCP plane's optional CallBacklogReporter.
//
// 🔴 known=false when the store cannot be read, rather than 0. A zero backlog
// means "everything has been delivered", which is the opposite of what a failed
// count actually tells us.
func (r *MCPCallRecorder) CallBacklog() (int64, bool) {
	if r.store == nil {
		return 0, false
	}
	store := r.store()
	if store == nil {
		return 0, false
	}
	_, unreported, err := store.CountMCPCalls()
	if err != nil {
		r.logger.Warn("MCP call backlog could not be counted; /health/mcp will omit it rather than report zero",
			"event.name", observability.EventProxyMCPCallRecordDropped, "error", err)
		return 0, false
	}
	return unreported, true
}
