package supervisor

// mcp_call_rail.go — shipping recorded MCP tool calls to the control plane.
//
// # 🔴 The local table is the queue
//
// Every call is written to the proxy's own `mcp_call_event` first and shipped
// afterwards. There is no in-memory buffer to lose on restart, no second WAL to
// operate, and no dead-letter file to replay: a record that has not been
// delivered simply still has `reported_at_ms = 0`, and the next drain finds it.
// A control plane that is down for an hour therefore costs a DELAY, not an
// audit gap — and it self-heals with no operator action, which is the property
// this product's private-deployment model needs most.
//
// # 🔴 At-least-once, made safe by the id
//
// The call_id is minted by the PROXY, and the control plane's ingest is
// idempotent on it. So the dangerous case — we delivered, the response was lost,
// we send again — produces no duplicate row. That is what lets this rail mark
// rows reported only AFTER an accepted response: stamping first would turn one
// lost response into permanent, invisible data loss.
//
// # 🔴 AUTHENTICATED, on the credential that already exists
//
// Same team account-JWT the manifest rail and the usage reporter use. 🚫 No
// second token scheme: a second credential for a second rail is a second thing
// to rotate, and the one that gets forgotten is the one that expires at 3am.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// MCPCallDrainInterval is how often undelivered records are shipped.
//
// 🔴 Thirty seconds, and deliberately NOT per-call. A tool call must not wait on
// our control plane (the whole point of the local-first write), and a batched
// drain also means a burst of 500 calls is one request rather than 500. It is
// shorter than the manifest rail's five minutes because this is OUR control
// plane, not a third party's server.
const MCPCallDrainInterval = 30 * time.Second

// mcpCallBatchSize bounds one POST.
//
// 🔴 A bound at all, because after a long outage the backlog is unbounded and a
// single request carrying all of it would be refused by any reverse proxy in
// front of the control plane — turning a recoverable backlog into one that can
// never drain. 200 records is well under any default body limit.
const mcpCallBatchSize = 200

// mcpCallIngestPath is the control plane's intake route. Declared once so the
// rail and the route-registration fence cannot drift apart.
const mcpCallIngestPath = "/v1/mcp/calls"

// StartMCPCallRail launches the drain loop.
//
// 🔴 It does nothing on a node with no control plane. That is not a degraded
// mode: on Personal the local table IS the product's record, read by the CLI,
// and there is nowhere to ship it to. Starting a loop that could never succeed
// would produce a WARN every thirty seconds forever, which is how operators
// learn to ignore WARNs.
func (s *Supervisor) StartMCPCallRail() {
	masterURL, orgID := s.mcpPolicyTarget()
	if masterURL == "" || orgID == "" {
		slog.Debug("MCP call rail not started: this node follows no control plane; " +
			"tool calls are recorded locally only")
		return
	}
	rail := &mcpCallRail{
		masterURL: masterURL,
		orgID:     orgID,
		bearer:    s.teamBearer,
		store:     s.EventStore,
		logger:    slog.Default(),
	}
	observability.GoSafe("supervisor.mcp_call_rail", observability.Isolated,
		func() { rail.run(s.ctx) })
}

type mcpCallRail struct {
	masterURL string
	orgID     string
	bearer    func(ctx context.Context) (string, error)
	// store is a GETTER, not a value. The event store is rebuilt on config
	// reload; a value captured here would keep writing to the closed handle of a
	// previous generation, and every drain would fail with "database is closed"
	// on a proxy that is otherwise perfectly healthy.
	store  func() *events.Store
	logger *slog.Logger
}

func (r *mcpCallRail) run(ctx context.Context) {
	ticker := time.NewTicker(MCPCallDrainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.drainOnce(ctx)
		}
	}
}

// drainOnce ships one batch. It returns nothing: a failure leaves the rows
// exactly where they were, which is the whole recovery mechanism.
func (r *mcpCallRail) drainOnce(ctx context.Context) {
	store := r.store()
	if store == nil {
		return
	}
	batch, err := store.UnreportedMCPCalls(mcpCallBatchSize)
	if err != nil {
		// 🔴 A read failure is WARNed, not swallowed. Silence here would make a
		// corrupted local database look exactly like an idle gateway.
		r.logger.WarnContext(ctx, "MCP call rail could not read undelivered records",
			"event.name", observability.EventProxyMCPCallsUploadFailed, "error", err)
		return
	}
	if len(batch) == 0 {
		return
	}
	if err := r.post(ctx, batch); err != nil {
		r.logger.WarnContext(ctx, "MCP call records could not be delivered to the control plane; "+
			"they remain in the local store and will be re-sent on the next drain",
			"event.name", observability.EventProxyMCPCallsUploadFailed,
			"records", len(batch), "error", err)
		return
	}
	ids := make([]string, 0, len(batch))
	for _, rec := range batch {
		ids = append(ids, rec.CallID)
	}
	if err := store.MarkMCPCallsReported(ctx, ids, time.Now()); err != nil {
		// 🔴 Delivered but not stamped. The next drain re-sends, and the control
		// plane ignores the duplicate — which is exactly why the ingest is
		// idempotent. WARN rather than ERROR: nothing is lost, the work repeats.
		r.logger.WarnContext(ctx, "MCP call records were delivered but could not be marked reported; "+
			"they will be re-sent and ignored as duplicates",
			"event.name", observability.EventProxyMCPCallsUploadFailed, "error", err)
		return
	}
	r.logger.InfoContext(ctx, "MCP call records delivered",
		"event.name", observability.EventProxyMCPCallsUploaded, "records", len(batch))
}

// mcpCallBatch is the request body. A wrapper object rather than a bare array
// so the rail can gain a field later without changing the media type.
type mcpCallBatch struct {
	Calls []mcpwire.CallRecord `json:"calls"`
}

func (r *mcpCallRail) post(ctx context.Context, batch []mcpwire.CallRecord) error {
	body, err := json.Marshal(mcpCallBatch{Calls: batch})
	if err != nil {
		return fmt.Errorf("marshal call records: %w", err)
	}
	u := r.masterURL + mcpCallIngestPath + "?org_id=" + url.QueryEscape(r.orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.bearer != nil {
		token, bErr := r.bearer(ctx)
		if bErr != nil {
			// 🔴 Refuse rather than send unauthenticated. An anonymous POST is
			// rejected anyway, and retrying it every thirty seconds would fill
			// the control plane's log with auth failures that look like an attack.
			return fmt.Errorf("no credential for the MCP call rail: %w", bErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := mcpHTTPClient.Get().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane answered HTTP %d", resp.StatusCode)
	}
	return nil
}
