package mcp

// handler.go — the six frozen public endpoints (freeze 0.13).
//
//	POST   /mcp/{toolset}                        JSON-RPC request
//	GET    /mcp/{toolset}                        SSE back-channel
//	DELETE /mcp/{toolset}                        end session
//	GET    /mcp/capabilities                     advertised support set
//	GET    /.well-known/oauth-protected-resource RFC 9728 metadata
//	GET    /health/mcp                           MCP-plane health
//
// 🔴 These paths are a PUBLIC contract. A customer's developer writes
// /mcp/<slug> into ~/.claude.json; renaming it later is a silent breakage on
// their machine whose only symptom is "cannot connect". Adding endpoints is
// fine; renaming or removing one is not.
//
// # Route registration
//
// The plane registers through server.RouteRegistrar, the seam the OAuth broker
// already uses. Go 1.22+ ServeMux gives more-specific patterns priority, so
// these win over the data plane's `/{path...}` catch-all without any ordering
// discipline in server.go.
//
// 🔴 The `mcp` prefix is additionally protected at the registry level
// (pkg/providerregistry/reserved.go): a provider row claiming proxy_path `mcp`
// is refused at parse time, so the catch-all can never learn to answer /mcp/.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/buildinfo"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// maxRequestBody caps a single JSON-RPC request body.
//
// 1 MiB is far above any real tools/call (arguments are prompts and
// identifiers, not payloads) and far below anything that threatens the process.
// 🔴 Without a cap, an unauthenticated POST could make the plane allocate
// unboundedly while holding one of its finite concurrency slots — turning the
// isolation shell's protection into the attack's amplifier.
const maxRequestBody = 1 << 20

// Handler serves the MCP plane.
type Handler struct {
	catalog   Catalog
	resolver  TokenResolver
	sessions  *SessionStore
	iso       *Isolation
	logger    *slog.Logger
	baseURL   string
	serverTag mcpwire.Implementation
	startedAt time.Time
	// syncer supplies backend health and circuit cooldowns.
	//
	// 🔴 A FUNCTION, not a value. The manifest sync starts AFTER the HTTP
	// surface is built (it probes the backends the policy names, so it has
	// nothing to do until the policy rail has run), which means a value captured
	// here would be nil forever. That is the same "frozen at wiring time" trap
	// the policy store and the fallback timeout both avoid, and it fails
	// silently: every cooldown would read as zero and every refusal would lose
	// its retry hint.
	syncer func() *ManifestSyncer
	// credentials resolves a backend credential id to material. nil until P4;
	// a backend that declares a credential is then REFUSED rather than tried
	// unauthenticated.
	credentials CredentialResolver
	// compliance runs tool arguments and results past the SAME DLP filter the
	// LLM path uses. nil where no filter app is installed, which is the common
	// default and costs nothing behind the nil check.
	compliance *complianceScanner
	// calls receives one record per tools/call, refusals included (R10). nil on
	// a node with no local store — the plane still serves, and /health/mcp says
	// call_recording is off rather than leaving an operator to wonder why the
	// call log is empty.
	calls CallSink
	// callStats feeds GET /metrics. Never nil in production wiring; a nil is
	// tolerated so a test can drive the handler without a counter set.
	callStats *CallStats
	// policyStore is read ONLY by /health/mcp, to report how long since the
	// control plane was last reached. May be nil (Personal, or a build with no
	// rail) — in which case the field is OMITTED from the health document
	// rather than reported as zero, because "not tracked" and "0 seconds ago"
	// are opposite claims.
	policyStore *PolicyStore
	// localApprovals supplies Personal edition's approval state. nil elsewhere.
	localApprovals LocalApprovals
}

// Config is the plane's wiring.
type Config struct {
	// Catalog answers what tools exist. Required.
	Catalog Catalog
	// Resolver resolves bearers. Required — pass the live *vkeys.Registry.
	Resolver TokenResolver
	// Isolation is the shell. Required; see isolation.go for why.
	Isolation *Isolation
	// Sessions may be nil; a default store is created.
	Sessions *SessionStore
	// ExternalBaseURL is how clients reach this proxy, e.g.
	// "http://127.0.0.1:8787". Used to build the RFC 9728 document and the
	// WWW-Authenticate hint. A wrong value here does not break requests, it
	// only sends a stuck client to the wrong metadata URL.
	ExternalBaseURL string
	// Logger may be nil.
	Logger *slog.Logger
	// Syncer supplies backend health + circuit cooldowns. Optional.
	//
	// 🔴 A getter, not a value — see the field it populates.
	Syncer func() *ManifestSyncer
	// Credentials resolves backend credentials. Optional (nil until P4).
	Credentials CredentialResolver
	// Compliance is the DLP filter hook — a GETTER, read per request.
	//
	// 🔴 A getter because the filter child is per config generation: a value
	// captured here would point at the previous generation's child after the
	// first reload, and every scan would come back degraded on a proxy whose
	// filter is in fact running fine.
	Compliance func() apphook.Hook
	// ComplianceRouteClass tells the filter child where ITS OWN audit event
	// should go (personal self-view vs the team control plane). Only the class
	// crosses the pipe — 🚫 never a credential or a URL.
	ComplianceRouteClass uint8
	// ComplianceEvents uploads the audit events the filter hands back for
	// team-routed traffic. Optional; without it the events are dropped and that
	// is logged.
	ComplianceEvents func(ctx context.Context, events [][]byte)
	// Calls receives finished call records. Optional; see the field it fills.
	//
	// 🔴 A SINK, not an uploader: it must return promptly, because it runs on
	// the request goroutine. Delivery to the control plane is a separate rail
	// that retries — putting a customer's tool call behind our control plane's
	// availability is the coupling the isolation shell exists to prevent.
	Calls CallSink
	// CallStats accumulates the counters behind /metrics. Optional.
	CallStats *CallStats
	// PolicyStore lets /health/mcp report the policy rail's freshness. Optional.
	//
	// 🔴 Passed separately from Catalog even though the shipping catalog is
	// built from the same store: health must be able to say "the rail has not
	// synced in 40 minutes" for a build whose catalog is something else, and a
	// health endpoint that can only describe one implementation is a health
	// endpoint that goes quiet exactly when the implementation changes.
	PolicyStore *PolicyStore
	// LocalApprovals supplies Personal edition's approval state to /health/mcp.
	// Optional and nil wherever a control plane owns that verdict.
	//
	// 🔴 A narrow interface rather than *LocalPublisher, so the plane reports on
	// the approval state without depending on who produces it — and so a test
	// can drive both fields without a filesystem.
	LocalApprovals LocalApprovals
}

// LocalApprovals is what /health/mcp needs to know about Personal's approvals.
type LocalApprovals interface {
	Review() []ReviewBackend
	// LoadError is non-empty when the approval record could not be read.
	LoadError() string
}

// NewHandler builds the plane.
func NewHandler(cfg Config) *Handler {
	sessions := cfg.Sessions
	if sessions == nil {
		sessions = NewSessionStore(0)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	base := cfg.ExternalBaseURL
	if base == "" {
		base = "http://127.0.0.1"
	}
	return &Handler{
		catalog:        cfg.Catalog,
		resolver:       cfg.Resolver,
		sessions:       sessions,
		iso:            cfg.Isolation,
		logger:         logger,
		baseURL:        base,
		startedAt:      time.Now(),
		policyStore:    cfg.PolicyStore,
		localApprovals: cfg.LocalApprovals,
		syncer:         cfg.Syncer,
		credentials:    cfg.Credentials,
		calls:          cfg.Calls,
		callStats:      cfg.CallStats,
		compliance: &complianceScanner{
			hookFn:     cfg.Compliance,
			logger:     logger,
			routeClass: cfg.ComplianceRouteClass,
			upload:     cfg.ComplianceEvents,
		},
		serverTag: mcpwire.Implementation{
			Name:    "aikey-mcp-gateway",
			Version: buildinfo.Get().Version,
			Title:   "AiKey MCP Gateway",
		},
	}
}

// RegisterRoutes implements server.RouteRegistrar.
//
// 🔴 Everything except the two unauthenticated discovery documents runs inside
// the isolation shell. /mcp/capabilities and the RFC 9728 document are static
// renders of compiled-in values: putting them behind the concurrency budget
// would mean that when the plane is saturated, the very endpoint an operator
// uses to find out what the plane supports is the one that stops answering.
//
// /health/mcp is likewise outside the shell, for the same reason plus a
// stronger one: a health endpoint that fails under load reports "unhealthy"
// for the wrong reason and destroys its own diagnostic value.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /mcp/capabilities", h.handleCapabilities)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", h.handleProtectedResourceMetadata)
	mux.HandleFunc("GET /health/mcp", h.handleHealth)

	shell := h.iso.Wrap(http.HandlerFunc(h.handleToolsetRPC))
	mux.Handle("POST /mcp/{toolset}", shell)
	mux.Handle("GET /mcp/{toolset}", h.iso.Wrap(http.HandlerFunc(h.handleToolsetSSE)))
	mux.Handle("DELETE /mcp/{toolset}", h.iso.Wrap(http.HandlerFunc(h.handleToolsetDelete)))
}

// ---------------------------------------------------------------------------
// GET /mcp/capabilities  (task 1.6, requirement R1)
// ---------------------------------------------------------------------------

// CapabilitiesDocument is what an operator, a release gate or a pre-sales
// engineer reads to find out what this build actually speaks.
//
// 🔴 It is rendered from mcpwire.SupportedProtocolVersions, the same slice the
// negotiator consults. That identity is the requirement (R1): a documented
// support set that can disagree with the enforced one is worse than no document,
// because people will trust it. Fenced by TestCapabilitiesMatchesNegotiator.
type CapabilitiesDocument struct {
	ProtocolVersions []string `json:"protocol_versions"`
	// Transports the gateway can serve to CLIENTS.
	Transports []string `json:"transports"`
	// Features is the honest enabled-capability list. 🔴 A capability appears
	// here only once it is actually implemented and reachable — this document
	// is quoted in sales conversations, and a hopeful entry becomes a promise.
	Features map[string]bool `json:"features"`
	// ServerInfo identifies the build, so a bug report names a version.
	ServerInfo mcpwire.Implementation `json:"server_info"`
}

func (h *Handler) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, CapabilitiesDocument{
		ProtocolVersions: mcpwire.SupportedProtocolStrings(),
		// 🔴 DERIVED from the registry, not a literal list (P5). A hand-written
		// list is a second source of truth for "what can this build reach", and
		// P5 is exactly the change that would have desynchronised it: adding a
		// transport is one Register call, and nothing would have made anyone
		// edit this line. Fenced by TestCapabilitiesTransportsComeFromTheRegistry.
		Transports: RegisteredTransports(),
		Features:   mcpFeatures(),
		ServerInfo: h.serverTag,
	})
}

// mcpFeatureNames is every capability key this document reports, in the order
// the phases shipped them. A client reads it to decide what it may rely on, and
// sales quotes it.
//
// 🔴 It is a NAME list, not a value list. Whether each one is true is derived
// from featuresNotYetShipped below, so the two cannot disagree.
var mcpFeatureNames = []string{
	// P1 — the access surface itself.
	"tools",
	"protected_resource_meta",
	"session_management",
	// P2 — per-seat grants + the read-time freeze rule.
	"tool_grants",
	// P3 — pending-vs-published manifests; write tools withdrawn on drift.
	"manifest_drift_freeze",
	// P4 — backend credentials in the vault, injected at the transport layer,
	// never visible to the Agent.
	"managed_backend_creds",
	// P5 — local MCP servers hosted as child processes.
	"stdio_backends",
	// P7 — every call recorded with an outcome and an argument digest.
	"call_audit",
	// Not shipped; see featuresNotYetShipped.
	"rate_limiting",
	"oauth_authorization_server",
}

// featuresNotYetShipped names every capability this build does NOT have, with
// the reason a reader needs.
//
// 🔴 ONE declaration, and the document is COMPUTED from it. This list and the
// document used to be two hand-kept lists, and they fell out of step three
// times: P3's drift freeze and P4's managed credentials both shipped while the
// document still said false, and P7's call auditing shipped while BOTH the
// document and the fence still called it unbuilt — so the fence was actively
// holding the error in place. Every one of those errs "safe", and every one
// means a client skipped a feature that works.
//
// Shipping a phase is now one deletion from this map. There is no second place
// to forget.
var featuresNotYetShipped = map[string]string{
	// P6 task 6.1 is blocked: the proxy has no rate-limiting substrate to
	// inherit (P0b is 0/76), and today limit=0 means "unlimited" — the exact
	// conflation the feature exists to remove.
	"rate_limiting": "no rate-limiting substrate exists yet (P0b not started)",

	// 🔴 Permanently false for this release line: sales may describe the RFC
	// 9728 document as "protected-resource metadata", never as "OAuth 2.1
	// support" (tasks 1.8b). Serving two RFC 9728 endpoints is not an
	// authorization server.
	"oauth_authorization_server": "this gateway serves protected-resource metadata only; " +
		"it is not an authorization server",
}

// mcpFeatures builds the document's feature map.
//
// A name is advertised as available unless featuresNotYetShipped explains why
// it is not. 🔴 Derived rather than written out, so "flip the flag" cannot be
// forgotten separately from "delete the reason".
func mcpFeatures() map[string]bool {
	out := make(map[string]bool, len(mcpFeatureNames))
	for _, name := range mcpFeatureNames {
		_, missing := featuresNotYetShipped[name]
		out[name] = !missing
	}
	return out
}

// ---------------------------------------------------------------------------
// GET /.well-known/oauth-protected-resource  (tasks 1.8 / 1.8a)
// ---------------------------------------------------------------------------

func (h *Handler) handleProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, NewProtectedResourceMetadata(h.baseURL))
}

// ---------------------------------------------------------------------------
// POST /mcp/{toolset}
// ---------------------------------------------------------------------------

func (h *Handler) handleToolsetRPC(w http.ResponseWriter, r *http.Request) {
	slug := NormalizeSlug(r.PathValue("toolset"))

	// 🔴 Origin FIRST, before authentication and before reading the body: a
	// rebinding attempt must be refused without the gateway doing any work on
	// its behalf, and without the reply varying by whether its credentials
	// happened to be valid.
	if h.guardOrigin(w, r) {
		return
	}
	if !h.guardProtocolVersionHeader(w, r) {
		return
	}

	ident, authErr := Authenticate(r.Header, h.resolver)
	if authErr != nil {
		h.writeAuthError(w, authErr)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil {
		writeParseError(w, "Could not read the request body.")
		return
	}
	if len(body) > maxRequestBody {
		writeParseError(w, "Request body exceeds the 1 MiB limit for a single JSON-RPC message.")
		return
	}

	var env mcpwire.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		// 🔴 Report the parse failure without echoing the body. An unparseable
		// body may be anything, including a credential pasted into the wrong
		// field, and error strings travel further than we can follow.
		writeParseError(w, "Request body is not a JSON-RPC 2.0 message.")
		return
	}
	if env.JSONRPC != mcpwire.JSONRPCVersion {
		writeJSON(w, http.StatusBadRequest, mcpwire.Envelope{
			JSONRPC: mcpwire.JSONRPCVersion,
			ID:      env.ID,
			Error: &mcpwire.RPCError{
				Code:    mcpwire.CodeInvalidRequest,
				Message: `The "jsonrpc" field must be exactly "2.0".`,
			},
		})
		return
	}

	// 🔴 A notification gets 202 and NO body. Answering one is a protocol
	// violation that several clients treat as fatal — they see a response with
	// no matching request id and tear down the session.
	if env.IsNotification() {
		h.handleNotification(r, slug, ident, env)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch env.Method {
	case mcpwire.MethodInitialize:
		h.handleInitialize(w, r, slug, ident, env)
	case mcpwire.MethodPing:
		// Ping carries no semantics beyond liveness; an empty result is the
		// specified answer.
		writeRPCResult(w, env.ID, struct{}{})
	case mcpwire.MethodToolsList:
		h.handleToolsList(w, r, slug, ident, env)
	case mcpwire.MethodToolsCall:
		h.handleToolsCall(w, r, slug, ident, env)
	default:
		writeMethodNotFound(w, env.ID, env.Method)
	}
}

func (h *Handler) handleNotification(r *http.Request, slug string, ident Identity, env mcpwire.Envelope) {
	// notifications/initialized is the client confirming the handshake; there
	// is nothing to do but record it. Other notifications are accepted and
	// ignored rather than rejected: the spec allows a peer to send
	// notifications the other side does not understand, and refusing them
	// would break forward compatibility with newer clients for no gain.
	h.logger.DebugContext(r.Context(), "MCP notification received",
		"method", env.Method, "toolset", slug, "seat", ident.SeatID)
}

func (h *Handler) handleInitialize(w http.ResponseWriter, r *http.Request, slug string, ident Identity, env mcpwire.Envelope) {
	var req mcpwire.InitializeRequest
	if len(env.Params) > 0 {
		if err := json.Unmarshal(env.Params, &req); err != nil {
			writeRPCError(w, env.ID, mcpwire.ErrSchemaInvalid,
				"The initialize params object could not be parsed.",
				&errorData{FieldPath: "params"})
			return
		}
	}

	// The toolset must exist before a session is minted. Minting first and
	// failing later would leave a session id the client believes in, pointing
	// at nothing.
	if _, found := h.catalog.Toolset(r.Context(), ident.OrgID, ident.SeatID, slug); !found {
		h.writeToolsetNotFound(w, env.ID, slug)
		return
	}

	// 🔴 Spec MUST: when the client asks for a revision we do not implement, the
	// server answers with one it DOES support and the CLIENT decides whether to
	// continue. Refusing here was measured to break every current MCP client —
	// see negotiate.go for the correction and the evidence.
	neg := Negotiate(req.ProtocolVersion)
	if neg.Downgraded {
		h.logger.WarnContext(r.Context(),
			"MCP client requested a protocol revision this build does not implement; answered with ours. "+
				"A rising rate here means the client population has moved past this build.",
			"requested", string(neg.Requested),
			"answered", string(neg.Agreed),
			"supported", mcpwire.SupportedProtocolStrings(),
			"toolset", slug)
	}

	sess, err := h.sessions.Create(slug, ident.OrgID, ident.SeatID, neg.Agreed, req.ClientInfo)
	if err != nil {
		// 🔴 crypto/rand failing is a system-level fault. We refuse rather than
		// falling back to a weaker id source: a predictable session id is a
		// permanent vulnerability, and "temporarily" degrading to one is how it
		// becomes permanent.
		h.logger.ErrorContext(r.Context(), "could not mint an MCP session id", "error", err)
		writeInternalError(w, env.ID, "The gateway could not create a session. Retry shortly.")
		return
	}

	w.Header().Set(mcpwire.HeaderSessionID, sess.ID)
	w.Header().Set(mcpwire.HeaderProtocolVersion, string(neg.Agreed))
	writeRPCResult(w, env.ID, mcpwire.InitializeResult{
		ProtocolVersion: neg.Agreed,
		Capabilities: mcpwire.ServerCapabilities{
			// 🔴 ListChanged stays false: the gateway FREEZES on manifest drift
			// (R3) rather than pushing updates, so there is nothing to notify
			// about. Advertising it would promise a notification that never
			// arrives, and clients that rely on it would never refresh.
			Tools: &mcpwire.ToolsCapability{ListChanged: false},
		},
		ServerInfo: h.serverTag,
	})
}

func (h *Handler) handleToolsList(w http.ResponseWriter, r *http.Request, slug string, ident Identity, env mcpwire.Envelope) {
	if !h.checkSession(w, r, slug, env.ID) {
		return
	}
	view, found := h.catalog.Toolset(r.Context(), ident.OrgID, ident.SeatID, slug)
	if !found {
		h.writeToolsetNotFound(w, env.ID, slug)
		return
	}
	// Tools is never nil on the wire: `"tools": null` makes some clients throw,
	// whereas `"tools": []` is unambiguously "this toolset is empty".
	tools := view.Tools
	if tools == nil {
		tools = []mcpwire.Tool{}
	}
	writeRPCResult(w, env.ID, mcpwire.ListToolsResult{Tools: tools})
}

func (h *Handler) handleToolsCall(w http.ResponseWriter, r *http.Request, slug string, ident Identity, env mcpwire.Envelope) {
	// 🔴 The session check runs OUTSIDE the recorder, on the unwrapped writer.
	// An unknown Mcp-Session-Id is a transport-level failure that happens before
	// a tool is named; recording it would invent a row for a call nobody made,
	// in the table an administrator reads to answer "who ran what".
	if !h.checkSession(w, r, slug, env.ID) {
		return
	}

	// From here on every outcome is recorded, refusals included (R10). The
	// recorder wraps the writer; the JSON-RPC writers stamp it on the way out,
	// so a branch added later is recorded without anyone remembering to. See
	// callrecord.go for why the outcome is observed rather than declared.
	rec := h.beginCall(w, r, ident, slug)
	defer rec.finish(h, r)
	w = rec

	var req mcpwire.CallToolRequest
	if err := json.Unmarshal(env.Params, &req); err != nil {
		writeRPCError(w, env.ID, mcpwire.ErrSchemaInvalid,
			"The tools/call params object could not be parsed.",
			&errorData{FieldPath: "params"})
		return
	}

	// 🔴 Authorisation is evaluated HERE, on EVERY call, against the CURRENT
	// policy snapshot — never against anything the session remembers.
	//
	// R8: a revoked grant must stop working within one poll interval even for a
	// client that is already connected. Caching this decision onto the session
	// is the exact shape of "revocation does not take effect", and fence 2.F2
	// exists to make that mistake go red.
	if h.resolver == nil {
		writeInternalError(w, env.ID, "The MCP gateway is not ready.")
		return
	}
	decider, ok := h.catalog.(CallResolver)
	if !ok {
		// A catalog with no call resolution cannot authorise anything, so it
		// must refuse everything. 🔴 Failing CLOSED: a catalog that cannot
		// answer "may this seat run this" has not said yes.
		h.logger.WarnContext(r.Context(),
			"tools/call refused: this catalog cannot evaluate authorisation",
			"toolset", slug, "tool", req.Name)
		writeRPCError(w, env.ID, mcpwire.ErrToolForbidden,
			"Tool execution is not available on this gateway build.", nil)
		return
	}

	// 🔴 The DIGEST is taken before authorisation, so a refused call still shows
	// WHAT SHAPE of arguments was attempted — which is most of what makes a
	// refusal worth recording. 🚫 It stores no values; see mcpwire.DigestArgs.
	rec.arguments(req.Arguments)
	rec.rec.ToolName = req.Name

	tool, state := decider.ResolveCall(r.Context(), ident.OrgID, ident.SeatID, slug, req.Name)
	switch state {
	case CallNotFound:
		// 🔴 "Not granted" and "no such tool" are the SAME answer by design: a
		// tool a seat cannot use must not be discoverable by probing names.
		writeRPCError(w, env.ID, mcpwire.ErrToolForbidden,
			"Tool \""+req.Name+"\" is not available to this seat in toolset \""+slug+"\". "+
				"Run tools/list to see what is available, or ask an administrator to grant it.",
			nil)
		return
	case CallFrozen:
		// R3: a WRITE tool whose upstream manifest drifted. The client may still
		// hold its name from a listing taken before the freeze, so refusing at
		// call time is required — hiding it from the list is not enough.
		writeRPCError(w, env.ID, mcpwire.ErrToolNeedsReview,
			"Tool \""+req.Name+"\" is frozen: its definition changed upstream and it performs write "+
				"operations, so it is unavailable until an administrator reviews the change.",
			nil)
		return
	case CallBackendDisabled:
		writeRPCError(w, env.ID, mcpwire.ErrBackendUnavailable,
			"The MCP backend behind \""+req.Name+"\" has been disabled by an administrator.", nil)
		return
	}

	// P6 task 6.7 — validate the arguments against the tool's OWN inputSchema
	// before anything is contacted.
	//
	// 🔴 The ordering is the requirement, not a preference. Fence 6.F5 asserts
	// the upstream sees ZERO calls for malformed arguments: this gateway sits in
	// front of a customer's production database, and "let the backend reject it"
	// means a malformed call reaches that database first.
	//
	// 🔴 It runs AFTER authorisation, on purpose. Validating first would let an
	// ungranted caller learn a tool's parameter names by watching which ones
	// come back as violations — turning a helpful message into an enumeration
	// oracle for tools the seat may not use.
	rec.tool(tool, h.toolsetIDFor(r.Context(), slug))

	if violations := ValidateArguments(tool.InputSchema, req.Arguments); len(violations) > 0 {
		h.writeSchemaViolations(w, env, req.Name, violations)
		return
	}

	// 🔴 Outbound compliance on the ARGUMENTS (task 7.3, invariant 2).
	//
	// Placed AFTER authorisation and schema validation and BEFORE the backend
	// credential is resolved. After authorisation, so DLP verdicts cannot serve
	// an ungranted caller as an oracle for what a tool accepts; before the
	// credential, so a blocked call never causes a secret to be decrypted into
	// process memory at all.
	verdict := h.compliance.scanArguments(r.Context(), req.Arguments)
	if verdict.Blocked {
		h.writeComplianceBlock(w, r, env, req.Name, verdict, "arguments")
		return
	}
	if verdict.Masked {
		// 🔴 The MASKED arguments are what goes upstream. The record's digest was
		// taken from the ORIGINAL — it holds no values, only shapes, so it
		// describes what the caller sent without carrying what was masked.
		req.Arguments = verdict.Mutated
	}
	// 🔴 Raw retention (task 7.2). This is the ONLY path in the product that
	// stores tool arguments verbatim, and it stores the POST-DLP payload, only
	// when the organisation switched it on, and only when DLP actually ran. See
	// retainRaw for why each of those three is load-bearing.
	if enabled, _ := h.rawArgsRetention(); enabled {
		rec.retainRaw(req.Arguments, verdict, true)
	}

	// The seat is authorised and the tool is servable. Execute it upstream.
	h.executeUpstream(w, r, ident, env, tool, req)
}

// rawArgsRetention reads the org's raw-argument switch from the live policy.
//
// 🔴 Off on a node with no policy store — which is every node that has not
// heard from a control plane. A node must not act on a switch it has never been
// told about, and the safe answer to "should I store the customer's SQL" is no.
func (h *Handler) rawArgsRetention() (bool, int) {
	if h.policyStore == nil {
		return false, 0
	}
	return h.policyStore.RawArgsRetention()
}

// writeComplianceBlock refuses a call an organisation's DLP policy rejected.
//
// 🔴 It names the POLICY, never the matched content. Echoing what was detected
// would send the sensitive value straight back out in an error message — one
// more copy of exactly the data the block exists to contain, this time in
// somebody's terminal scrollback and their agent's context window.
func (h *Handler) writeComplianceBlock(
	w http.ResponseWriter, r *http.Request, env mcpwire.Envelope,
	toolName string, verdict ComplianceVerdict, side string,
) {
	h.logger.InfoContext(r.Context(), "an MCP tool call was refused by the compliance filter",
		"event.name", observability.EventProxyMCPComplianceBlocked,
		"tool", toolName, "side", side, "reason", verdict.Reason)
	h.compliance.uploadEvents(r.Context(), verdict.Events)
	where := "The arguments you sent"
	if side == "result" {
		where = "The data this tool returned"
	}
	writeRPCError(w, env.ID, mcpwire.ErrComplianceBlocked,
		where+" for \""+toolName+"\" were refused by your organisation's compliance policy"+
			reasonSuffix(verdict.Reason)+". The tool itself is available to you — this is a "+
			"CONTENT decision, so re-requesting it will not help. Ask your administrator to "+
			"review the finding in the console (Quality → Compliance).", nil)
}

// reasonSuffix appends the filter's own reason when it gave one.
//
// 🔴 The filter's REASON CODE (e.g. PII_DETECTED), which is a category, never
// the matched text. The distinction is the whole privacy property.
func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

// writeSchemaViolations reports invalid arguments.
//
// 🔴 THIS IS THE ONE PLACE the classification decision lands, and it is
// deliberately a single function so that changing it is a one-line change.
//
// The frozen contract (mcpwire: MCP_SCHEMA_INVALID → HTTP 400, InvalidParams)
// and task 6.7 both say "protocol error, 400, carry the field path". The MCP
// 2025-11-25 revision argues the opposite: input-validation failures should be
// TOOL EXECUTION errors (`CallToolResult.isError = true`), because a protocol
// error is invisible to the model — the client treats it as a transport fault,
// so the model never learns its arguments were wrong and cannot correct them.
//
// 🔴 The two are NOT in conflict about the important half: either way the
// upstream is not called. What differs is only how the answer is SHAPED. That
// choice is registered as an open decision (mcp-2025-11-25-impact.md, 冲突 A),
// which explicitly reserves it rather than letting the implementer settle it —
// so this implements the frozen contract, and switching to the in-band form is
// a change to this function alone.
func (h *Handler) writeSchemaViolations(w http.ResponseWriter, env mcpwire.Envelope, toolName string, violations []SchemaViolation) {
	paths := make([]string, 0, len(violations))
	lines := make([]string, 0, len(violations))
	for _, v := range violations {
		paths = append(paths, v.Path)
		lines = append(lines, "  "+v.String())
	}
	// 🔴 The message carries EVERY path, because the consumer is a model and
	// "arguments are invalid" is not something it can act on. It also says the
	// upstream was not called — otherwise a developer reading this cannot tell
	// whether their database already saw the malformed call.
	//
	// 🔴 The structured field is the FROZEN `field_path` (singular), carrying
	// the first violation. 🚫 No parallel plural field was added: the frozen
	// error shape is a published contract, the full list is already in the
	// message, and a second field meaning almost-the-same thing is how two
	// consumers end up reading different ones.
	first := ""
	if len(paths) > 0 {
		first = paths[0]
	}
	writeRPCError(w, env.ID, mcpwire.ErrSchemaInvalid,
		"Arguments for \""+toolName+"\" do not satisfy the tool's inputSchema, so it was NOT called:\n"+
			strings.Join(lines, "\n"),
		&errorData{FieldPath: first})
}

// executeUpstream forwards an authorised tools/call to the backend.
//
// 🔴 Everything that decides WHETHER the call happens is already done by the
// time we get here (grant, freeze state, backend status). This function's only
// job is the round trip and the honest reporting of its outcome — keeping the
// two apart is what stops "make the upstream work" changes from quietly
// loosening an authorisation check.
func (h *Handler) executeUpstream(w http.ResponseWriter, r *http.Request, ident Identity, env mcpwire.Envelope, tool PolicyTool, req mcpwire.CallToolRequest) {
	backend, ok := h.backendFor(r.Context(), tool.BackendID)
	if !ok {
		writeRPCError(w, env.ID, mcpwire.ErrBackendUnavailable,
			"No MCP backend is registered for this tool. Register one in the console (Keys → MCP backends).", nil)
		return
	}

	// 🔴 A circuit-open backend is refused WITH THE REMAINING SECONDS. The
	// caller is a model; "try again later" without a number makes it retry
	// immediately and forever.
	if syncer := h.currentSyncer(); syncer != nil {
		if remaining := syncer.CooldownRemaining(tool.BackendID); remaining > 0 {
			secs := int(remaining.Seconds()) + 1
			writeRPCHTTPErrorInBand(w, env.ID, mcpwire.ErrBackendUnavailable,
				"Backend \""+backend.Name+"\" is temporarily unavailable after repeated failures. "+
					"Retry in about "+itoa(secs)+" seconds.",
				&errorData{RetryAfterSeconds: secs})
			return
		}
	}

	if _, ok := LookupTransport(backend.Transport); !ok {
		// 🔴 OUR gap, not the backend's. Reported without an EXT_ code so the
		// customer is not sent to debug a server that is working.
		h.logger.ErrorContext(r.Context(), "no transport registered for an MCP backend",
			"backend_id", backend.ID, "transport", backend.Transport)
		writeRPCError(w, env.ID, mcpwire.ErrBackendUnavailable,
			"This gateway build cannot reach a \""+backend.Transport+"\" backend.", nil)
		return
	}

	up := UpstreamBackend{
		ID: backend.ID, Name: backend.Name, Transport: backend.Transport,
		EndpointURL: backend.EndpointURL, Command: backend.Command, Args: backend.Args,
		EnvKeys: backend.EnvKeys, CredentialID: backend.CredentialID,
		// P9: how to turn this call into an HTTP request, for a backend that is a
		// REST API rather than an MCP server. Empty for everything else.
		RESTBinding: tool.HTTPBinding,
	}
	if backend.CredentialID != "" {
		if h.credentials == nil {
			// 🔴 Refused rather than attempted unauthenticated. A bare request
			// to an endpoint that expects auth yields a 401 that reads like the
			// customer's token is wrong, sending them to rotate a credential
			// that was never the problem.
			writeRPCError(w, env.ID, mcpwire.ErrCredentialMissing,
				"Backend \""+backend.Name+"\" has a credential bound, but this gateway build cannot "+
					"resolve it. Bind the credential in the console (Keys → MCP backends).", nil)
			return
		}
		cred, err := h.credentials.Resolve(r.Context(), ident.OrgID, backend.CredentialID)
		if err != nil {
			h.logger.ErrorContext(r.Context(), "MCP backend credential could not be resolved",
				"event.name", observability.EventProxyMCPCredentialResolveFailed,
				"backend_id", backend.ID, "error", err)
			writeRPCError(w, env.ID, mcpwire.ErrCredentialMissing,
				"Backend \""+backend.Name+"\" has a credential bound but it could not be decrypted. "+
					"Re-bind it in the console (Keys → MCP backends).", nil)
			return
		}
		up.Credential = cred
	}

	// 🔴 The UPSTREAM name, not the alias. An alias is our renaming of the tool
	// within a toolset; the backend has never heard of it.
	result, err := h.callWithRestrictedRetry(r, up, tool, req, backend)
	if err != nil {
		h.writeUpstreamError(w, r, env.ID, backend, tool, err)
		return
	}

	// 🔴 Inbound compliance on the RESULT (task 7.3, invariant 2). This is where
	// the volume is: a tool that answers a query returns the rows themselves, so
	// a gateway that scanned only the request would stop at the door that is
	// cheapest to walk around.
	//
	// 🔴 A block here still costs the upstream call — the tool already ran. That
	// is unavoidable and is not a reason to skip the scan: the point is that the
	// DATA does not reach the model.
	if verdict := h.compliance.scanResult(r.Context(), result); verdict.Blocked {
		h.writeComplianceBlock(w, r, env, tool.Name, verdict, "result")
		return
	}
	writeRPCResult(w, env.ID, result)
}

// callWithRestrictedRetry performs the tool call, retrying ONLY where retrying
// cannot execute the tool twice (P6 tasks 6.5 / 6.6, requirement R4).
//
// # The rule, and why it is this narrow
//
// A retry is safe in exactly two situations:
//
//	the request PROVABLY never arrived  — connection refused, DNS failure, TLS
//	                                      handshake failure. The tool cannot
//	                                      have run, because nothing received it.
//	the tool declares itself idempotent  — running it twice is defined to be the
//	                                      same as running it once.
//
// 🔴 Everything else is NOT retried, including a timeout and including a 5xx.
// Both of those happen AFTER the request was handed over, so `create_issue` may
// already have opened the issue; retrying opens a second one. "The call failed"
// and "the call did not happen" are different facts, and only the second one
// permits a retry.
//
// 🔴 `Idempotent` defaults to FALSE and is set by a human at review — never
// derived from anything the upstream says about itself. The costs are
// asymmetric: a non-idempotent tool wrongly marked idempotent duplicates a
// customer's writes, while the reverse merely costs a retry nobody got.
//
// # Why the suppression is an EVENT
//
// Task 6.6 exists because "we deliberately did not retry" is invisible
// otherwise: the user sees one failed call and assumes the gateway simply gave
// up. The event is what lets an operator answer "why did this not retry" without
// reading this function.
func (h *Handler) callWithRestrictedRetry(
	r *http.Request, up UpstreamBackend, tool PolicyTool,
	req mcpwire.CallToolRequest, backend PolicyBackend,
) (*mcpwire.CallToolResult, error) {
	transport, _ := LookupTransport(backend.Transport)
	result, err := transport.CallTool(r.Context(), up, tool.Name, req.Arguments)
	if err == nil {
		return result, nil
	}

	var ue *UpstreamError
	notAccepted := errors.As(err, &ue) && ue.NotAccepted

	switch {
	case notAccepted:
		// The tool cannot have run. Retrying is free of the duplicate-execution
		// risk entirely — idempotency does not even enter into it.
		h.logger.InfoContext(r.Context(), "MCP tool call retried: the request never reached the backend",
			"event.name", observability.EventProxyMCPRetryAttempted,
			"backend_id", backend.ID, "tool", tool.Name, "reason", "not_accepted")
	case tool.Idempotent:
		h.logger.InfoContext(r.Context(), "MCP tool call retried: the tool is declared idempotent",
			"event.name", observability.EventProxyMCPRetryAttempted,
			"backend_id", backend.ID, "tool", tool.Name, "reason", "idempotent")
	default:
		// 🔴 The deliberate non-retry, made visible.
		h.logger.WarnContext(r.Context(),
			"MCP tool call was NOT retried: the request may already have been executed and the tool is not declared idempotent",
			"event.name", observability.EventProxyMCPRetrySuppressed,
			"backend_id", backend.ID, "tool", tool.Name,
			"upstream_code", upstreamCodeOf(err))
		return nil, err
	}

	retried, retryErr := transport.CallTool(r.Context(), up, tool.Name, req.Arguments)
	if retryErr != nil {
		// 🚫 One retry, never a loop. A second failure is the answer.
		return nil, retryErr
	}
	return retried, nil
}

// upstreamCodeOf extracts the frozen error code for a log field.
func upstreamCodeOf(err error) string {
	var ue *UpstreamError
	if errors.As(err, &ue) {
		return string(ue.Code)
	}
	return "unknown"
}

// backendFor finds the backend record behind a tool.
//
// A catalog that cannot resolve backends yields found=false, and the caller
// answers "no backend is registered". 🔴 Failing CLOSED again: a catalog that
// cannot say where a call should go has not said it may go anywhere.
func (h *Handler) backendFor(ctx context.Context, backendID string) (PolicyBackend, bool) {
	lookup, ok := h.catalog.(BackendResolver)
	if !ok {
		return PolicyBackend{}, false
	}
	return lookup.Backend(ctx, backendID)
}

// writeUpstreamError turns a transport failure into an answer that says WHOSE
// fault it is.
//
// 🔴 The EXT_ prefix is the whole point: it is how a customer decides whether to
// open a ticket with us or with whoever runs their MCP server, and that single
// question is most of the support cost of a gateway product.
func (h *Handler) writeUpstreamError(w http.ResponseWriter, r *http.Request, id json.RawMessage, backend PolicyBackend, tool PolicyTool, err error) {
	if errors.Is(err, ErrCredentialMissing) {
		writeRPCError(w, id, mcpwire.ErrCredentialMissing,
			"Backend \""+backend.Name+"\" requires a credential that is not available.", nil)
		return
	}
	var ue *UpstreamError
	if errors.As(err, &ue) {
		// 🔴 Logged with the detail, answered without it: an upstream dial error
		// can carry internal hostnames, and error strings travel further than we
		// can follow.
		h.logger.WarnContext(r.Context(), "MCP upstream call failed",
			"backend_id", backend.ID, "tool", tool.Name,
			"aikey_code", string(ue.Code), "upstream_status", ue.Status, "detail", ue.Detail)
		msg := "Backend \"" + backend.Name + "\" did not complete the call."
		if ue.Code == mcpwire.ErrUpstreamTimeout {
			msg = "Backend \"" + backend.Name + "\" did not respond in time."
		}
		if ue.Code == mcpwire.ErrCredentialMissing {
			msg = "Backend \"" + backend.Name + "\" rejected the credential we presented."
		}
		writeRPCError(w, id, ue.Code, msg, nil)
		return
	}
	h.logger.ErrorContext(r.Context(), "unclassified MCP upstream failure",
		"backend_id", backend.ID, "tool", tool.Name, "error", err)
	writeInternalError(w, id, "The MCP gateway could not complete this tool call.")
}

// checkSession enforces that a post-handshake request carries a session that
// belongs to THIS toolset.
//
// A missing header is tolerated: the 2024-11-05 revision has no session header
// at all, and rejecting those clients would break the compatibility R1 exists
// to preserve. A PRESENT but unknown or cross-toolset id is rejected — that is
// a real client bug or a stale handle, and silently serving it would let a
// session opened against one toolset read another.
func (h *Handler) checkSession(w http.ResponseWriter, r *http.Request, slug string, id json.RawMessage) bool {
	raw := r.Header.Get(mcpwire.HeaderSessionID)
	if raw == "" {
		return true
	}
	sess, ok := h.sessions.Get(raw)
	if !ok || sess.ToolsetSlug != slug {
		// 🔴 HTTP 404, not an in-band JSON-RPC error. The transport spec makes
		// the status code load-bearing: "The server MAY terminate the session at
		// any time, after which it MUST respond to requests containing that
		// session ID with HTTP 404 Not Found… When a client receives HTTP 404 in
		// response to a request containing an Mcp-Session-Id, it MUST start a new
		// session by sending a new InitializeRequest."
		//
		// Answering 200 + an error body — which this did until 2026-09-01 — is
		// interoperable-looking and functionally dead: the client never learns it
		// should re-initialize, so a proxy restart leaves every connected client
		// permanently broken until a human restarts it too.
		writeRPCHTTPError(w, id, mcpwire.ErrSessionNotFound,
			"This Mcp-Session-Id is unknown, expired, or belongs to a different toolset. "+
				"Run initialize again to obtain a new session.", nil)
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// GET /mcp/{toolset} — SSE back-channel
// ---------------------------------------------------------------------------

// handleToolsetSSE opens the server→client event stream.
//
// 🔴 The gateway currently pushes NOTHING on this channel: it does not send
// tools/list_changed (manifest drift freezes instead of pushing, R3) and it has
// no server-initiated requests. So the stream is opened, kept alive, and closed
// when the client goes away.
//
// It still has to EXIST. Spec-compliant clients open it right after initialize;
// a 404 or 405 here is read by several of them as "this server is broken" and
// aborts the session that was otherwise about to work.
func (h *Handler) handleToolsetSSE(w http.ResponseWriter, r *http.Request) {
	slug := NormalizeSlug(r.PathValue("toolset"))
	if h.guardOrigin(w, r) {
		return
	}
	ident, authErr := Authenticate(r.Header, h.resolver)
	if authErr != nil {
		h.writeAuthError(w, authErr)
		return
	}
	if _, found := h.catalog.Toolset(r.Context(), ident.OrgID, ident.SeatID, slug); !found {
		h.writeToolsetNotFound(w, nil, slug)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeInternalError(w, nil, "This server cannot stream responses.")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	// An immediate comment frame flushes headers, so a client waiting for the
	// stream to "open" does not sit on a buffered response wondering.
	_, _ = io.WriteString(w, ": aikey mcp stream open\n\n")
	flusher.Flush()

	// Hold until the client leaves or the isolation shell's timeout fires.
	// 🔴 No goroutine is spawned: this handler IS the stream's lifetime, so the
	// concurrency budget already accounts for it. Spawning would hide the cost
	// from the very budget that exists to bound it.
	<-r.Context().Done()
}

// ---------------------------------------------------------------------------
// DELETE /mcp/{toolset}
// ---------------------------------------------------------------------------

// handleToolsetDelete ends a session. Idempotent — deleting an unknown session
// is 204, because a client retrying after a dropped response must not be told
// it failed at the thing it already succeeded at.
func (h *Handler) handleToolsetDelete(w http.ResponseWriter, r *http.Request) {
	if h.guardOrigin(w, r) {
		return
	}
	if _, authErr := Authenticate(r.Header, h.resolver); authErr != nil {
		h.writeAuthError(w, authErr)
		return
	}
	if id := r.Header.Get(mcpwire.HeaderSessionID); id != "" {
		h.sessions.Delete(id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func (h *Handler) writeAuthError(w http.ResponseWriter, e *AuthError) {
	if e.StatusCode == http.StatusUnauthorized {
		// 🔴 RFC 9728: the challenge points at the metadata document so a
		// compliant client degrades to "ask the user for a token" instead of
		// hanging in discovery. Fence 1.F4.
		w.Header().Set("WWW-Authenticate", WWWAuthenticate(h.baseURL))
	}
	if e.Code == "" {
		writeJSON(w, e.StatusCode, mcpwire.Envelope{
			JSONRPC: mcpwire.JSONRPCVersion,
			Error:   &mcpwire.RPCError{Code: mcpwire.CodeInvalidRequest, Message: e.Message},
		})
		return
	}
	writeRPCHTTPError(w, nil, e.Code, e.Message, nil)
}

// writeToolsetNotFound answers for a slug this reader cannot see.
//
// 🔴 It does not distinguish "no such toolset" from "exists, not yours". The
// second answer would tell a caller that a toolset by that name exists in
// another org, which is a tenancy leak that costs nothing to avoid.
func (h *Handler) writeToolsetNotFound(w http.ResponseWriter, id json.RawMessage, slug string) {
	msg := "No MCP toolset named \"" + slug + "\" is available to this key. " +
		"Check the endpoint URL, or ask an administrator to grant you a toolset."
	if id == nil {
		writeJSON(w, http.StatusNotFound, mcpwire.Envelope{
			JSONRPC: mcpwire.JSONRPCVersion,
			Error:   &mcpwire.RPCError{Code: mcpwire.CodeInvalidRequest, Message: msg},
		})
		return
	}
	writeRPCError(w, id, mcpwire.ErrToolForbidden, msg, nil)
}

// NormalizeSlug is the one definition of how a toolset slug is compared.
//
// Lower-cased and trimmed, matching how provider path prefixes are normalised
// (pkg/providerregistry norm). Having ONE definition matters because the
// console, the CLI and this router all have to agree on whether "GitHub" and
// "github" are the same toolset — and if they disagree, the symptom is a 404
// that looks like a permissions problem.
func NormalizeSlug(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// mcpProtocolStrings is a thin alias so health.go does not import mcpwire just
// for one call; it also keeps the health document and /mcp/capabilities reading
// from the same source (requirement R1).
func mcpProtocolStrings() []string { return mcpwire.SupportedProtocolStrings() }

// guardProtocolVersionHeader enforces the per-request MCP-Protocol-Version
// rule. Returns false when the request has been answered and must stop.
//
// 🔴 This is where the frozen MCP_PROTOCOL_UNSUPPORTED code lives now that
// handshake negotiation answers with our own revision instead of refusing. The
// transport spec is explicit that this one is a refusal:
// "If the server receives a request with an invalid or unsupported
// MCP-Protocol-Version, it MUST respond with 400 Bad Request."
func (h *Handler) guardProtocolVersionHeader(w http.ResponseWriter, r *http.Request) bool {
	raw := r.Header.Get(mcpwire.HeaderProtocolVersion)
	version, ok := CheckProtocolVersionHeader(raw)
	if ok {
		return true
	}
	h.logger.WarnContext(r.Context(),
		"rejected an MCP request whose MCP-Protocol-Version header names an unimplemented revision",
		"requested", string(version),
		"supported", mcpwire.SupportedProtocolStrings(),
		"path", r.URL.Path)
	writeRPCHTTPError(w, nil, mcpwire.ErrProtocolUnsupported,
		UnsupportedHeaderMessage(version),
		&errorData{SupportedVersions: mcpwire.SupportedProtocolStrings()})
	return false
}

// currentSyncer reads the live manifest syncer, or nil when none is installed.
func (h *Handler) currentSyncer() *ManifestSyncer {
	if h.syncer == nil {
		return nil
	}
	return h.syncer()
}
