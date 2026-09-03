package mcp

// manifestsync.go — periodically ask each backend what tools it has, and report
// the answer.
//
// # Why the PROXY does this and not the control plane
//
// The credentials live here. The control plane holds only ciphertext (D-3/R7),
// so it cannot reach a backend even if it wanted to — and it must not want to:
// a control plane that could connect to backends would be a second, unaudited
// execution path (see the mcpgateway package doc).
//
// So the split is:
//
//	proxy          reaches the backend, computes the fingerprint, REPORTS
//	control plane  compares against the PUBLISHED fingerprint and decides
//
// 🔴 The proxy deliberately does NOT decide. It reports what it saw; the freeze
// verdict is the control plane's, because that is where a human adopts or
// rejects it and where the audit trail lives. A proxy that decided would give
// every node its own opinion of the same upstream.
//
// # 🔴 tools/list is the ONLY probe (R9, fence 3.F2)
//
// Health checking with a real tool is forbidden. The reason is not squeamishness
// about side effects in the abstract: a probe runs on a TIMER, so probing with a
// real tool installs a machine that performs an action on the customer's systems
// every N seconds, forever, that nobody asked for and that no audit trail
// attributes to a person. If that tool writes, it is worse than a bug.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// ManifestSyncInterval is how often each backend is asked.
//
// 🔴 Five minutes, NOT the policy rail's 60 seconds. The two answer different
// questions and cost different amounts: the policy poll is a conditional GET
// against our own control plane and is nearly free, while this one opens a
// connection to a THIRD-PARTY server per backend. Polling someone else's
// service every minute per node is behaviour a customer would reasonably
// complain about, and drift is not a per-minute event.
const ManifestSyncInterval = 5 * time.Minute

// BackendHealth is the three-state verdict for one backend.
//
// 🔴 Three states, not two. "We have not checked" and "we checked and it is
// fine" are different facts, and collapsing them is how a dead backend shows up
// green. The console is forbidden from painting Unknown green (task 8.8a).
type BackendHealth string

const (
	// BackendHealthy — the last tools/list succeeded.
	BackendHealthy BackendHealth = "healthy"
	// BackendCircuitOpen — repeated failures; calls are refused with a
	// remaining-cooldown number rather than attempted.
	BackendCircuitOpen BackendHealth = "circuit_open"
	// BackendUnknown — never probed, or the probe itself could not run.
	// 🔴 Never rendered as healthy.
	BackendUnknown BackendHealth = "unknown"
)

// ObservedManifest is what one sync round saw at one backend.
type ObservedManifest struct {
	BackendID string `json:"backend_id"`
	// ToolHashes maps tool name → manifest_hash, computed with the FROZEN
	// algorithm (mcpwire.ManifestHash).
	ToolHashes map[string]string `json:"tool_hashes"`
	// SetHash detects tools appearing or disappearing. A manifest that silently
	// GAINS a tool is a capability expansion nobody reviewed.
	SetHash string `json:"set_hash"`
	// Tools carries the current definitions so the control plane can render a
	// diff without re-fetching — and so the diff survives the upstream going
	// away mid-review.
	Tools []ObservedTool `json:"tools"`
	// ObservedAtMs is when this round ran.
	ObservedAtMs int64 `json:"observed_at_ms"`
}

// ObservedTool is one tool as the upstream currently describes itself.
//
// 🔴 `Annotations` is carried for DISPLAY only. It is the upstream's claim about
// itself and is not hashed (freeze 0.17), which is precisely why it may never be
// turned into a verdict: an attacker could flip readOnlyHint to dodge review and
// raise no drift at all. It reaches a human as "what the upstream says", and a
// human decides write_op. Fence 3.F8.
type ObservedTool struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description"`
	InputSchema string `json:"input_schema"`
	Annotations string `json:"annotations,omitempty"`
	Hash        string `json:"hash"`
}

// BackendStatus is the sync loop's live view of one backend.
type BackendStatus struct {
	Health BackendHealth
	// LastOKMs is the last successful tools/list. 0 = never.
	LastOKMs int64
	// ConsecutiveFailures drives the circuit breaker.
	ConsecutiveFailures int
	// CooldownUntilMs is when the circuit may close again.
	CooldownUntilMs int64
	// LastError is operator-facing detail. 🔴 Never contains a request body.
	LastError string
	// ToolCount from the last successful round.
	ToolCount int
}

// ManifestReporter delivers an observation to the control plane.
//
// An interface so the sync loop can be tested without a control plane, and so
// Personal (which has neither) can run with a nil reporter.
type ManifestReporter interface {
	Report(ctx context.Context, orgID string, m ObservedManifest) error
}

// ManifestPublisher is the Personal-edition counterpart of ManifestReporter.
//
// 🔴 Symmetric on purpose. A node either REPORTS what it saw upward (there is a
// control plane, and it decides) or PUBLISHES it into its own policy (there is
// not, and the rules in localpublish.go decide). Both end with tools in the
// SAME Policy snapshot read by the SAME catalog — see localpublish.go for why
// the alternative, a Personal-only read path, was rejected.
//
// 🔴 No error return. There is nothing upstream to retry against; a failure
// here is logged where it happens and must not stop the probe loop.
type ManifestPublisher interface {
	Publish(ctx context.Context, m ObservedManifest)
}

// ManifestSyncer probes backends and reports what it finds.
type ManifestSyncer struct {
	store    *PolicyStore
	reporter ManifestReporter
	// publisher is set instead of reporter on a node with no control plane.
	// 🔴 Never both — see NewManifestSyncer.
	publisher ManifestPublisher
	resolver  CredentialResolver
	logger    *slog.Logger
	orgID     string

	mu     sync.RWMutex
	status map[string]*BackendStatus
	now    func() time.Time
}

// CredentialResolver turns a credential id into usable material.
//
// nil until P4. 🔴 A nil resolver means a backend that declares a credential is
// reported UNKNOWN rather than probed — it must not be probed unauthenticated,
// because the resulting 401 would be recorded as "this backend is broken".
type CredentialResolver interface {
	Resolve(ctx context.Context, orgID, credentialID string) (UpstreamCredential, error)
}

// NewManifestSyncer builds the syncer.
//
// 🔴 `reporter` and `publisher` are mutually exclusive: they are two producers
// of one tool list, and a node honouring both would let a developer's local
// observation overwrite what their administrator published — silently, on the
// machine where the tools actually run. When both are given the reporter wins
// (the control plane wins by existing, the same rule EnableLocalMCPPolicy
// applies) and the conflict is logged as an ERROR rather than resolved quietly.
func NewManifestSyncer(orgID string, store *PolicyStore, reporter ManifestReporter, publisher ManifestPublisher, resolver CredentialResolver, logger *slog.Logger) *ManifestSyncer {
	if logger == nil {
		logger = slog.Default()
	}
	if reporter != nil && publisher != nil {
		logger.Error("MCP manifest sync was given both a control-plane reporter and a local publisher; the local publisher is ignored",
			"event.name", observability.EventProxyMCPLocalConfigInvalid)
		publisher = nil
	}
	return &ManifestSyncer{
		store: store, reporter: reporter, publisher: publisher, resolver: resolver,
		logger: logger, orgID: orgID,
		status: map[string]*BackendStatus{},
		now:    time.Now,
	}
}

// Run polls until ctx is canceled.
func (s *ManifestSyncer) Run(ctx context.Context) {
	s.SyncOnce(ctx)
	ticker := time.NewTicker(ManifestSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.SyncOnce(ctx)
		}
	}
}

// SyncOnce probes every backend in the current policy.
//
// 🔴 Sequential, not concurrent. A customer with twenty backends would
// otherwise open twenty simultaneous connections to twenty third-party services
// every five minutes from every node — a traffic pattern that looks like abuse
// from the receiving end. Drift is not urgent enough to justify it.
func (s *ManifestSyncer) SyncOnce(ctx context.Context) {
	snapshot := s.store.Snapshot()
	if snapshot == nil {
		return // no policy yet; nothing to probe.
	}
	for _, b := range snapshot.Backends {
		if b.Status == StatusDisabled {
			// An admin switched it off. Probing anyway would keep a disabled
			// backend's health "fresh", which is the opposite of what disabling
			// is for.
			continue
		}
		s.syncBackend(ctx, b)
	}
}

func (s *ManifestSyncer) syncBackend(ctx context.Context, b PolicyBackend) {
	st := s.statusFor(b.ID)

	// A backend in cooldown is skipped entirely — the circuit is open.
	if st.CooldownUntilMs > s.now().UnixMilli() {
		return
	}

	// 🔴 A REST backend is not probed AT ALL, and is reported UNKNOWN rather
	// than healthy (P9).
	//
	// Two independent reasons, either one sufficient:
	//
	//  1. There is nothing to discover. Its manifest was authored HERE, from an
	//     OpenAPI document a human reviewed — the API has no opinion of its own
	//     to drift from, so a "sync" would compare our answer with our answer.
	//  2. 🔴 There is no safe probe. A probe runs on a TIMER, so probing a REST
	//     API with one of its own operations installs a machine that performs a
	//     real business action on the customer's systems every five minutes,
	//     forever, that nobody asked for and no audit trail attributes to a
	//     person. That is R9's rule, and it bites harder here than on an MCP
	//     server, where tools/list is a protocol handshake with no side effects.
	//
	// 🚫 The alternative — calling it healthy because the row exists — is the
	// one thing a health state must never do: it is green exactly when the API
	// is unreachable.
	if b.Transport == TransportHTTPREST {
		s.markUnknown(b.ID, "a REST backend has no tools/list to probe, and probing it with one of "+
			"its own operations would perform a real action on a timer; its tools come from the import")
		return
	}

	transport, ok := LookupTransport(b.Transport)
	if !ok {
		// 🔴 UNKNOWN, not unhealthy. A transport this build cannot speak is our
		// gap, not the backend's fault, and calling it unhealthy would send an
		// operator to investigate a server that is working fine.
		s.markUnknown(b.ID, "this build has no transport for "+b.Transport)
		return
	}

	up := UpstreamBackend{
		ID: b.ID, Name: b.Name, Transport: b.Transport,
		EndpointURL: b.EndpointURL, Command: b.Command, Args: b.Args,
		EnvKeys: b.EnvKeys, CredentialID: b.CredentialID,
	}
	if b.CredentialID != "" {
		if s.resolver == nil {
			// See CredentialResolver: unknown rather than a probe that would
			// record a 401 as "this backend is broken".
			s.markUnknown(b.ID, "backend needs a credential and none can be resolved on this build")
			return
		}
		cred, err := s.resolver.Resolve(ctx, s.orgID, b.CredentialID)
		if err != nil {
			s.markUnknown(b.ID, "credential could not be resolved")
			s.logger.WarnContext(ctx, "MCP backend credential could not be resolved for the manifest probe",
				"event.name", observability.EventProxyMCPCredentialResolveFailed,
				"backend_id", b.ID, "error", err)
			return
		}
		up.Credential = cred
	}

	tools, err := transport.ListTools(ctx, up)
	if err != nil {
		s.markFailure(b.ID, err)
		return
	}

	wireTools := make([]mcpwire.Tool, 0, len(tools))
	wireTools = append(wireTools, tools...)
	perTool, setHash, hashErr := mcpwire.ManifestHashAll(wireTools)
	if hashErr != nil {
		// A duplicate tool name upstream. 🔴 Reported as a FAILURE rather than
		// silently collapsed: collapsing would let an upstream hide a second,
		// different definition behind a name we already trust.
		s.markFailure(b.ID, hashErr)
		s.logger.WarnContext(ctx, "MCP backend manifest could not be fingerprinted",
			"event.name", observability.EventProxyMCPManifestDriftDetected,
			"backend_id", b.ID, "error", hashErr)
		return
	}

	observed := ObservedManifest{
		BackendID:    b.ID,
		ToolHashes:   perTool,
		SetHash:      setHash,
		ObservedAtMs: s.now().UnixMilli(),
	}
	for _, tl := range tools {
		observed.Tools = append(observed.Tools, ObservedTool{
			Name:        tl.Name,
			Title:       tl.Title,
			Description: tl.Description,
			InputSchema: string(tl.InputSchema),
			Annotations: string(tl.Annotations),
			Hash:        perTool[tl.Name],
		})
	}

	s.markSuccess(b.ID, len(tools))

	if s.publisher != nil {
		// Personal: there is nobody to report to, so the observation becomes
		// the local policy right here. 🔴 Before P14 this branch did not exist
		// and the observation was simply dropped — which is why /mcp/local
		// served an empty tool list on every Personal install (task 14.0).
		// 🚫 Do not "simplify" this back to `if s.reporter == nil { return }`:
		// that IS the defect. See
		// workflow/CI/bugfix/20260902-personal-mcp-local-served-an-empty-tool-list.md
		// and the L1/L2 drills in check-mcp-local-review-can-red.py.
		s.publisher.Publish(ctx, observed)
		return
	}
	if s.reporter == nil {
		return // a build with neither; nothing to do with the observation.
	}
	if err := s.reporter.Report(ctx, s.orgID, observed); err != nil {
		// 🔴 WARN and carry on. The observation is lost for this round and the
		// next one re-sends it — but a reporting failure must never look like a
		// backend failure, because they send an operator to different places.
		s.logger.WarnContext(ctx, "MCP manifest observation could not be reported; it will be re-sent next round",
			"event.name", observability.EventProxyMCPManifestReportFailed,
			"backend_id", b.ID, "error", err)
	}
}

// ---------------------------------------------------------------------------
// health bookkeeping
// ---------------------------------------------------------------------------

// circuitOpenAfter is how many consecutive failures open the circuit.
//
// 🔴 Three, not one. A single failed probe is a network blip; opening on it
// would mean a backend goes dark every time a switch reboots, and the operator
// learns to ignore the state.
const circuitOpenAfter = 3

// circuitCooldown is how long the circuit stays open.
const circuitCooldown = 2 * time.Minute

func (s *ManifestSyncer) statusFor(backendID string) *BackendStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.status[backendID]
	if !ok {
		st = &BackendStatus{Health: BackendUnknown}
		s.status[backendID] = st
	}
	return st
}

func (s *ManifestSyncer) markSuccess(backendID string, toolCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status[backendID]
	st.Health = BackendHealthy
	st.LastOKMs = s.now().UnixMilli()
	st.ConsecutiveFailures = 0
	st.CooldownUntilMs = 0
	st.LastError = ""
	st.ToolCount = toolCount
}

func (s *ManifestSyncer) markFailure(backendID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status[backendID]
	st.ConsecutiveFailures++
	st.LastError = err.Error()
	if st.ConsecutiveFailures >= circuitOpenAfter {
		st.Health = BackendCircuitOpen
		st.CooldownUntilMs = s.now().Add(circuitCooldown).UnixMilli()
		return
	}
	// 🔴 Below the threshold the backend is UNKNOWN, not healthy. It failed; we
	// simply have not decided it is down yet. Leaving it "healthy" would let a
	// backend that fails two probes out of every three read as fine.
	st.Health = BackendUnknown
}

func (s *ManifestSyncer) markUnknown(backendID, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status[backendID]
	st.Health = BackendUnknown
	st.LastError = reason
}

// Status snapshots every backend's health, for GET /health/mcp.
func (s *ManifestSyncer) Status() map[string]BackendStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]BackendStatus, len(s.status))
	for id, st := range s.status {
		out[id] = *st
	}
	return out
}

// LastRoundMs is when a sync round last completed against ANY backend, or 0 if
// none ever has.
//
// 🔴 The answer to "is drift detection alive". A gateway whose prober died keeps
// serving tools perfectly — the freeze rule reads the LAST KNOWN manifest — so
// the only symptom of a dead prober is that upstream changes stop being noticed,
// which is silent by construction. Hence a number on the health endpoint.
func (s *ManifestSyncer) LastRoundMs() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var newest int64
	for _, st := range s.status {
		if st.LastOKMs > newest {
			newest = st.LastOKMs
		}
	}
	return newest
}

// CooldownRemaining reports how long a backend's circuit stays open.
//
// 🔴 Surfaced so MCP_BACKEND_UNAVAILABLE can carry a NUMBER. "Try again later"
// without one is not an actionable error, and the caller is a model that will
// otherwise retry immediately and forever.
func (s *ManifestSyncer) CooldownRemaining(backendID string) time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.status[backendID]
	if !ok || st.CooldownUntilMs == 0 {
		return 0
	}
	remaining := time.UnixMilli(st.CooldownUntilMs).Sub(s.now())
	if remaining < 0 {
		return 0
	}
	return remaining
}
