// mcp_policy.go — the MCP policy follower.
//
// # Problem it solves
//
// An administrator grants a seat access to a toolset, or revokes it. That
// decision lives in the control plane; the thing that enforces it is a proxy on
// a developer's machine. Without a rail between them, the enforcement point
// never learns — and the console shows a change that is applied everywhere
// except where it matters.
//
// # 🔴 The four semantics, inherited VERBATIM from the quota rail
//
// This is deliberately the same shape as quota_policy.go, not a second design:
//
//	60s + one immediate     the interval is the number the console quotes to an
//	                        admin ("effective within 60 seconds"), so it must be
//	                        the same number in both places.
//	whole-snapshot replace  a poll REPLACES the policy. No deltas, no replay log,
//	                        no ordering to get wrong. A proxy that missed three
//	                        changes converges on the next poll.
//	write only on change    the conditional GET answers 304 when nothing moved,
//	                        so the steady state costs one integer comparison.
//	stale keeps serving     🔴 an unreachable control plane leaves the last known
//	                        policy in force. The alternative — reverting to "no
//	                        tools" on a failed poll — would disconnect every
//	                        Agent in the fleet the moment a switch rebooted.
//	                        /health/mcp reports the age so the staleness is
//	                        visible rather than silent.
//
// 🔴 And one more, which the quota rail does not need: the poller is a COMPLETE
// no-op when the node has no control plane. Personal edition configures its MCP
// backends locally and has no org at all; a rail that logged an error every 60
// seconds there would train operators to ignore the log.

package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/mcp"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// mcpPollInterval matches quotaPollInterval and the control plane's
// PolicyPollIntervalSeconds.
//
// 🔴 Three places must agree on this number: here, the control plane's revoke
// response ("effective within N seconds"), and the console copy an admin reads.
// A drift makes the product lie about its own revocation latency.
const mcpPollInterval = 60 * time.Second

var mcpHTTPClient = httpx.NewSwappableDirect(10 * time.Second)

// MCPPolicyRail is the follower's state.
type MCPPolicyRail struct {
	store  *mcp.PolicyStore
	cache  *mcp.PolicyCache
	syncer *mcp.ManifestSyncer
}

// NewMCPPolicyRail builds the rail and restores the on-disk cache.
//
// 🔴 The restore happens HERE, before the first poll, so a proxy that starts
// while the control plane is down serves its last known policy immediately
// rather than serving nothing for 60 seconds — or forever, if the control plane
// stays down.
func NewMCPPolicyRail(orgID string, logger *slog.Logger) *MCPPolicyRail {
	store := mcp.NewPolicyStore()
	cache := mcp.NewPolicyCache(logger, 0)
	if restored := cache.Load(orgID); restored != nil {
		store.Store(restored)
		// 🔴 The restored policy does NOT count as a successful poll: it proves
		// nothing about reachability. Store() sets the freshness clock, so it is
		// immediately reset — otherwise /health/mcp would report a healthy rail
		// on a node that has never once reached the control plane.
		store.MarkNeverPolled()
		logger.Info("MCP policy restored from the local cache; serving it until the first live poll",
			"event.name", observability.EventProxyMCPPolicyChanged,
			"version", restored.Version,
			"toolsets", len(restored.Toolsets))
	}
	return &MCPPolicyRail{store: store, cache: cache}
}

// Store exposes the live snapshot to the MCP plane.
func (r *MCPPolicyRail) Store() *mcp.PolicyStore { return r.store }

// Syncer exposes the manifest prober, so the MCP plane can read backend health
// and circuit cooldowns. nil until AttachSyncer runs.
func (r *MCPPolicyRail) Syncer() *mcp.ManifestSyncer { return r.syncer }

// AttachSyncer installs the manifest prober.
//
// Separate from NewMCPPolicyRail because the syncer needs a credential source
// that only the Supervisor can provide, and the rail is built before the
// Supervisor is fully assembled.
func (r *MCPPolicyRail) AttachSyncer(s *mcp.ManifestSyncer) { r.syncer = s }

// pollMCPPolicy runs until ctx is canceled.
func (s *Supervisor) pollMCPPolicy(ctx context.Context) {
	if s.mcpRail == nil {
		return // no control plane on this node — the whole rail is bypassed.
	}
	s.syncMCPPolicy(ctx)
	ticker := time.NewTicker(mcpPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncMCPPolicy(ctx)
		}
	}
}

// syncMCPPolicy performs one conditional poll.
//
// 🔴 EVERY failure path returns without touching the store. That is the
// "stale keeps serving" semantic, and it is the reason this function has no
// error return: there is nothing a caller could usefully do, and giving it one
// would invite somebody to "handle" a failed poll by clearing the policy.
func (s *Supervisor) syncMCPPolicy(ctx context.Context) {
	rail := s.mcpRail
	if rail == nil {
		return
	}
	masterURL, orgID := s.mcpPolicyTarget()
	if masterURL == "" || orgID == "" {
		return // not configured; not an error.
	}

	policy, changed, ok := fetchMCPPolicy(ctx, masterURL, orgID, rail.store.Version())
	if !ok {
		// Unreachable or malformed. Keep last-known and say nothing at ERROR:
		// a proxy on a laptop is offline routinely, and an ERROR per minute
		// would bury the one that matters. /health/mcp carries the age, which is
		// the signal an operator should be reading.
		slog.Debug("MCP policy poll did not succeed; keeping the last known policy",
			"org_id", orgID)
		return
	}
	if !changed {
		// 🔴 A 304 proves REACHABILITY, so the freshness clock must advance even
		// though no value moved. Without this a fleet whose policy is simply
		// stable looks increasingly stale.
		rail.store.TouchSuccess()
		return
	}

	rail.store.Store(policy)
	rail.cache.Save(policy)
	slog.Info("MCP policy changed",
		"event.name", observability.EventProxyMCPPolicyChanged,
		"org_id", orgID,
		"version", policy.Version,
		"toolsets", len(policy.Toolsets),
		"grants", len(policy.Grants))
}

// fetchMCPPolicy performs the conditional GET.
//
// Returns (policy, changed, ok). ok=false on ANY error so the caller keeps the
// last-known value; changed=false on a 304.
func fetchMCPPolicy(ctx context.Context, masterURL, orgID string, knownVersion int64) (*mcp.Policy, bool, bool) {
	u := masterURL + "/v1/mcp/policy?org_id=" + url.QueryEscape(orgID) +
		"&version=" + strconv.FormatInt(knownVersion, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, false, false
	}
	resp, err := mcpHTTPClient.Get().Do(req)
	if err != nil {
		return nil, false, false
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, false, true
	case http.StatusOK:
	default:
		// 🔴 A 404 here is the "handler exists but was never routed" failure
		// this repo has shipped three times. It is indistinguishable from an
		// unreachable control plane at this layer, which is why the fix is a
		// route-registration fence in the control plane rather than a special
		// case here.
		return nil, false, false
	}

	var policy mcp.Policy
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		// 🔴 WARN, not silence: a control plane answering 200 with a body we
		// cannot parse is a version-skew bug, and it would otherwise present as
		// "the rail never updates" with nothing in the log to explain it.
		slog.Warn("MCP policy response could not be decoded; keeping the last known policy",
			"event.name", observability.EventProxyMCPPolicyDecodeFailed,
			"org_id", orgID, "error", err)
		return nil, false, false
	}
	if policy.OrgID != "" && policy.OrgID != orgID {
		// Answering with another organisation's policy is a control-plane bug,
		// but applying it would be OUR data-leak. Refuse and keep last-known.
		slog.Warn("MCP policy response is for a different organization; refusing to apply it",
			"event.name", observability.EventProxyMCPPolicyDecodeFailed,
			"requested_org", orgID, "returned_org", policy.OrgID)
		return nil, false, false
	}
	return &policy, true, true
}

// mcpPolicyTarget resolves where to poll and for which organisation.
//
// 🔴 It reads the SAME sources the quota rail reads — the control-panel URL and
// the active team managed keys — rather than introducing a config key of its
// own. Two ways to say "which org is this node in" is two answers that can
// disagree, and the one that disagrees silently is the one that ships.
//
// Returns ("", "") on a node with no control plane (Personal). That is the
// normal case there, not an error: Personal configures its MCP backends locally
// and has no org to follow.
func (s *Supervisor) mcpPolicyTarget() (masterURL, orgID string) {
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return "", ""
	}
	masterURL = readControlPanelURL()
	if masterURL == "" {
		return "", ""
	}
	mks, _ := gen.vault.GetActiveManagedKeys()
	orgID = resolveTeamOrgIDFromKeys(os.Getenv("AIKEY_HUB_ORG_ID"), mks)
	if orgID == "" {
		return "", ""
	}
	return masterURL, orgID
}

// EnableLocalMCPPolicy installs a policy built from this machine's own
// mcp.json (P5, Personal edition).
//
// 🔴 It is REFUSED when the node already follows a control plane. Local config
// and org policy are two producers of one snapshot, and a node that honoured
// both would let a developer grant themselves a tool their administrator did
// not — silently, on the machine where the tools actually run. There is no
// merge semantics here on purpose: the control plane wins by existing.
func (s *Supervisor) EnableLocalMCPPolicy(store *mcp.PolicyStore) error {
	if s.mcpRail != nil {
		return errors.New("supervisor: this node follows a control plane; local MCP config is ignored")
	}
	s.mcpLocalPolicy = store
	return nil
}

// StartLocalMCPManifestSync probes the locally hosted backends so their tools
// are discovered, exactly as they are for a remote backend, and PUBLISHES what
// it finds into this node's own policy.
//
// 🔴 The syncer runs with a nil REPORTER (there is no control plane to report
// to) and a non-nil PUBLISHER. Before P14 it had neither, so the observation
// was discarded and `/mcp/local` served an empty tool list on every Personal
// install — see internal/mcp/localpublish.go, task 14.0.
//
// The publisher is returned so the admin surface can render and accept reviews;
// nil when the approval path could not be resolved, which is reported by the
// caller rather than swallowed.
func (s *Supervisor) StartLocalMCPManifestSync() {
	if s.mcpLocalPolicy == nil {
		return
	}
	var credResolver mcp.CredentialResolver
	if s.mcpCredentials != nil {
		credResolver = s.mcpCredentials
	}
	path, err := mcp.LocalManifestPath()
	if err != nil {
		// 🔴 Non-fatal and loud. Without a path the approvals cannot survive a
		// restart, but serving no tools at all would be worse — so the publisher
		// still runs, in memory, and says so.
		slog.Error("MCP local manifest approvals have no resolvable path; approvals will not survive a restart",
			"event.name", observability.EventProxyMCPLocalManifestUnwritable, "error", err)
	}
	publisher := mcp.NewLocalPublisher(path, s.mcpLocalPolicy, slog.Default())
	s.mcpLocalPublisher = publisher
	syncer := mcp.NewManifestSyncer("", s.mcpLocalPolicy, nil, publisher, credResolver, slog.Default())
	s.mcpLocalSyncer = syncer
	observability.GoSafe("supervisor.mcp_local_manifest_sync", observability.Isolated,
		func() { syncer.Run(s.ctx) })
}

// MCPLocalPublisher exposes Personal edition's approval state to the admin
// surface. nil on a node that follows a control plane — where reviewing is the
// console's job, not this proxy's.
func (s *Supervisor) MCPLocalPublisher() *mcp.LocalPublisher { return s.mcpLocalPublisher }

// RefreshLocalMCP re-reads ~/.aikey/mcp.json and probes every backend in it,
// now.
//
// bugfix: workflow/CI/bugfix/20260902-mcp-json-was-never-re-read-after-startup.md
// regression fence: `make -C workflow/CI verify-mcp-local-review` drill G7
//
// 🔴 It exists because there was no such path at all. `mountLocalMCP` runs ONCE,
// inside process start-up, so a server registered by `aikey mcp add` did nothing
// whatsoever until the proxy was restarted — and nothing said so: the CLI
// reported "backend added", the proxy logged nothing, and the developer's Agent
// simply had no new tools. Adoption made that unacceptable rather than merely
// bad: `aikey mcp adopt` rewrites the client config in the same breath, so
// without this the user would be pointed at a gateway that had never heard of
// the servers it had just taken over.
//
// It is also what lets the first-review gate be a CONVERSATION instead of a
// wait: adopt registers, calls this, and shows the human what arrived — rather
// than telling them to come back in five minutes when the timer next fires.
//
// 🔴 Synchronous, and slow by design: it opens a connection to every configured
// backend. That is fine for a command a human typed and would not be for the
// five-minute timer, which is why they are separate entry points into the same
// syncer.
func (s *Supervisor) RefreshLocalMCP() error {
	if s.mcpLocalPolicy == nil || s.mcpLocalSyncer == nil {
		return errors.New("supervisor: this node has no local MCP config to refresh")
	}
	path, err := mcp.LocalConfigPath()
	if err != nil {
		return fmt.Errorf("resolve the local MCP config: %w", err)
	}
	cfg, err := mcp.LoadLocalConfig(path)
	if errors.Is(err, mcp.ErrNoLocalConfig) {
		return fmt.Errorf("%s does not exist", path)
	}
	if err != nil {
		return err
	}

	// 🔴 The SAME translation the boot path uses. A second one here would be a
	// second producer of the policy, and the first rule it forgot would be one
	// that only applies on the edition where the tools run on the user's own
	// machine.
	const localOrg, localSeat = "", ""
	policy, problems := mcp.BuildLocalPolicy(cfg, localOrg, localSeat, s.VaultSecretLookup())
	for _, pr := range problems {
		slog.Error("MCP local backend is misconfigured and has been disabled",
			"event.name", observability.EventProxyMCPLocalConfigInvalid, "error", pr.Error())
	}

	// 🔴 The tools already published survive the reload: the store is rebuilt
	// from the config (which names backends, never tools) and then the probe
	// re-publishes from the APPROVAL RECORD. Storing the bare translation and
	// stopping there would blank every tool until the next probe — a reload that
	// disconnects the Agent it was run to help.
	s.mcpLocalPolicy.Store(policy)

	if s.mcpCredentials != nil {
		material, credProblems := mcp.LocalCredentialMaterial(cfg, s.VaultSecretLookup())
		for _, pr := range credProblems {
			slog.Error("MCP local backend credential could not be read",
				"event.name", observability.EventProxyMCPLocalConfigInvalid, "error", pr.Error())
		}
		s.mcpCredentials.Replace(s.ctx, material)
	}

	slog.Info("MCP local config re-read on request",
		"event.name", observability.EventProxyMCPLocalConfigReloaded,
		"path", path, "backends", len(policy.Backends))

	s.mcpLocalSyncer.SyncOnce(s.ctx)
	return nil
}

// MCPPolicyOrgID returns the organisation this node follows, or "" when it
// follows none.
//
// Exported so app wiring can decide whether to install the rail at all without
// duplicating the resolution logic. 🔴 It reads the same two sources
// mcpPolicyTarget does, so "which org is this node in" keeps exactly one answer.
func (s *Supervisor) MCPPolicyOrgID() string {
	_, orgID := s.mcpPolicyTarget()
	return orgID
}

// StartMCPManifestSync launches the manifest prober.
//
// 🔴 Separate from the policy poll and on a DIFFERENT interval (5 minutes vs
// 60 seconds): the policy poll is a conditional GET against our own control
// plane and is nearly free, while this one opens a connection to a THIRD-PARTY
// server per backend. Polling someone else's service every minute from every
// node is behaviour a customer would reasonably complain about, and drift is not
// a per-minute event.
//
// No-op when the node has no control plane.
func (s *Supervisor) StartMCPManifestSync() {
	if s.mcpRail == nil {
		return
	}
	masterURL, orgID := s.mcpPolicyTarget()
	if masterURL == "" || orgID == "" {
		return
	}
	// P4: the credential store IS the resolver. 🔴 It may still be nil (a node
	// with no MCP credential store), and nil keeps the P3 behaviour exactly: a
	// backend that declares a credential is reported UNKNOWN rather than probed
	// unauthenticated, because the resulting 401 would be recorded as "this
	// backend is broken" and send an operator to debug a server that is working.
	//
	// 🔴 Passed as a typed nil-safe value, not `s.mcpCredentials` directly into
	// an interface parameter: a nil *CredentialStore stored in a non-nil
	// interface would pass the syncer's `resolver == nil` check and then panic
	// on first use — the classic Go typed-nil trap, and it would fire only on a
	// node that has backends WITH credentials, i.e. in front of a customer.
	var credResolver mcp.CredentialResolver
	if s.mcpCredentials != nil {
		credResolver = s.mcpCredentials
	}
	syncer := mcp.NewManifestSyncer(orgID, s.mcpRail.Store(),
		&manifestReporter{masterURL: masterURL, bearer: s.teamBearer},
		// 🚫 No publisher here: on a node with a control plane the manifest
		// verdict is the control plane's, and a second producer would let this
		// node's observation overwrite what an administrator published.
		nil,
		credResolver,
		slog.Default())
	s.mcpRail.AttachSyncer(syncer)
	observability.GoSafe("supervisor.mcp_manifest_sync", observability.Isolated, func() { syncer.Run(s.ctx) })
}

// MCPManifestSyncer exposes the prober to the MCP plane. nil when this node has
// no control plane or the sync has not started.
func (s *Supervisor) MCPManifestSyncer() *mcp.ManifestSyncer {
	if s.mcpRail == nil {
		// Personal: the local syncer, or nil when there is no local config
		// either. Same getter for both editions so the plane has one question
		// to ask, not an edition check.
		return s.mcpLocalSyncer
	}
	return s.mcpRail.Syncer()
}
