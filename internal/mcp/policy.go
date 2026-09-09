package mcp

// policy.go — the proxy's view of the org's MCP policy, and the Catalog that
// serves it.
//
// # What replaced what
//
// P1 shipped StaticCatalog: one fixed tool list, identical for every seat, with
// no grants at all. This file is its replacement — the same Catalog interface,
// now answering from a policy snapshot the control plane owns.
//
// 🔴 The P1 placeholder's honesty warning is retired TOGETHER with the
// placeholder, not before it. Deleting the warning while leaving the fixture
// would have turned a loudly-declared gap into a silent tenancy hole.
//
// # Two rules that look like implementation detail and are not
//
//  1. 🔴 Authorisation is evaluated on EVERY tools/call, from the CURRENT
//     snapshot. Nothing is cached onto a session. R8 requires a revoked grant to
//     stop working within one poll interval even for a client that is already
//     connected, and "we checked when the session opened" is the exact shape of
//     "revocation does not take effect".
//
//  2. 🔴 The freeze decision (R3) is made HERE, at read time, per requester —
//     not by the control plane and not by the sync loop. A read-only tool whose
//     upstream drifted keeps serving its published version; a write tool in the
//     same state disappears from tools/list. Making the decision at read time is
//     what lets an admin's adoption take effect on the very next tools/list
//     instead of after another sync round.

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// PolicyTool is one tool as delivered by the control plane.
//
// Field names and JSON tags mirror the control plane's PolicyTool exactly. They
// are re-declared rather than imported because the proxy must not depend on the
// control-plane module — but the wire shape is one contract, and
// TestPolicyWireShapeMatchesControlPlane keeps the two honest.
type PolicyTool struct {
	// HTTPBinding is how to call this tool when the backend is a plain REST API
	// (transport http_rest, P9). Empty for every MCP-native tool — an MCP server
	// is asked tools/call and needs no mapping.
	HTTPBinding string `json:"http_binding,omitempty"`

	ID          string `json:"id"`
	BackendID   string `json:"backend_id"`
	Name        string `json:"name"`
	Alias       string `json:"alias,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description"`
	InputSchema string `json:"input_schema"`
	// ManifestHash is the PUBLISHED fingerprint — what a human approved.
	ManifestHash string `json:"manifest_hash"`
	// State is one of published / needs_review / auto_admitted. draft and
	// retired never reach the proxy.
	State string `json:"state"`
	// WriteOp decides what a freeze does to this tool. 🔴 Produced by a human at
	// review; never derived from the upstream's own annotations.
	WriteOp    bool   `json:"write_op"`
	Idempotent bool   `json:"idempotent"`
	ToolGroup  string `json:"tool_group,omitempty"`
}

// PolicyToolset is a toolset plus its tools.
type PolicyToolset struct {
	ID     string       `json:"id"`
	Slug   string       `json:"slug"`
	Title  string       `json:"title,omitempty"`
	Status string       `json:"status"`
	Tools  []PolicyTool `json:"tools"`
}

// PolicyBackend is a backend as the proxy needs it. No credential material —
// only the id, which the proxy resolves against its own vault.
type PolicyBackend struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Transport       string   `json:"transport"`
	EndpointURL     string   `json:"endpoint_url,omitempty"`
	Command         string   `json:"command,omitempty"`
	Args            []string `json:"args,omitempty"`
	EnvKeys         []string `json:"env_keys,omitempty"`
	CredentialID    string   `json:"credential_id,omitempty"`
	MTLSCertAlias   string   `json:"mtls_cert_alias,omitempty"`
	Status          string   `json:"status"`
	DiscoverySource string   `json:"discovery_source"`
}

// PolicyGrant is one authorisation row.
type PolicyGrant struct {
	SubjectKind     string `json:"subject_kind"`
	SubjectID       string `json:"subject_id"`
	VirtualServerID string `json:"virtual_server_id"`
}

// Policy is the whole snapshot for one organisation.
type Policy struct {
	// ArgsRawEnabled is the organisation's raw-argument retention switch.
	// 🔴 Default false, and the default IS the security property.
	ArgsRawEnabled bool `json:"args_raw_enabled,omitempty"`
	// ArgsRawRetentionDays is how long raw arguments survive once kept.
	ArgsRawRetentionDays int `json:"args_raw_retention_days,omitempty"`

	OrgID         string          `json:"org_id"`
	Version       int64           `json:"version"`
	Backends      []PolicyBackend `json:"backends"`
	Toolsets      []PolicyToolset `json:"toolsets"`
	Grants        []PolicyGrant   `json:"grants"`
	GeneratedAtMs int64           `json:"generated_at_ms"`
}

// Tool states as they arrive from the control plane.
const (
	ToolStatePublished    = "published"
	ToolStateNeedsReview  = "needs_review"
	ToolStateAutoAdmitted = "auto_admitted"
	// ToolStateDraft — recorded, never reviewed, and therefore NOT SERVED.
	//
	// 🔴 It never arrives on the policy wire: the control plane withholds draft
	// tools rather than sending them with a flag, so a proxy that mishandled the
	// flag could not expose one. It is spelled here because Personal's local
	// producer (localpublish.go) needs the same word for the same state — the
	// alternative, a second name for one thing, is how a console and a CLI come
	// to disagree about what a user is looking at.
	ToolStateDraft = "draft"
)

// StatusDisabled marks a backend or toolset an admin switched off.
const StatusDisabled = "disabled"

// StatusActive is the other half of that vocabulary.
//
// 🔴 It did not exist here until P5, and the reason is worth keeping: until
// Personal edition, the proxy was only ever a CONSUMER of a policy — it needed
// to recognise "disabled" and treat everything else as usable, so "active" was
// never spelled. Local config made the proxy a PRODUCER too (localconfig.go),
// and a producer has to emit the exact value the consumer compares against.
// Writing the literal "active" at the producer would put the two halves of one
// enum in two files with nothing tying them together.
const StatusActive = "active"

// DiscoveryStatic marks a backend that was configured by hand rather than found
// in a service registry. Personal's local config is always static.
const DiscoveryStatic = "static"

// SubjectSeat / SubjectGroup mirror the grant vocabulary.
const (
	SubjectSeat  = "seat"
	SubjectGroup = "group"
)

// ---------------------------------------------------------------------------
// PolicyStore — the live snapshot
// ---------------------------------------------------------------------------

// PolicyStore holds the last policy the rail successfully pulled.
//
// 🔴 Keep-last-known, exactly like FallbackPolicyCache: losing contact with the
// control plane must NOT change behaviour. A failed poll leaves the snapshot
// untouched and /health/mcp reports its age; reverting to "no tools" on a
// network blip would disconnect every Agent in the fleet the moment a switch
// rebooted.
type PolicyStore struct {
	mu       sync.RWMutex
	policy   *Policy
	indexed  *policyIndex
	version  int64
	synced   bool
	lastOKAt atomic.Int64 // unix millis
	// reviewBacklogSince is when the "tools awaiting review" count last went
	// from zero to non-zero. 0 = the backlog is empty.
	//
	// 🔴 Stamped on the POLICY RAIL (every 60s), not when /health/mcp is read.
	// Deriving it from health reads would mean a backlog only ages while somebody
	// is watching — and the whole point of escalating it (task 7.7b) is to catch
	// the backlog nobody is watching.
	reviewBacklogSince atomic.Int64
	now                func() time.Time
}

// NewPolicyStore builds an empty store.
//
// 🔴 Empty is NOT the same as "pulled and empty". Until the first successful
// poll, Synced() is false, and /health/mcp says "never reached the control
// plane" rather than showing zero tools with no explanation. An operator
// staring at an empty tool list needs to know which of the two it is.
func NewPolicyStore() *PolicyStore {
	return &PolicyStore{now: time.Now}
}

// Store records a successfully pulled policy and rebuilds the lookup index.
func (s *PolicyStore) Store(p *Policy) {
	idx := buildPolicyIndex(p)
	s.mu.Lock()
	s.policy = p
	s.indexed = idx
	if p != nil {
		s.version = p.Version
	}
	s.synced = true
	s.mu.Unlock()
	s.lastOKAt.Store(s.now().UnixMilli())
	s.trackReviewBacklog(idx)
}

// trackReviewBacklog starts (or clears) the escalation clock.
//
// 🔴 The clock is NOT restarted while the backlog stays non-empty. If it were,
// an organisation that reviews one tool a day and gains two would keep resetting
// its own overdue timer and never escalate — which is the failure mode "never
// leave it at WARN" exists to prevent.
func (s *PolicyStore) trackReviewBacklog(idx *policyIndex) {
	if idx == nil || idx.needsReview == 0 {
		s.reviewBacklogSince.Store(0)
		return
	}
	s.reviewBacklogSince.CompareAndSwap(0, s.now().UnixMilli())
}

// ToolsNeedingReview is how many tools are waiting for a human right now.
//
// found=false before the first successful poll. 🔴 The distinction matters:
// "zero tools await review" and "we have not learned what awaits review" are
// opposite claims, and a release gate asserting on the first while receiving the
// second is asserting on nothing.
func (s *PolicyStore) ToolsNeedingReview() (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.indexed == nil || !s.synced {
		return 0, false
	}
	return s.indexed.needsReview, true
}

// ReviewBacklogAgeSeconds is how long the review backlog has been non-empty.
// -1 when it is empty.
func (s *PolicyStore) ReviewBacklogAgeSeconds() int64 {
	since := s.reviewBacklogSince.Load()
	if since == 0 {
		return -1
	}
	return (s.now().UnixMilli() - since) / 1000
}

// MarkNeverPolled resets the freshness clock without discarding the policy.
//
// 🔴 Used exactly once: after restoring the on-disk cache at boot. The restored
// policy is real and must be served, but it proves NOTHING about whether the
// control plane is reachable. Leaving the clock set would make /health/mcp
// report a healthy rail on a node that has never once reached the control
// plane — the precise false-green this endpoint exists to prevent.
func (s *PolicyStore) MarkNeverPolled() { s.lastOKAt.Store(0) }

// TouchSuccess records a poll that changed nothing (a 304).
//
// 🔴 Distinct from Store: a 304 proves the control plane is REACHABLE, so the
// freshness clock must advance even though no value moved. Without this, a fleet
// whose policy is simply stable would look increasingly stale and an operator
// would go hunting for a sync failure that is not happening.
func (s *PolicyStore) TouchSuccess() { s.lastOKAt.Store(s.now().UnixMilli()) }

// Version returns the delivery cursor of the snapshot in hand, for the
// conditional poll.
func (s *PolicyStore) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// Synced reports whether any poll has ever succeeded.
func (s *PolicyStore) Synced() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.synced
}

// AgeSeconds returns how long since the last successful poll, or -1 if there has
// never been one.
//
// 🔴 -1 rather than a large number: "never" and "very stale" are different
// facts, and a health endpoint that renders the first as the second sends an
// operator to debug a network that was never configured.
func (s *PolicyStore) AgeSeconds() int64 {
	last := s.lastOKAt.Load()
	if last == 0 {
		return -1
	}
	return (s.now().UnixMilli() - last) / 1000
}

// RawArgsRetention reports the org's raw-argument retention setting.
//
// 🔴 enabled=false before the first successful poll, and on any node with no
// policy at all. A node that has not heard from the control plane must not act
// on a switch it has never been told about — and the safe answer to "should I
// store the customer's SQL" is always no.
func (s *PolicyStore) RawArgsRetention() (enabled bool, days int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.policy == nil || !s.synced {
		return false, 0
	}
	if !s.policy.ArgsRawEnabled || s.policy.ArgsRawRetentionDays <= 0 {
		return false, 0
	}
	return true, s.policy.ArgsRawRetentionDays
}

// Snapshot returns the policy in hand. May be nil before the first poll.
func (s *PolicyStore) Snapshot() *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

// ---------------------------------------------------------------------------
// the index
// ---------------------------------------------------------------------------

// policyIndex is the read-optimised form of a Policy, rebuilt once per Store
// rather than per request.
//
// 🔴 Built eagerly on WRITE, not lazily on read. Policy changes ~once a day;
// tools/call happens continuously. Doing the work on the rare path keeps the hot
// path free of locks beyond one RLock — and, more importantly, keeps the grant
// check cheap enough that nobody is ever tempted to cache its RESULT onto a
// session, which is the thing R8 forbids.
type policyIndex struct {
	toolsetBySlug map[string]*PolicyToolset
	// grantedTo maps "kind\x00id" → set of toolset ids.
	grantedTo map[string]map[string]bool
	// backendByID answers "is this backend switched off".
	backendByID map[string]PolicyBackend
	// needsReview counts tools waiting for a human, computed once per snapshot.
	//
	// 🔴 Counted HERE rather than scanned on each /health/mcp read: health is
	// polled by monitoring, and a full scan of every toolset per poll is work
	// that grows with the customer's catalogue for a number that only changes
	// when the policy does.
	//
	// 🔴 It counts DISTINCT tool ids, not appearances. One tool may sit in three
	// toolsets; reporting "3 tools await review" when one does would send an
	// administrator looking for two reviews that do not exist.
	needsReview int
}

func buildPolicyIndex(p *Policy) *policyIndex {
	idx := &policyIndex{
		toolsetBySlug: map[string]*PolicyToolset{},
		grantedTo:     map[string]map[string]bool{},
		backendByID:   map[string]PolicyBackend{},
	}
	if p == nil {
		return idx
	}
	pending := map[string]bool{}
	for i := range p.Toolsets {
		ts := &p.Toolsets[i]
		idx.toolsetBySlug[NormalizeSlug(ts.Slug)] = ts
		for _, t := range ts.Tools {
			if t.State == ToolStateNeedsReview {
				pending[t.ID] = true
			}
		}
	}
	idx.needsReview = len(pending)
	for _, g := range p.Grants {
		key := g.SubjectKind + "\x00" + g.SubjectID
		if idx.grantedTo[key] == nil {
			idx.grantedTo[key] = map[string]bool{}
		}
		idx.grantedTo[key][g.VirtualServerID] = true
	}
	for _, b := range p.Backends {
		idx.backendByID[b.ID] = b
	}
	return idx
}

// ---------------------------------------------------------------------------
// PolicyCatalog — the shipping Catalog
// ---------------------------------------------------------------------------

// PolicyCatalog answers "what does this seat see" from the live snapshot.
//
// SeatGroups resolves a seat to the groups it belongs to. It may be nil, in
// which case only seat-level grants apply — which is the correct degradation:
// a missing group resolver must never GRANT anything, it can only fail to grant.
type PolicyCatalog struct {
	store      *PolicyStore
	seatGroups func(ctx context.Context, orgID, seatID string) []string
}

// NewPolicyCatalog builds the shipping catalog.
func NewPolicyCatalog(store *PolicyStore, seatGroups func(ctx context.Context, orgID, seatID string) []string) *PolicyCatalog {
	return &PolicyCatalog{store: store, seatGroups: seatGroups}
}

// Toolset implements Catalog.
//
// The returned view already has the freeze rule applied for THIS requester, so
// the handler does not need to know about tool states at all.
func (c *PolicyCatalog) Toolset(ctx context.Context, orgID, seatID, slug string) (ToolsetView, bool) {
	c.store.mu.RLock()
	idx := c.store.indexed
	c.store.mu.RUnlock()
	if idx == nil {
		return ToolsetView{}, false
	}

	ts, ok := idx.toolsetBySlug[NormalizeSlug(slug)]
	if !ok || ts.Status == StatusDisabled {
		// 🔴 A disabled toolset is reported as NOT FOUND to the client, on
		// purpose: an MCP client has no way to render "administratively
		// disabled", and inventing one would be a protocol extension. The human
		// answer lives in the console, which does distinguish them.
		return ToolsetView{}, false
	}
	if !c.isGranted(ctx, idx, orgID, seatID, ts.ID) {
		// 🔴 Same answer as "no such toolset". Telling an ungranted caller that
		// the toolset EXISTS is a tenancy leak that costs nothing to avoid.
		return ToolsetView{}, false
	}

	view := ToolsetView{Slug: ts.Slug, Title: ts.Title}
	for _, t := range ts.Tools {
		if b, known := idx.backendByID[t.BackendID]; known && b.Status == StatusDisabled {
			// The backend was switched off. Its tools cannot work, so listing
			// them would produce failures the developer cannot act on.
			continue
		}
		if !visibleInList(t) {
			continue
		}
		view.Tools = append(view.Tools, mcpwire.Tool{
			Name:        effectiveName(t),
			Title:       t.Title,
			Description: t.Description,
			InputSchema: []byte(orEmptySchema(t.InputSchema)),
		})
	}
	return view, true
}

// ToolsetID implements ToolsetIdentifier.
//
// 🔴 Identity-INDEPENDENT, like Slugs and unlike Toolset: it is called on a
// request that has ALREADY passed authorisation, purely to label the call
// record. Making it re-check the grant would duplicate the decision made
// microseconds earlier, and two copies of an authorisation rule is how they
// come to disagree.
func (c *PolicyCatalog) ToolsetID(_ context.Context, slug string) (string, bool) {
	c.store.mu.RLock()
	idx := c.store.indexed
	c.store.mu.RUnlock()
	if idx == nil {
		return "", false
	}
	ts, ok := idx.toolsetBySlug[NormalizeSlug(slug)]
	if !ok {
		return "", false
	}
	return ts.ID, true
}

// Slugs implements Catalog — an operational inventory for /health/mcp, not a
// permission answer, so it is identity-independent.
func (c *PolicyCatalog) Slugs(context.Context) []string {
	c.store.mu.RLock()
	idx := c.store.indexed
	c.store.mu.RUnlock()
	if idx == nil {
		return nil
	}
	out := make([]string, 0, len(idx.toolsetBySlug))
	for s := range idx.toolsetBySlug {
		out = append(out, s)
	}
	return out
}

// isGranted evaluates authorisation against the CURRENT snapshot.
//
// 🔴 Called on every request that needs it, never memoised per session. See the
// file header: a cached decision is how revocation stops working.
func (c *PolicyCatalog) isGranted(ctx context.Context, idx *policyIndex, orgID, seatID, toolsetID string) bool {
	if idx.grantedTo[SubjectSeat+"\x00"+seatID][toolsetID] {
		return true
	}
	if c.seatGroups == nil {
		return false
	}
	for _, group := range c.seatGroups(ctx, orgID, seatID) {
		if idx.grantedTo[SubjectGroup+"\x00"+group][toolsetID] {
			return true
		}
	}
	return false
}

// visibleInList applies the manifest-freeze rule (R3) at READ time.
//
// 🔴 The asymmetry is the whole design:
//
//	read-only + needs_review  → still listed, at its PUBLISHED version. The
//	                            version we serve is the one a human approved, so
//	                            serving it introduces no new risk, and hiding it
//	                            would make a routine upstream edit look like an
//	                            outage. Noise is not free: a detector that cries
//	                            wolf gets switched off.
//	write     + needs_review  → GONE from the list. The upstream changed and we
//	                            do not know into what. A write that turns out
//	                            wrong is not undoable.
//
// A name change is deliberately NOT handled here: the old name simply stops
// arriving from the upstream (a fact, not a verdict) and the new name arrives as
// a new tool in draft, which never reaches the proxy at all.
func visibleInList(t PolicyTool) bool {
	if t.State == ToolStateNeedsReview && t.WriteOp {
		return false
	}
	return true
}

// CallableState is why a tools/call was allowed or refused.
type CallableState int

const (
	// CallAllowed — the tool may execute.
	CallAllowed CallableState = iota
	// CallNotFound — no such tool in this toolset for this seat. Reported as
	// MCP_TOOL_FORBIDDEN so probing cannot enumerate tool names.
	CallNotFound
	// CallFrozen — a write tool whose upstream manifest drifted.
	CallFrozen
	// CallBackendDisabled — an admin switched the backend off.
	CallBackendDisabled
)

// ResolveCall decides whether a seat may call one tool right now, and returns
// the policy record if so.
//
// 🔴 This re-reads the snapshot and re-evaluates the grant. It does not consult
// anything the session remembers, and it must never learn to.
func (c *PolicyCatalog) ResolveCall(ctx context.Context, orgID, seatID, slug, toolName string) (PolicyTool, CallableState) {
	c.store.mu.RLock()
	idx := c.store.indexed
	c.store.mu.RUnlock()
	if idx == nil {
		return PolicyTool{}, CallNotFound
	}
	ts, ok := idx.toolsetBySlug[NormalizeSlug(slug)]
	if !ok || ts.Status == StatusDisabled {
		return PolicyTool{}, CallNotFound
	}
	if !c.isGranted(ctx, idx, orgID, seatID, ts.ID) {
		return PolicyTool{}, CallNotFound
	}
	for _, t := range ts.Tools {
		if effectiveName(t) != toolName {
			continue
		}
		if b, known := idx.backendByID[t.BackendID]; known && b.Status == StatusDisabled {
			return t, CallBackendDisabled
		}
		// 🔴 A frozen WRITE tool is refused at call time as well as hidden from
		// the list. Hiding alone is not enough: a client that listed the tool
		// before the freeze still holds its name, and would otherwise execute
		// against a schema we no longer trust.
		if t.State == ToolStateNeedsReview && t.WriteOp {
			return t, CallFrozen
		}
		return t, CallAllowed
	}
	return PolicyTool{}, CallNotFound
}

// effectiveName is the name a client sees: the toolset alias if one is set,
// otherwise the tool's own name.
func effectiveName(t PolicyTool) string {
	if t.Alias != "" {
		return t.Alias
	}
	return t.Name
}

// orEmptySchema guarantees a syntactically valid schema on the wire.
//
// An absent inputSchema makes some clients throw while parsing tools/list, which
// presents as "the server is broken" rather than "this tool declares no
// arguments".
func orEmptySchema(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}

// Backend implements BackendResolver.
//
// Reads the CURRENT snapshot, like every other lookup here: a backend that was
// disabled or re-pointed on the last poll must take effect on the next call,
// not on the next process restart.
func (c *PolicyCatalog) Backend(_ context.Context, backendID string) (PolicyBackend, bool) {
	c.store.mu.RLock()
	idx := c.store.indexed
	c.store.mu.RUnlock()
	if idx == nil {
		return PolicyBackend{}, false
	}
	b, ok := idx.backendByID[backendID]
	return b, ok
}
