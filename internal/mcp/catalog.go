package mcp

// catalog.go — where the plane gets its toolsets from.
//
// # Why an interface and not a direct read of the policy cache
//
// P1's job is to make a real MCP client connect, handshake and list tools. P2
// replaces the source of those tools with the control-plane-driven policy
// snapshot, and P3 adds the manifest-freeze rules on top. Those are three
// different owners landing in three different weeks.
//
// A seam here means P2 swaps ONE implementation instead of editing the HTTP
// handlers, the session code and the negotiator. It also means the handler
// tests do not need a control plane to run — they exercise the real handler
// against a fixed catalog, rather than a simplified re-implementation of it,
// which is the project rule for tests (call the real user-facing code path).
//
// 🚫 This interface must NOT grow an "is this seat allowed" method. Grant
// evaluation is a separate decision made on EVERY tools/call (R8) and belongs
// with the policy snapshot, not with the thing that knows what tools exist.
// Merging them is how a listing cache turns into an authorisation cache.

import (
	"context"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// ToolsetView is one toolset as the plane needs to serve it.
type ToolsetView struct {
	// Slug is the public path segment: /mcp/<slug>.
	Slug string
	// Title is display copy for the console and for MCP `serverInfo`.
	Title string
	// Tools are the PUBLISHED tools, already filtered for this reader.
	//
	// 🔴 "already filtered" is doing real work here from P3 onward: a write
	// tool whose upstream manifest has drifted must NOT appear in this slice,
	// while a read-only tool in the same state must appear at its OLD version
	// (R3). That decision is made at READ time by the catalog implementation,
	// 🚫 not by the sync loop — so that adopting a change restores the tool on
	// the very next tools/list without re-running any sync.
	Tools []mcpwire.Tool
}

// Catalog answers "what does this seat see at /mcp/<slug>".
//
// Implementations must be safe for concurrent use.
type Catalog interface {
	// Toolset returns the view for slug as seen by (orgID, seatID).
	//
	// found=false means the slug does not exist FOR THIS READER. Callers turn
	// that into a 404.
	//
	// 🔴 Deliberately not distinguishing "no such toolset" from "exists but you
	// cannot see it": the second answer tells an unauthenticated-for-this-org
	// caller that a toolset with that name exists elsewhere, which is a tenancy
	// leak that costs nothing to avoid.
	Toolset(ctx context.Context, orgID, seatID, slug string) (view ToolsetView, found bool)

	// Slugs lists the toolset slugs this node can currently serve, for
	// GET /health/mcp. Identity-independent: it is an operational inventory,
	// not a permission answer.
	Slugs(ctx context.Context) []string
}

// StaticCatalog is a fixed, in-memory Catalog.
//
// 🔴 What it is FOR: P1 acceptance (a real MCP client connects and lists
// tools), and as the fixture backing the handler tests so those tests drive the
// real handler rather than a stand-in.
//
// 🔴 What it is NOT: a shipping default. app wiring must supply the
// policy-backed catalog once P2 lands; a node that serves StaticCatalog in
// production would be advertising tools nobody granted. The wiring asserts this
// (see the mcpEnabled guard in app.go) so the failure is a startup refusal, not
// a silent wrong answer.
type StaticCatalog struct {
	// Toolsets keyed by slug. Read-only after construction.
	Toolsets map[string]ToolsetView
}

// Toolset implements Catalog.
//
// A static catalog has no notion of org or seat — every reader sees the same
// thing. That is exactly why it may not ship: the parameters are accepted and
// ignored, which is safe for a fixture and unsafe for a tenant.
func (c *StaticCatalog) Toolset(_ context.Context, _, _, slug string) (ToolsetView, bool) {
	v, ok := c.Toolsets[slug]
	return v, ok
}

// Slugs implements Catalog.
func (c *StaticCatalog) Slugs(context.Context) []string {
	out := make([]string, 0, len(c.Toolsets))
	for s := range c.Toolsets {
		out = append(out, s)
	}
	return out
}

// CallResolver is the authorisation half of a Catalog.
//
// 🔴 A SEPARATE interface from Catalog on purpose. Catalog answers "what exists
// for this reader"; CallResolver answers "may this reader run this, right now".
// Merging them would let a listing cache quietly become an authorisation cache,
// which is precisely what R8 forbids — and the seam makes the failure mode
// explicit: a catalog that does not implement this cannot authorise anything,
// so the handler refuses every call rather than defaulting to allow.
type CallResolver interface {
	// ResolveCall re-evaluates the grant against the CURRENT policy and returns
	// the tool record plus why it was allowed or refused.
	//
	// 🚫 Implementations must not memoise the answer per session. The decision
	// is per-call by requirement, not by convention.
	ResolveCall(ctx context.Context, orgID, seatID, slug, toolName string) (PolicyTool, CallableState)
}

// BackendResolver looks up the backend record behind a tool.
//
// 🔴 Separate from Catalog and CallResolver, and for the same reason those two
// are separate from each other: this one answers "where does this go", which is
// a routing question, not a permission question. Keeping it apart means a
// change to routing cannot accidentally widen authorisation.
type BackendResolver interface {
	// Backend returns the backend record, or found=false when the policy has no
	// such backend.
	Backend(ctx context.Context, backendID string) (PolicyBackend, bool)
}

// ToolsetIdentifier maps a public slug to the virtual server's id.
//
// 🔴 Deliberately its OWN optional interface rather than a field added to
// ToolsetView. ToolsetView is the AUTHORISED view handed to a requester; the
// virtual-server id is internal bookkeeping that a call record needs and a
// client must never see. Widening the view to carry it would put an internal
// identifier one JSON tag away from a response body.
//
// A catalog that does not implement this yields an empty id and the record's
// virtual_server_id column stays empty — the same fail-quiet direction the
// other optional resolvers take, and a missing id can only make a report less
// specific, never wrong.
type ToolsetIdentifier interface {
	ToolsetID(ctx context.Context, slug string) (string, bool)
}
