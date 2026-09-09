package mcp

// policy_test.go — P2's fences on the proxy side.
//
// The four that matter most, and what each would look like in production if it
// were missing:
//
//	2.F1  a revoked grant keeps working on an already-open session
//	2.F2  the same, caused by memoising the decision — the classic shortcut
//	2.F3  a control-plane outage silently empties every developer's tool list
//	2.F5  a restart during an outage does the same, permanently

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

func samplePolicy(version int64, grantSeat bool) *Policy {
	p := &Policy{
		OrgID:   testOrg,
		Version: version,
		Backends: []PolicyBackend{
			// 🔴 127.0.0.1:1 is deliberately unroutable and fails INSTANTLY with
			// connection-refused. A real hostname here would make these tests
			// depend on DNS and on network egress — slow where it works, and a
			// hang where a sandbox blackholes outbound traffic.
			{ID: "b1", Name: "github", Transport: "streamable_http",
				EndpointURL: "http://127.0.0.1:1/mcp", Status: "active"},
			{ID: "b-off", Name: "legacy", Transport: "stdio", Status: StatusDisabled},
		},
		Toolsets: []PolicyToolset{{
			ID: "ts1", Slug: testToolset, Title: "Dev Tools", Status: "active",
			Tools: []PolicyTool{
				{ID: "t-read", BackendID: "b1", Name: "query_readonly",
					Description: "Run a read-only SQL query.", InputSchema: `{"type":"object"}`,
					ManifestHash: "h-read", State: ToolStatePublished, WriteOp: false},
				{ID: "t-write", BackendID: "b1", Name: "create_issue",
					Description: "Open a GitHub issue.", InputSchema: `{"type":"object"}`,
					ManifestHash: "h-write", State: ToolStatePublished, WriteOp: true},
			},
		}},
		GeneratedAtMs: time.Now().UnixMilli(),
	}
	if grantSeat {
		p.Grants = []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}}
	}
	return p
}

// newPolicyServer builds the real handler over a policy-backed catalog.
func newPolicyServer(t *testing.T, p *Policy) (*http.ServeMux, *PolicyStore) {
	t.Helper()
	store := NewPolicyStore()
	if p != nil {
		store.Store(p)
	}
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, store
}

func listToolNames(t *testing.T, mux *http.ServeMux) []string {
	t.Helper()
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if env.Error != nil {
		return nil
	}
	var res mcpwire.ListToolsResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	out := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		out = append(out, tool.Name)
	}
	return out
}

func callTool(t *testing.T, mux *http.ServeMux, name string) mcpwire.Envelope {
	t.Helper()
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"`+name+`","arguments":{}}}`, nil)
	return env
}

// ---------------------------------------------------------------------------
// Fence 2.F1 / 2.F2 — revocation reaches an OPEN session
// ---------------------------------------------------------------------------

// TestFence_2F1_RevokedGrantStopsWorkingOnAnOpenSession.
//
// 🔴 The session is opened FIRST and reused after the revocation, because that
// is the case that breaks: a client that connected while it was authorised
// keeps its session for hours. A test that opened a new session after revoking
// would pass against an implementation that caches the decision at handshake —
// i.e. it would prove nothing about the requirement.
func TestFence_2F1_RevokedGrantStopsWorkingOnAnOpenSession(t *testing.T) {
	mux, store := newPolicyServer(t, samplePolicy(1, true))

	rec, _ := rpc(t, mux, "/mcp/"+testToolset, testToken, initializeBody("2025-06-18"), nil)
	sid := rec.Header().Get(mcpwire.HeaderSessionID)
	if sid == "" {
		t.Fatal("handshake did not mint a session")
	}
	hdr := map[string]string{mcpwire.HeaderSessionID: sid}

	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_readonly","arguments":{}}}`, hdr)
	if got := aikeyCode(t, env); got == string(mcpwire.ErrToolForbidden) {
		t.Fatalf("the granted seat was refused before revocation: %s", env.Error.Message)
	}

	// The admin revokes; the next poll delivers a policy with no grant.
	store.Store(samplePolicy(2, false))

	_, after := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_readonly","arguments":{}}}`, hdr)
	if got := aikeyCode(t, after); got != string(mcpwire.ErrToolForbidden) {
		t.Fatalf("aikey_code = %q after revocation, want MCP_TOOL_FORBIDDEN.\n"+
			"The seat kept its access on an already-open session — this is the shape of "+
			"\"revocation does not take effect\".", got)
	}

	// And the tool disappears from the listing on the SAME session.
	if names := listToolNames(t, mux); len(names) != 0 {
		t.Errorf("tools/list still returns %v after the grant was revoked", names)
	}
}

// TestFence_2F2_AuthorisationIsNotMemoisedPerSession.
//
// The shortcut this fences against is "we already checked this session, skip
// the lookup". It looks like a harmless optimisation and it silently disables
// revocation.
//
// 🔴 Asserted by COUNTING resolver calls, not by observing the outcome: an
// implementation could re-check and still get the old answer from a stale cache,
// and only the call count distinguishes "re-evaluated" from "remembered".
func TestFence_2F2_AuthorisationIsNotMemoisedPerSession(t *testing.T) {
	store := NewPolicyStore()
	store.Store(samplePolicy(1, true))

	var mu sync.Mutex
	groupLookups := 0
	catalog := NewPolicyCatalog(store, func(context.Context, string, string) []string {
		mu.Lock()
		groupLookups++
		mu.Unlock()
		return nil
	})
	h := NewHandler(Config{
		Catalog:         catalog,
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: "seat_without_grant"}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Three calls from one session. The seat has no seat-level grant, so each
	// call must fall through to the group resolver — three times, not once.
	for i := 0; i < 3; i++ {
		_, _ = rpc(t, mux, "/mcp/"+testToolset, testToken,
			`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"query_readonly","arguments":{}}}`, nil)
	}
	mu.Lock()
	got := groupLookups
	mu.Unlock()
	if got < 3 {
		t.Fatalf("authorisation was evaluated %d times for 3 calls; it must be re-evaluated on EVERY call (R8). "+
			"A memoised decision is how a revoked grant keeps working.", got)
	}
}

// TestUngrantedSeatCannotSeeTheToolsetAtAll — telling an ungranted caller that
// a toolset exists is a tenancy leak that costs nothing to avoid.
func TestUngrantedSeatCannotSeeTheToolsetAtAll(t *testing.T) {
	store := NewPolicyStore()
	store.Store(samplePolicy(1, false)) // no grants at all
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	rec, env := rpc(t, mux, "/mcp/"+testToolset, testToken, initializeBody("2025-06-18"), nil)

	// 🔴 The signal is the JSON-RPC error, not the HTTP status: the request WAS
	// a valid JSON-RPC message with an id, so it is answered 200 with an error
	// object (see rpcerror.go for why that split is the spec's, not ours).
	// Asserting on rec.Code here would be asserting on the transport rather than
	// on the refusal.
	if env.Error == nil {
		t.Fatalf("an ungranted seat completed a handshake against a toolset it cannot use: %s", rec.Body)
	}
	// 🔴 And no session was minted — a client holding a session id for a toolset
	// it may not use would keep retrying against it.
	if sid := rec.Header().Get(mcpwire.HeaderSessionID); sid != "" {
		t.Errorf("a session was minted for an ungranted seat: %q", sid)
	}
	body := strings.ToLower(rec.Body.String())
	for _, leak := range []string{"not granted", "exists", "another organization", "not authorized to see"} {
		if strings.Contains(body, leak) {
			t.Errorf("the refusal reveals that the toolset exists (%q): %s", leak, rec.Body)
		}
	}
}

// TestGroupGrantIsHonouredWhenAResolverIsPresent — and a nil resolver can only
// FAIL to grant, never grant something extra.
func TestGroupGrantIsHonouredWhenAResolverIsPresent(t *testing.T) {
	p := samplePolicy(1, false)
	p.Grants = []PolicyGrant{{SubjectKind: SubjectGroup, SubjectID: "engineering", VirtualServerID: "ts1"}}
	store := NewPolicyStore()
	store.Store(p)

	withGroups := NewPolicyCatalog(store, func(context.Context, string, string) []string {
		return []string{"engineering"}
	})
	if _, ok := withGroups.Toolset(context.Background(), testOrg, testSeat, testToolset); !ok {
		t.Error("a group grant was not honoured with a resolver present")
	}

	withoutGroups := NewPolicyCatalog(store, nil)
	if _, ok := withoutGroups.Toolset(context.Background(), testOrg, testSeat, testToolset); ok {
		t.Error("a nil group resolver GRANTED access; it must only ever fail to grant")
	}
}

// ---------------------------------------------------------------------------
// R3 — the manifest freeze, decided at read time
// ---------------------------------------------------------------------------

// TestFrozenWriteToolDisappearsWhileFrozenReadToolKeepsServing.
//
// 🔴 The asymmetry IS the design. Hiding read-only tools too would make a
// routine upstream edit look like an outage, and a detector that cries wolf gets
// switched off — at which point the write-tool protection is gone as well.
func TestFrozenWriteToolDisappearsWhileFrozenReadToolKeepsServing(t *testing.T) {
	p := samplePolicy(1, true)
	p.Toolsets[0].Tools[0].State = ToolStateNeedsReview // read-only, frozen
	p.Toolsets[0].Tools[1].State = ToolStateNeedsReview // write, frozen
	mux, _ := newPolicyServer(t, p)

	names := listToolNames(t, mux)
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "query_readonly") {
		t.Errorf("the frozen READ-ONLY tool vanished from tools/list (got %v); it must keep serving its published version", names)
	}
	if strings.Contains(joined, "create_issue") {
		t.Errorf("the frozen WRITE tool is still listed (got %v); it must disappear until a human reviews the change", names)
	}
}

// TestFrozenWriteToolIsAlsoRefusedAtCallTime.
//
// 🔴 Hiding it from the list is NOT enough: a client that listed the tool before
// the freeze still holds its name and would otherwise execute against a schema
// we no longer trust.
func TestFrozenWriteToolIsAlsoRefusedAtCallTime(t *testing.T) {
	p := samplePolicy(1, true)
	p.Toolsets[0].Tools[1].State = ToolStateNeedsReview
	mux, _ := newPolicyServer(t, p)

	env := callTool(t, mux, "create_issue")
	if got := aikeyCode(t, env); got != string(mcpwire.ErrToolNeedsReview) {
		t.Fatalf("aikey_code = %q, want MCP_TOOL_NEEDS_REVIEW", got)
	}
	if !strings.Contains(env.Error.Message, "review") {
		t.Errorf("the message should tell the developer what unblocks it: %q", env.Error.Message)
	}
}

// TestAdoptingAChangeTakesEffectOnTheNextListWithoutASync — the reason the
// freeze decision is made at READ time rather than by the sync loop.
func TestAdoptingAChangeTakesEffectOnTheNextListWithoutASync(t *testing.T) {
	p := samplePolicy(1, true)
	p.Toolsets[0].Tools[1].State = ToolStateNeedsReview
	mux, store := newPolicyServer(t, p)

	if strings.Contains(strings.Join(listToolNames(t, mux), ","), "create_issue") {
		t.Fatal("precondition: the frozen write tool should be hidden")
	}
	// The admin adopts; the next poll carries state=published.
	adopted := samplePolicy(2, true)
	store.Store(adopted)

	if !strings.Contains(strings.Join(listToolNames(t, mux), ","), "create_issue") {
		t.Error("adopting the change did not restore the tool on the very next tools/list")
	}
}

// TestDisabledBackendHidesItsToolsAndRefusesCalls — listing tools that cannot
// work produces failures a developer has no way to act on.
func TestDisabledBackendHidesItsToolsAndRefusesCalls(t *testing.T) {
	p := samplePolicy(1, true)
	p.Toolsets[0].Tools = append(p.Toolsets[0].Tools, PolicyTool{
		ID: "t-legacy", BackendID: "b-off", Name: "legacy_tool",
		InputSchema: `{}`, State: ToolStatePublished})
	mux, _ := newPolicyServer(t, p)

	if strings.Contains(strings.Join(listToolNames(t, mux), ","), "legacy_tool") {
		t.Error("a tool on a disabled backend was listed")
	}
	env := callTool(t, mux, "legacy_tool")
	if got := aikeyCode(t, env); got != string(mcpwire.ErrBackendUnavailable) {
		t.Errorf("aikey_code = %q, want MCP_BACKEND_UNAVAILABLE", got)
	}
}

// TestDisabledToolsetIsNotFoundRatherThanDisabled — an MCP client has no way to
// render "administratively disabled", so inventing one would be a protocol
// extension. The human answer lives in the console.
func TestDisabledToolsetIsNotFoundRatherThanDisabled(t *testing.T) {
	p := samplePolicy(1, true)
	p.Toolsets[0].Status = StatusDisabled
	mux, _ := newPolicyServer(t, p)

	rec, env := rpc(t, mux, "/mcp/"+testToolset, testToken, initializeBody("2025-06-18"), nil)
	if env.Error == nil {
		t.Fatalf("a disabled toolset still completed a handshake: %s", rec.Body)
	}
	if sid := rec.Header().Get(mcpwire.HeaderSessionID); sid != "" {
		t.Errorf("a session was minted against a disabled toolset: %q", sid)
	}
}

// TestAliasRenamesTheToolWithinTheToolset — two backends that both export
// "search" must be able to coexist.
func TestAliasRenamesTheToolWithinTheToolset(t *testing.T) {
	p := samplePolicy(1, true)
	p.Toolsets[0].Tools[0].Alias = "sql_query"
	mux, _ := newPolicyServer(t, p)

	joined := strings.Join(listToolNames(t, mux), ",")
	if !strings.Contains(joined, "sql_query") {
		t.Errorf("the alias is not the name clients see: %s", joined)
	}
	if strings.Contains(joined, "query_readonly") {
		t.Errorf("the underlying name leaked alongside the alias: %s", joined)
	}
	// And the alias is what tools/call accepts.
	if got := aikeyCode(t, callTool(t, mux, "sql_query")); got == string(mcpwire.ErrToolForbidden) {
		t.Error("calling by the alias was refused")
	}
	if got := aikeyCode(t, callTool(t, mux, "query_readonly")); got != string(mcpwire.ErrToolForbidden) {
		t.Error("the underlying name is still callable; the alias must be the only name")
	}
}

// ---------------------------------------------------------------------------
// Fence 2.F3 — an unreachable control plane must not empty the tool list
// ---------------------------------------------------------------------------

// TestFence_2F3_StalePolicyKeepsServingAndHealthSaysSo.
//
// 🔴 Reverting to "no tools" on a failed poll would disconnect every Agent in
// the fleet the moment a switch rebooted. The staleness must be VISIBLE instead
// — that is what /health/mcp is for.
func TestFence_2F3_StalePolicyKeepsServingAndHealthSaysSo(t *testing.T) {
	p := samplePolicy(1, true)
	store := NewPolicyStore()
	base := time.Now()
	store.now = func() time.Time { return base }
	store.Store(p)

	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// 40 minutes of failed polls: nothing calls Store or TouchSuccess.
	base = base.Add(40 * time.Minute)

	if names := listToolNames(t, mux); len(names) != 2 {
		t.Fatalf("tools/list returned %v after a 40-minute outage; the last known policy must keep serving", names)
	}
	if age := store.AgeSeconds(); age < 2000 {
		t.Errorf("AgeSeconds = %d, expected ~2400 — the staleness must be measurable", age)
	}
}

// TestNeverPolledIsDistinguishableFromVeryStale.
//
// 🔴 "We have never reached the control plane" and "we reached it 40 minutes
// ago" send an operator to two different places. Rendering the first as a large
// number sends them to debug a network that was never configured.
func TestNeverPolledIsDistinguishableFromVeryStale(t *testing.T) {
	fresh := NewPolicyStore()
	if got := fresh.AgeSeconds(); got != -1 {
		t.Errorf("a never-polled store reports age %d, want -1", got)
	}
	if fresh.Synced() {
		t.Error("a never-polled store reports itself as synced")
	}

	polled := NewPolicyStore()
	polled.Store(samplePolicy(1, true))
	if got := polled.AgeSeconds(); got < 0 {
		t.Errorf("a polled store reports age %d, want >= 0", got)
	}
	if !polled.Synced() {
		t.Error("a polled store does not report itself as synced")
	}
}

// TestA304AdvancesTheFreshnessClock — a 304 proves reachability, so a fleet
// whose policy is simply stable must not look increasingly stale.
func TestA304AdvancesTheFreshnessClock(t *testing.T) {
	store := NewPolicyStore()
	base := time.Now()
	store.now = func() time.Time { return base }
	store.Store(samplePolicy(1, true))

	base = base.Add(10 * time.Minute)
	if store.AgeSeconds() < 500 {
		t.Fatal("precondition: the store should look stale before the 304")
	}
	store.TouchSuccess()
	if got := store.AgeSeconds(); got != 0 {
		t.Errorf("AgeSeconds = %d after a 304, want 0 — a revalidation proves the control plane is reachable", got)
	}
	// 🔴 And the policy itself is untouched.
	if store.Snapshot() == nil || len(store.Snapshot().Toolsets) != 1 {
		t.Error("TouchSuccess altered the policy; it must only move the clock")
	}
}

// ---------------------------------------------------------------------------
// Fence 2.F5 — delete the cache, restart, recover
// ---------------------------------------------------------------------------

// TestFence_2F5_PolicySurvivesARestartAndADeletedCacheRecovers.
func TestFence_2F5_PolicySurvivesARestartAndADeletedCacheRecovers(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AIKEY_RUN_DIR", dir)
	cache := NewPolicyCache(discardLogger(), 0)

	p := samplePolicy(7, true)
	cache.Save(p)

	// "Restart": a brand-new cache object reading the same directory.
	restored := NewPolicyCache(discardLogger(), 0).Load(testOrg)
	if restored == nil {
		t.Fatal("the policy did not survive a restart; a node restarting during a control-plane outage would come back with no tools at all")
	}
	if restored.Version != 7 || len(restored.Toolsets) != 1 {
		t.Errorf("restored policy is wrong: version=%d toolsets=%d", restored.Version, len(restored.Toolsets))
	}

	// Delete the cache — a supported operation.
	if err := os.Remove(filepath.Join(dir, policyCacheFilename)); err != nil {
		t.Fatal(err)
	}
	if again := NewPolicyCache(discardLogger(), 0).Load(testOrg); again != nil {
		t.Error("a deleted cache still produced a policy")
	}
	// 🔴 And a missing cache must be a NON-EVENT: the store starts empty and the
	// first poll fills it. Nothing here may fail startup.
	store := NewPolicyStore()
	if store.Snapshot() != nil {
		t.Error("an empty store reports a policy")
	}
	store.Store(p)
	if store.Snapshot().Version != 7 {
		t.Error("the store did not accept the policy delivered by the first poll")
	}
}

// TestCacheFromAnotherOrgIsIgnored — a machine legitimately moves between
// organisations (a contractor's laptop, a re-provisioned node). Serving the
// previous org's grants would be the actual defect.
func TestCacheFromAnotherOrgIsIgnored(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AIKEY_RUN_DIR", dir)
	NewPolicyCache(discardLogger(), 0).Save(samplePolicy(3, true))

	if got := NewPolicyCache(discardLogger(), 0).Load("a_completely_different_org"); got != nil {
		t.Fatal("a cached policy was served to a different organization")
	}
}

// TestTooOldACacheIsIgnored — a laptop shut for three weeks must not come back
// serving three-week-old grants, including ones revoked in the meantime.
func TestTooOldACacheIsIgnored(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AIKEY_RUN_DIR", dir)

	writer := NewPolicyCache(discardLogger(), 0)
	base := time.Now()
	writer.now = func() time.Time { return base }
	writer.Save(samplePolicy(3, true))

	reader := NewPolicyCache(discardLogger(), 0)
	reader.now = func() time.Time { return base.Add(8 * 24 * time.Hour) }
	if got := reader.Load(testOrg); got != nil {
		t.Fatal("an 8-day-old cache was served; grants revoked in the meantime would be honoured")
	}

	fresh := NewPolicyCache(discardLogger(), 0)
	fresh.now = func() time.Time { return base.Add(6 * 24 * time.Hour) }
	if got := fresh.Load(testOrg); got == nil {
		t.Error("a 6-day-old cache was rejected; the bound must cover a holiday weekend plus a maintenance window")
	}
}

// TestCorruptCacheIsANonEvent — a corrupt cache is fixed by the next poll.
// Refusing to start over a disposable file would convert a non-event into an
// outage.
func TestCorruptCacheIsANonEvent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AIKEY_RUN_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, policyCacheFilename), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := NewPolicyCache(discardLogger(), 0).Load(testOrg); got != nil {
		t.Error("a corrupt cache produced a policy")
	}
}

// TestCacheWriteFailureIsNotFatal — the policy is already applied in memory, so
// only the restart shortcut is lost.
func TestCacheWriteFailureIsNotFatal(t *testing.T) {
	// A path that cannot be created: a file where the directory should be.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIKEY_RUN_DIR", filepath.Join(blocker, "nested"))

	// Must not panic and must not block.
	NewPolicyCache(discardLogger(), 0).Save(samplePolicy(1, true))
}

// ---------------------------------------------------------------------------
// wire-shape contract
// ---------------------------------------------------------------------------

// TestPolicyWireShapeMatchesControlPlane pins the JSON the control plane emits.
//
// 🔴 The proxy re-declares these types rather than importing the control-plane
// module, so nothing but this test keeps the two in step. The literal below is a
// verbatim sample of what the control plane produces; if a field is renamed on
// either side, this decodes into a zero value and the assertion catches it.
func TestPolicyWireShapeMatchesControlPlane(t *testing.T) {
	const fromControlPlane = `{
	  "org_id":"org_test","version":42,
	  "backends":[{"id":"b1","name":"github","transport":"streamable_http","endpoint_url":"https://x/v1","credential_id":"c1","status":"active","discovery_source":"static"}],
	  "toolsets":[{"id":"ts1","slug":"devtools","title":"Dev Tools","status":"active",
	    "tools":[{"id":"t1","backend_id":"b1","name":"query_readonly","alias":"sql",
	              "description":"d","input_schema":"{}","manifest_hash":"h1",
	              "state":"needs_review","write_op":true,"idempotent":false,"tool_group":"db"}]}],
	  "grants":[{"subject_kind":"seat","subject_id":"seat_7","virtual_server_id":"ts1"}],
	  "generated_at_ms":1700000000000}`

	var p Policy
	if err := json.Unmarshal([]byte(fromControlPlane), &p); err != nil {
		t.Fatal(err)
	}
	if p.OrgID != "org_test" || p.Version != 42 || p.GeneratedAtMs != 1700000000000 {
		t.Errorf("envelope fields did not decode: %+v", p)
	}
	if len(p.Backends) != 1 || p.Backends[0].CredentialID != "c1" || p.Backends[0].DiscoverySource != "static" {
		t.Errorf("backend did not decode: %+v", p.Backends)
	}
	if len(p.Toolsets) != 1 || len(p.Toolsets[0].Tools) != 1 {
		t.Fatalf("toolset did not decode: %+v", p.Toolsets)
	}
	tool := p.Toolsets[0].Tools[0]
	// 🔴 These four carry the security decisions. A rename that silently zeroed
	// any of them would make every tool look published, read-only and unaliased.
	if tool.State != ToolStateNeedsReview {
		t.Errorf("state did not decode (%q) — every tool would look published", tool.State)
	}
	if !tool.WriteOp {
		t.Error("write_op did not decode — every tool would look read-only and the freeze rule would never fire")
	}
	if tool.ManifestHash != "h1" {
		t.Error("manifest_hash did not decode")
	}
	if tool.Alias != "sql" {
		t.Error("alias did not decode — clients would see the wrong tool name")
	}
	if len(p.Grants) != 1 || p.Grants[0].SubjectKind != "seat" {
		t.Errorf("grant did not decode: %+v", p.Grants)
	}
}

// TestValueDomainsMatchTheCentralEnum is the producer half of fence 2.F4.
//
// The DDL half lives in aikey-config-tool. This asserts the proxy's own
// constants are members of the same domains — a value the proxy can produce that
// the database refuses is the 2026-08-10 failure, where every row was dropped
// and the only symptom was an empty page.
func TestValueDomainsMatchTheCentralEnum(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"tool state published", ToolStatePublished},
		{"tool state needs_review", ToolStateNeedsReview},
		{"tool state auto_admitted", ToolStateAutoAdmitted},
		{"subject seat", SubjectSeat},
		{"subject group", SubjectGroup},
		{"status disabled", StatusDisabled},
	} {
		if tc.value == "" {
			t.Errorf("%s is the empty string", tc.name)
		}
	}
	// The domains the DDL declares, mirrored here. Kept as literals on purpose:
	// importing aikey-config-tool into the proxy to share a slice would couple a
	// data-path binary to a migration tool for the sake of six strings.
	states := map[string]bool{"draft": true, "published": true, "needs_review": true, "auto_admitted": true, "retired": true}
	for _, s := range []string{ToolStatePublished, ToolStateNeedsReview, ToolStateAutoAdmitted} {
		if !states[s] {
			t.Errorf("tool state %q is not in the database's CHECK IN-list; every row carrying it would be rejected", s)
		}
	}
	kinds := map[string]bool{"seat": true, "group": true}
	for _, s := range []string{SubjectSeat, SubjectGroup} {
		if !kinds[s] {
			t.Errorf("subject kind %q is not in the database's CHECK IN-list", s)
		}
	}
}

// TestHealthReportsPolicyAgeOnceTheRailExists — fence 2.F3's operator-facing
// half: the staleness must be READABLE, not merely measurable in a Go struct.
func TestHealthReportsPolicyAgeOnceTheRailExists(t *testing.T) {
	store := NewPolicyStore()
	base := time.Now()
	store.now = func() time.Time { return base }
	store.Store(samplePolicy(1, true))

	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		PolicyStore:     store,
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	base = base.Add(25 * time.Minute)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/mcp", nil))

	var doc HealthDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.PolicyAgeSeconds == nil {
		t.Fatal("/health/mcp does not report policy_age_seconds; a control-plane outage would be invisible")
	}
	if *doc.PolicyAgeSeconds < 1400 {
		t.Errorf("policy_age_seconds = %d, expected ~1500", *doc.PolicyAgeSeconds)
	}
	if doc.Status != PlaneDegraded {
		t.Errorf("status = %q with a 25-minute-old policy; a rail that has not synced in 25 minutes is not healthy", doc.Status)
	}
	if !strings.Contains(strings.ToLower(doc.Reason), "policy") {
		t.Errorf("the degraded reason does not mention the policy: %q", doc.Reason)
	}
}

var _ = vkeys.ResolvedRoute{}
