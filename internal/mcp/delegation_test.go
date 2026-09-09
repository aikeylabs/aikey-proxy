package mcp

// delegation_test.go — fences for the delegation evaluator (checklist §D
// D-79/D-84/D-85/D-86/D-90/D-92, tasks 15.F1/15.F6/15.F7/15.F11/15.F14).

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

func intp(v int) *int { return &v }

func parentSet() []string { return []string{"reports", "prod-db", "jira"} }

// ---------------------------------------------------------------------------
// D-79 / I30 / R60 — child ⊆ parent ⊆ seat, always
// ---------------------------------------------------------------------------

// Mutation: replace the intersection with the tier's own list (i.e. let a tier
// GRANT a toolset instead of only filtering one).
// Rationale: a tier that can widen is a second authorisation source, and the
// seat grant stops being the outer bound of the chain.
func TestChildIsAlwaysASubsetOfParent(t *testing.T) {
	pol := mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{{
		Name:       "read-only",
		AgentTypes: []string{"Explore"},
		// 🔴 "billing" is deliberately NOT in the parent's set. A tier naming a
		// toolset the parent does not hold must not conjure it.
		ToolsetSlugs: []string{"reports", "billing"},
	}}}
	d := EvaluateDelegation(pol, parentSet(), DelegationRequest{AgentType: "Explore", Depth: 1})

	parent := map[string]bool{}
	for _, s := range parentSet() {
		parent[s] = true
	}
	for _, s := range d.Toolsets {
		if !parent[s] {
			t.Fatalf("child got toolset %q which the parent does not hold; "+
				"a delegation tier may only REDUCE (R60/I30)", s)
		}
	}
	if len(d.Toolsets) != 1 || d.Toolsets[0] != "reports" {
		t.Fatalf("toolsets = %v; want exactly the intersection [reports]", d.Toolsets)
	}
	if d.Verdict != mcpwire.VerdictNarrow {
		t.Fatalf("verdict = %q; a strict subset of the parent's set is a narrow", d.Verdict)
	}
}

// A tier that matches the parent's set exactly is an ALLOW, not a narrow —
// otherwise every delegation in a correctly-configured org reads as downgraded
// and the narrow signal becomes noise.
func TestEqualSetIsAllowNotNarrow(t *testing.T) {
	pol := mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{{
		Name: "full", AgentTypes: []string{"*"}, ToolsetSlugs: parentSet(),
	}}}
	d := EvaluateDelegation(pol, parentSet(), DelegationRequest{AgentType: "Explore", Depth: 1})
	if d.Verdict != mcpwire.VerdictAllow {
		t.Fatalf("verdict = %q; want allow when nothing was removed", d.Verdict)
	}
}

// ---------------------------------------------------------------------------
// D-90 / D-27 — the zero value must behave exactly like today
// ---------------------------------------------------------------------------

// Mutation: delete the len(pol.Tiers)==0 pass-through, or flip DefaultAllow's
// zero value's meaning.
// Rationale: DelegationPolicy's zero value has DefaultAllow=false. An older
// control plane that does not send the field yet, or an org that has configured
// nothing, must not have every sub-agent in the fleet refused the moment a
// proxy upgrades. Governance ships by making today VISIBLE, not by changing it.
func TestZeroPolicyAllowsEverything(t *testing.T) {
	d := EvaluateDelegation(mcpwire.DelegationPolicy{}, parentSet(),
		DelegationRequest{AgentType: "general-purpose", Depth: 1})
	if d.Verdict != mcpwire.VerdictAllow {
		t.Fatalf("verdict = %q on an unconfigured org; upgrade day must change "+
			"nothing (D-27)", d.Verdict)
	}
	if len(d.Toolsets) != len(parentSet()) {
		t.Fatalf("toolsets = %v; an unconfigured org narrows nothing", d.Toolsets)
	}
}

// The other half: once an org HAS tiers, "none matched" is a real opinion and
// DefaultAllow decides it. Not configured and configured-to-refuse are
// different facts and must not share a code path.
func TestConfiguredButUnmatchedConsultsDefaultAllow(t *testing.T) {
	tiers := []mcpwire.DelegationTier{{Name: "ro", AgentTypes: []string{"Explore"}}}

	closed := EvaluateDelegation(mcpwire.DelegationPolicy{Tiers: tiers, DefaultAllow: false},
		parentSet(), DelegationRequest{AgentType: "general-purpose", Depth: 1})
	if closed.Verdict != mcpwire.VerdictDeny {
		t.Fatalf("verdict = %q; a configured org with DefaultAllow=false refuses "+
			"an unmatched type", closed.Verdict)
	}

	open := EvaluateDelegation(mcpwire.DelegationPolicy{Tiers: tiers, DefaultAllow: true},
		parentSet(), DelegationRequest{AgentType: "general-purpose", Depth: 1})
	if open.Verdict != mcpwire.VerdictAllow {
		t.Fatalf("verdict = %q; DefaultAllow=true must pass an unmatched type", open.Verdict)
	}
}

// ---------------------------------------------------------------------------
// Three-state MaxDepth — zero is NOT unlimited
// ---------------------------------------------------------------------------

// Mutation: change MaxDepth to a plain int and treat 0 as "no limit".
// Rationale: the repo has already been bitten by exactly this — the rate-limit
// work found limit=0 reading as "unlimited", which is precisely the number an
// operator types when they mean "none".
func TestMaxDepthZeroMeansNoneNotUnlimited(t *testing.T) {
	none := mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{{
		Name: "no-delegation", AgentTypes: []string{"*"}, MaxDepth: intp(0),
	}}}
	d := EvaluateDelegation(none, parentSet(), DelegationRequest{AgentType: "Explore", Depth: 1})
	if d.Verdict != mcpwire.VerdictDeny {
		t.Fatal("MaxDepth=0 must forbid delegation entirely; reading it as " +
			"'unlimited' inverts the operator's intent")
	}
	if d.Code != mcpwire.DelegationDepthExceeded {
		t.Fatalf("code = %q; a depth refusal has its own code because its fix differs", d.Code)
	}

	unset := mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{{
		Name: "unbounded", AgentTypes: []string{"*"}, // MaxDepth nil
	}}}
	deep := EvaluateDelegation(unset, parentSet(), DelegationRequest{AgentType: "Explore", Depth: 9})
	if deep.Verdict == mcpwire.VerdictDeny {
		t.Fatal("MaxDepth unset must mean AiKey does not limit depth; the harness " +
			"still may (Harness manages quantity, AiKey manages authority — D-24)")
	}
}

// nil vs empty ToolsetSlugs: "this tier does not narrow" vs "narrow to nothing".
//
// Mutation: collapse the two (the obvious simplification).
// Rationale: collapsing turns an unconfigured tier into a total lockout — the
// D-27 failure mode wearing a different hat.
func TestNilToolsetsIsNotAnEmptyToolset(t *testing.T) {
	noNarrow := mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{{
		Name: "same-as-parent", AgentTypes: []string{"*"}, ToolsetSlugs: nil,
	}}}
	if d := EvaluateDelegation(noNarrow, parentSet(), DelegationRequest{AgentType: "Explore", Depth: 1}); d.Verdict != mcpwire.VerdictAllow {
		t.Fatalf("verdict = %q; nil ToolsetSlugs means 'do not narrow'", d.Verdict)
	}

	lockout := mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{{
		Name: "nothing", AgentTypes: []string{"*"}, ToolsetSlugs: []string{},
	}}}
	if d := EvaluateDelegation(lockout, parentSet(), DelegationRequest{AgentType: "Explore", Depth: 1}); d.Verdict != mcpwire.VerdictDeny {
		t.Fatalf("verdict = %q; an explicitly empty tier grants nothing", d.Verdict)
	}
}

// ---------------------------------------------------------------------------
// R61 / D-24 口径 — a refusal must say WHO refused
// ---------------------------------------------------------------------------

// Mutation: drop "AiKey" from denyReason, or drop the tier name, or drop the
// next step.
// Rationale: the harness refuses spawns too — depth, concurrency and budget
// limits of its own (measured in subagent_stats.refused). A message that does
// not name AiKey leaves the developer unable to tell which of two completely
// different fixes applies.
func TestDenialReasonNamesAikeyAndTheTier(t *testing.T) {
	pol := mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{
		{Name: "read-only", AgentTypes: []string{"Explore"}, ToolsetSlugs: []string{"reports"}},
	}, DefaultAllow: false}
	d := EvaluateDelegation(pol, parentSet(), DelegationRequest{AgentType: "general-purpose", Depth: 1})

	if d.Verdict != mcpwire.VerdictDeny {
		t.Fatalf("expected a denial, got %q", d.Verdict)
	}
	for _, want := range []string{"AiKey", string(mcpwire.DelegationDenied), "Explore", "Next:"} {
		if !strings.Contains(d.Reason, want) {
			t.Fatalf("refusal reason is missing %q.\nA refusal must say who refused, "+
				"which rule, what IS allowed, and the next step (R61 / D-24 口径).\ngot: %s",
				want, d.Reason)
		}
	}
}

// ---------------------------------------------------------------------------
// D-84 / I35 — the decision is made locally, with no network call
// ---------------------------------------------------------------------------

// Mutation: have the evaluator ask the control plane.
// Rationale: spawning is on the path a developer walks every time they ask
// their Agent to do anything. One round trip here is a stall they feel, and a
// governance hook that makes the tool feel slow gets uninstalled in week one —
// a gate nobody runs is worth less than no gate, because it is also believed in.
//
// 🔴 Asserted STRUCTURALLY on the source's import set rather than by counting
// requests at runtime: a runtime counter only catches the paths a test happens
// to walk, while the import list catches the capability itself.
func TestDelegationIsEvaluatedWithoutNetwork(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "delegation.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	banned := []string{"net/http", "net/url", "net", "io/ioutil", "os/exec"}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, b := range banned {
			if path == b {
				t.Fatalf("delegation.go imports %q; the spawn decision must be made "+
					"from the local snapshot with no I/O (I35)", path)
			}
		}
	}
	// Guard against the fence going vacuous if the file is ever renamed away.
	if len(f.Imports) == 0 {
		t.Fatal("parsed no imports at all — the fence is inspecting the wrong file")
	}
	if !ast.IsExported("EvaluateDelegation") {
		t.Fatal("unreachable; keeps the ast import honest")
	}
}

// ---------------------------------------------------------------------------
// D-85 / D-86 / I36 / D-29 — the fail-open, in BOTH directions
// ---------------------------------------------------------------------------

// D-85. Mutation: drop the Stale flag (and with it the caller's WARN).
// Rationale: a silent fail-open is indistinguishable, from the outside, from a
// gate that is working. That is the failure this whole design exists to avoid.
func TestNeverPolledAllowsAndFlagsStale(t *testing.T) {
	store := NewPolicyStore()
	store.MarkNeverPolled()
	gate := NewDelegationGate(store, NewPolicyCatalog(store, nil))

	d := gate.Decide(context.Background(), "org1", "seat1",
		DelegationRequest{AgentType: "Explore", Depth: 1})

	if d.Verdict != mcpwire.VerdictAllow {
		t.Fatalf("verdict = %q; a machine that has never reached the control plane "+
			"must behave exactly as it did before the gate existed (D-29)", d.Verdict)
	}
	if !d.Stale {
		t.Fatal("a fail-open decision must be FLAGGED so the caller emits " +
			"delegation_policy_stale. A silent fail-open looks identical to a working gate.")
	}
}

// D-86. Mutation: change the disconnect branch to refuse.
//
// 🔴 This fence asserts that we do NOT become more restrictive, which reads
// backwards and is very easy to "fix" by deleting. The reason it exists: with
// fail-closed, a developer who is offline or whose proxy is down loses
// sub-agents entirely, and their next move is to remove the hook — after which
// the organisation has no gate at all and does not know it.
func TestNeverFailsClosedOnDisconnect(t *testing.T) {
	store := NewPolicyStore()
	store.MarkNeverPolled()
	gate := NewDelegationGate(store, NewPolicyCatalog(store, nil))

	for _, agentType := range []string{"Explore", "general-purpose", "anything-at-all"} {
		d := gate.Decide(context.Background(), "org1", "seat1",
			DelegationRequest{AgentType: agentType, Depth: 3})
		if d.Verdict == mcpwire.VerdictDeny {
			t.Fatalf("a disconnected gate refused %q. Fail-closed here gets the hook "+
				"uninstalled, which leaves the org with no gate AND no signal (D-29).",
				agentType)
		}
	}
}

// ---------------------------------------------------------------------------
// D-92 / 15.F14 — one evaluator, shared by the console preview and the hook
// ---------------------------------------------------------------------------

// Mutation: give the console its own copy of the rule.
// Rationale: two evaluators eventually disagree, and the user believes the
// console — so the disagreement surfaces as "the console said I could".
func TestConsolePreviewAndHookShareTheEvaluator(t *testing.T) {
	pol := mcpwire.DelegationPolicy{Tiers: []mcpwire.DelegationTier{{
		Name: "ro", AgentTypes: []string{"Explore"}, ToolsetSlugs: []string{"reports"},
	}}}
	req := DelegationRequest{AgentType: "Explore", Depth: 1}

	// The console asks the pure function directly (no store, no seat lookup).
	preview := EvaluateDelegation(pol, parentSet(), req)

	// The hook goes through the gate, which must reach the same function.
	store := NewPolicyStore()
	store.Store(&Policy{
		OrgID: "org1", Version: 1, Delegation: pol,
		Toolsets: []PolicyToolset{
			{ID: "ts-reports", Slug: "reports", Status: StatusActive},
			{ID: "ts-prod", Slug: "prod-db", Status: StatusActive},
			{ID: "ts-jira", Slug: "jira", Status: StatusActive},
		},
		Grants: []PolicyGrant{
			{SubjectKind: SubjectSeat, SubjectID: "seat1", VirtualServerID: "ts-reports"},
			{SubjectKind: SubjectSeat, SubjectID: "seat1", VirtualServerID: "ts-prod"},
			{SubjectKind: SubjectSeat, SubjectID: "seat1", VirtualServerID: "ts-jira"},
		},
	})
	store.TouchSuccess()
	gate := NewDelegationGate(store, NewPolicyCatalog(store, nil))
	live := gate.Decide(context.Background(), "org1", "seat1", req)

	if preview.Verdict != live.Verdict {
		t.Fatalf("console preview said %q, the live gate said %q — two evaluators "+
			"have drifted, and the user believes the console",
			preview.Verdict, live.Verdict)
	}
	if strings.Join(preview.Toolsets, ",") != strings.Join(live.Toolsets, ",") {
		t.Fatalf("preview toolsets %v != live %v", preview.Toolsets, live.Toolsets)
	}
}

// ---------------------------------------------------------------------------
// R62 / 15.X9 — depth is ours, not the client's
// ---------------------------------------------------------------------------

// Mutation: read delegation_depth out of the hook event instead of computing it.
// Rationale: a client that reports its own depth reports 0 forever and walks
// past every limit. Same trust rule that keeps app_slug and session_id out of
// authorisation.
func TestDepthComesFromUsNotFromTheClient(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "delegation.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var offending []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// A HookEvent field read inside the evaluator would mean the client's
		// own claims are reaching the decision.
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "evt" {
			offending = append(offending, sel.Sel.Name)
		}
		return true
	})
	if len(offending) > 0 {
		t.Fatalf("the evaluator reads client-supplied hook fields %v; depth and "+
			"identity must be derived by us (R62)", offending)
	}
}

// ---------------------------------------------------------------------------
// 🔴 Never-polled is the STALEST state, not the freshest (bugfix 2026-09-08)
// ---------------------------------------------------------------------------

// Mutation: in DelegationGate.Decide, go back to
// `d.Stale = g.store.AgeSeconds() > delegationStaleAfterSeconds`; or make
// PolicyStore.StalerThan drop its `age < 0` branch.
//
// Rationale: a store restored from the on-disk cache HAS a policy (Synced() is
// true, so the fail-open early-return never fires) but has never polled, so
// AgeSeconds() reports the sentinel -1. `-1 > 120` is false ⇒ the gateway judged
// on an arbitrarily old cached snapshot and reported itself FRESH: no
// delegation_policy_stale, no WARN, indistinguishable from a healthy node.
//
// 🔴 The pre-existing fence could not catch this: it exercises the `!Synced()`
// path (never had any policy at all), and this defect lives on the
// `Synced() == true` path. The fence guarded a different route than the one the
// bug was on. Measured live 2026-09-08; see the E2E case for that run.
func TestNeverPolledIsMaximallyStale(t *testing.T) {
	store := NewPolicyStore()
	// Exactly what MCPPolicyRail does on start when a cache file exists.
	store.Store(&Policy{
		OrgID:   "org-1",
		Version: 7,
		Delegation: mcpwire.DelegationPolicy{
			Tiers:        []mcpwire.DelegationTier{{Name: "t", AgentTypes: []string{"*"}}},
			DefaultAllow: true,
		},
	})
	store.MarkNeverPolled()

	if !store.Synced() {
		t.Fatal("a cache-restored store is synced; if this changed, retarget this fence " +
			"— the defect it guards only exists on the synced path")
	}
	if got := store.AgeSeconds(); got != -1 {
		t.Fatalf("expected the never-polled sentinel -1, got %d", got)
	}
	if !store.StalerThan(delegationStaleAfterSeconds) {
		t.Fatal("a store that has NEVER reached the control plane reported itself fresh. " +
			"Never-polled is the stalest state there is — the sentinel must not be compared raw")
	}

	gate := NewDelegationGate(store, NewPolicyCatalog(store, nil))
	d := gate.Decide(context.Background(), "org-1", "seat-1",
		DelegationRequest{AgentType: "Explore", Depth: 1})
	if !d.Stale {
		t.Fatal("a decision made from a never-refreshed cached snapshot must be flagged Stale, " +
			"or D-29's WARN never fires and a gateway running on a month-old policy looks healthy")
	}
}
