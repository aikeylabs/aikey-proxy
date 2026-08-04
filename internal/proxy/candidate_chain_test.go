package proxy

// candidate_chain_test.go — the fence candidate_chain.go says exists.
//
// 🔴 It did not. `candidate_chain.go:44` has read "The fence in
// candidate_chain_test.go exists because 'it is true today by construction' is
// not the same as 'it will stay true'" since the file was written, and no such
// file was ever added. Task 6.3d (同 VK 围栏) was therefore uncovered while the
// source asserted otherwise — a pointer to evidence, with no evidence behind it.
// Found 2026-07-31 while auditing what the staging suite does and does not cover.
//
// Why THIS invariant needs a fence more than most: crossing virtual keys
// produces a request that SUCCEEDS. The caller gets a 200, so no user reports
// it; the bill lands on another key's owner, and the caller reaches a channel
// they were never granted. There is no failure signal anywhere for a monitor to
// notice. Either the fence catches it or nothing does.

import (
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func route(vkID, provider string, priority int64) *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		VirtualKeyID: vkID,
		ProviderCode: provider,
		ProtocolType: "anthropic",
		Priority:     priority,
		RouteGroupID: "rg-" + vkID,
		CredentialID: "cred-" + provider,
		BaseURL:      "https://" + provider + ".example",
	}
}

// TestChainFrom_CandidatesNeverLeaveTheVirtualKey is the 6.3d fence.
//
// 能红: make chainFrom read candidates from anywhere other than the route it was
// given (a registry-wide lookup, a provider-keyed cache, a "borrow a healthy
// sibling" fallback) and the second assertion fails.
func TestChainFrom_CandidatesNeverLeaveTheVirtualKey(t *testing.T) {
	p := &Proxy{}

	mine := route("vk-mine", "anthropic", 1)
	mine.Bindings = []*vkeys.ResolvedRoute{
		route("vk-mine", "anthropic", 1),
		route("vk-mine", "zhipu", 2),
	}
	// A neighbor that is healthy, cheaper, and completely irrelevant. Nothing
	// in the request references it; it exists only so that "borrowing" has
	// something to borrow.
	neighbor := route("vk-neighbor", "openai", 1)
	neighbor.Bindings = []*vkeys.ResolvedRoute{route("vk-neighbor", "openai", 1)}

	chain, err := p.chainFrom(mine, nil, "anthropic", nil)
	if err != nil {
		t.Fatalf("chainFrom: %v", err)
	}

	if len(chain.candidates) != 2 {
		t.Fatalf("candidates = %d, want 2 (the two bindings of THIS key)", len(chain.candidates))
	}
	for i, c := range chain.candidates {
		if c.VirtualKeyID != "vk-mine" {
			t.Errorf("candidate %d belongs to virtual key %q, want vk-mine.\n"+
				"A chain that reaches into another key bills its owner and grants a channel\n"+
				"the caller was never given — on a request that returns 200, so nothing else\n"+
				"in the system would ever report it.", i, c.VirtualKeyID)
		}
		if c.ProviderCode == neighbor.ProviderCode {
			t.Errorf("candidate %d is the NEIGHBOR's upstream (%s)", i, c.ProviderCode)
		}
	}
}

// TestChainFrom_EmptyBindingsStaysSingleShot pins the first of the three
// empty-ish states candidate_chain.go's header separates. Personal's resting
// state must keep pre-upgrade behavior byte for byte.
func TestChainFrom_EmptyBindingsStaysSingleShot(t *testing.T) {
	p := &Proxy{}
	r := route("vk-solo", "anthropic", 1)
	r.RouteGroupID = "" // no group at all — a legacy row
	chain, err := p.chainFrom(r, nil, "anthropic", nil)
	if err != nil {
		t.Fatalf("chainFrom: %v", err)
	}
	if len(chain.candidates) != 1 || chain.grouped {
		t.Fatalf("want a single ungrouped candidate, got %d (grouped=%v)", len(chain.candidates), chain.grouped)
	}
	if chain.canFailover() {
		t.Error("a legacy single binding must not fail over — that is the pre-upgrade contract")
	}
}

// TestChainFrom_OneMemberGroupIsUnconfiguredNotExhausted keeps the two terminal
// codes apart. They point at OPPOSITE next actions: UNCONFIGURED is permanent
// until an administrator adds a second upstream, EXHAUSTED means go look at the
// upstreams you have.
func TestChainFrom_OneMemberGroupIsUnconfiguredNotExhausted(t *testing.T) {
	p := &Proxy{}
	r := route("vk-one", "anthropic", 1)
	r.Bindings = []*vkeys.ResolvedRoute{route("vk-one", "anthropic", 1)}
	chain, err := p.chainFrom(r, nil, "anthropic", nil)
	if err != nil {
		t.Fatalf("chainFrom: %v", err)
	}
	if got := chain.exhaustedCode(); got != "UPSTREAM_FALLBACK_UNCONFIGURED" {
		t.Errorf("exhaustedCode = %q, want UPSTREAM_FALLBACK_UNCONFIGURED.\n"+
			"An administrator who built a one-member group very likely believes it is\n"+
			"redundant; telling them to retry hides the only action that would work.", got)
	}
}

// TestChainFrom_OrdersByPriorityRegardlessOfInputOrder guards the second sort.
// candidate_chain.go sorts even though the registry already did, because a
// second producer of Bindings would otherwise serve the administrator's FALLBACK
// as the primary — and the request would succeed, so nothing would report it.
func TestChainFrom_OrdersByPriorityRegardlessOfInputOrder(t *testing.T) {
	p := &Proxy{}
	r := route("vk-order", "anthropic", 1)
	r.Bindings = []*vkeys.ResolvedRoute{
		route("vk-order", "zhipu", 2), // fallback handed in FIRST
		route("vk-order", "anthropic", 1),
	}
	chain, err := p.chainFrom(r, nil, "anthropic", nil)
	if err != nil {
		t.Fatalf("chainFrom: %v", err)
	}
	if chain.candidates[0].ProviderCode != "anthropic" {
		t.Errorf("first candidate = %q, want anthropic (priority 1).\n"+
			"Serving the fallback first is invisible: the call succeeds, the bill goes to\n"+
			"the wrong vendor, and the console still shows the configured order.",
			chain.candidates[0].ProviderCode)
	}
}

// poolRoute builds one row of an OAuth account pool's projection: no route
// group, priority defaulted to 1 by the vault reader, group identity in
// OauthGroupID. `accounts` empty models the stale pre-P1e row.
func poolRoute(vkID, groupID, provider, accounts string) *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		VirtualKeyID:  vkID,
		ProviderCode:  provider,
		ProtocolType:  "anthropic",
		Priority:      1,
		FallbackRole:  "primary",
		OauthGroupID:  groupID,
		GroupAccounts: accounts,
		BaseURL:       "https://api.anthropic.com",
	}
}

// TestChainFrom_PoolRowsAreNotARouteGroupAmbiguity is the staging outage of
// 2026-08-03: every OAuth account pool answered 409 PROVIDER_ROUTE_AMBIGUOUS.
//
// The shape is exactly what the node vault held — one pool VK, two cache rows at
// the defaulted priority 1, no route group, differing only in provider_code
// (a pre-P1e row with none, the live row with "anthropic"). The route-group
// uniqueness invariant does not reach these rows and never did.
//
// 能红: drop the `RouteGroupID == ""` skip in duplicatePriority and this returns
// the 409 again.
func TestChainFrom_PoolRowsAreNotARouteGroupAmbiguity(t *testing.T) {
	p := &Proxy{}
	r := poolRoute("vk-pool", "grp-1", "anthropic", `[{"account_id":"a1"}]`)
	r.Bindings = []*vkeys.ResolvedRoute{
		// Sorted order as buildManagedRoutes hands it over: equal priority breaks
		// on provider code, so the EMPTY provider — the stale row — comes first.
		poolRoute("vk-pool", "grp-1", "", "[]"),
		poolRoute("vk-pool", "grp-1", "anthropic", `[{"account_id":"a1"}]`),
	}

	chain, err := p.chainFrom(r, nil, "anthropic", nil)
	if err != nil {
		t.Fatalf("pool VK refused with %v.\n"+
			"  Two pool rows at priority 1 is legal by construction: nothing constrains\n"+
			"  priority outside a route group, and the vault reader defaults it to 1.\n"+
			"  Refusing here takes the whole pool offline on data the control plane\n"+
			"  cannot even express as an ordering.", err)
	}
	if len(chain.candidates) != 1 {
		t.Fatalf("pool expanded to %d hops, want 1.\n"+
			"  A pool is ONE routing destination — which account serves is the assignment\n"+
			"  engine's decision, made on quota and seat rank the chain cannot see.\n"+
			"  Failing over between its rows would silently overrule that allocation.",
			len(chain.candidates))
	}
	if got := chain.candidates[0].ProviderCode; got != "anthropic" {
		t.Errorf("pool hop provider = %q, want anthropic.\n"+
			"  The stale row sorts FIRST (empty provider < \"anthropic\"), so taking\n"+
			"  candidates[0] picks the row with no provider and no accounts. That does\n"+
			"  not 409 — it fails deeper in, as GROUP_NO_CANDIDATES, further from the cause.",
			got)
	}
	if chain.canFailover() {
		t.Error("canFailover() on a single pool: a request may now try the pool twice")
	}
}

// TestChainFrom_RouteGroupAmbiguityStillRefuses pins the narrowing to what it
// narrowed. 2.27b is still in force for the rows it was written about.
//
// 能红: skip grouped candidates too (e.g. by dropping the group key from the seen
// map) and the refusal disappears — the chain would then serve in an order
// nobody authored.
func TestChainFrom_RouteGroupAmbiguityStillRefuses(t *testing.T) {
	p := &Proxy{}
	r := route("vk-rg", "anthropic", 1)
	clash := route("vk-rg", "zhipu", 1) // same RouteGroupID (rg-vk-rg), same priority
	r.Bindings = []*vkeys.ResolvedRoute{r, clash}

	_, err := p.chainFrom(r, nil, "anthropic", nil)
	if err == nil {
		t.Fatal("two route group members at priority 1 were accepted — the chain has no " +
			"defined order, so which upstream serves is whatever the sort happened to do")
	}
	// C: the message must name the group it is talking about. "the route group"
	// alone is not an instruction when a key sits in more than one.
	if !strings.Contains(err.Error(), "rg-vk-rg") {
		t.Errorf("error does not name the offending route group: %q", err.Error())
	}
}

// TestDuplicatePriority_GroupedAndUngroupedDoNotClash: a route group member and
// an ungrouped row sharing a priority are not in the same ordering at all, so
// this is not a conflict to report.
//
// 能红: make duplicatePriority compare priorities in one flat bucket (the shape
// before this change) and it reports a clash between two unrelated rows.
func TestDuplicatePriority_GroupedAndUngroupedDoNotClash(t *testing.T) {
	grouped := route("vk-mix", "anthropic", 1) // RouteGroupID rg-vk-mix
	loose := poolRoute("vk-mix", "grp-9", "zhipu", `[{"account_id":"a1"}]`)
	if dup, ambiguous := duplicatePriority([]*vkeys.ResolvedRoute{grouped, loose}); ambiguous {
		t.Errorf("reported a clash at priority %d between a route group member and a row "+
			"that is in no route group — they are not ordered against each other", dup)
	}
	// And two members of DIFFERENT groups at the same priority are likewise fine.
	other := route("vk-mix2", "zhipu", 1) // RouteGroupID rg-vk-mix2
	if dup, ambiguous := duplicatePriority([]*vkeys.ResolvedRoute{grouped, other}); ambiguous {
		t.Errorf("reported a clash at priority %d across two different route groups", dup)
	}
}

// TestChainFrom_UngroupedSiblingsAtOnePriorityAreNotAmbiguous covers the OTHER
// way ungrouped rows reach the ambiguity check — two ordinary bindings under one
// virtual key with no route group between them, which is every multi-provider key
// written before route groups existed. The vault reader defaults both to priority
// 1, so before this change they refused too.
//
// 🔴 Separate from the pool fence on purpose: the pool never reaches
// duplicatePriority at all (collapseOauthGroups runs first and leaves one hop),
// so the pool test passes with or without the skip. This is the case that pins it.
//
// 能红: give duplicatePriority one flat priority map again — the shape before
// 2026-08-03 — and this refuses.
func TestChainFrom_UngroupedSiblingsAtOnePriorityAreNotAmbiguous(t *testing.T) {
	p := &Proxy{}
	legacy := func(provider string) *vkeys.ResolvedRoute {
		r := route("vk-legacy", provider, 1)
		r.RouteGroupID = "" // pre-route-group row
		return r
	}
	r := legacy("anthropic")
	r.Bindings = []*vkeys.ResolvedRoute{legacy("anthropic"), legacy("zhipu")}

	chain, err := p.chainFrom(r, nil, "anthropic", nil)
	if err != nil {
		t.Fatalf("two ungrouped bindings at the defaulted priority 1 were refused: %v\n"+
			"  Nothing authored that priority — the vault reader supplies 1 when the\n"+
			"  column is absent — so there is no administrator order here to be unreadable.", err)
	}
	if chain.grouped {
		t.Error("chain reports grouped=true with no route group id; " +
			"exhaustedCode() would then hand back UPSTREAM_FALLBACK_UNCONFIGURED and tell " +
			"the user to go fix a route group that does not exist")
	}
}

// Failover must stay an authored decision. Ungrouped siblings carry a defaulted
// priority, so a chain built from them has no order anybody chose — trying the
// second one on the first one's failure would silently route to an upstream the
// administrator never ranked, and it would SUCCEED, so nothing would surface it.
// 能红 (2026-08-03 review finding): drop `c.grouped` from canFailover and this
// fires.
func TestCanFailover_RequiresAnAuthoredGroupOrder(t *testing.T) {
	ungrouped := &candidateChain{
		candidates: []*vkeys.ResolvedRoute{
			{ProviderCode: "anthropic", Priority: 1},
			{ProviderCode: "zhipu", Priority: 1},
		},
		grouped: false,
	}
	if ungrouped.canFailover() {
		t.Error("ungrouped siblings must stay single-shot: no administrator ordered them")
	}

	grouped := &candidateChain{
		candidates: []*vkeys.ResolvedRoute{
			{ProviderCode: "anthropic", Priority: 1, RouteGroupID: "rg-1"},
			{ProviderCode: "zhipu", Priority: 2, RouteGroupID: "rg-1"},
		},
		grouped: true,
	}
	if !grouped.canFailover() {
		t.Error("a real group chain must still fail over — that is the feature")
	}

	pinned := &candidateChain{
		candidates: grouped.candidates,
		grouped:    true,
		pinned:     true,
	}
	if pinned.canFailover() {
		t.Error("`aikey use` pinning must keep disabling failover (D-1③/F-16④)")
	}
}
