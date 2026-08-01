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
