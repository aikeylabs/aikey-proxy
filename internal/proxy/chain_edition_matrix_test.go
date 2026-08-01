package proxy

// chain_edition_matrix_test.go — task 6.4, the L1 row of the three-edition
// regression matrix (Trial / Production / Cluster).
//
// # 🔴 Why this is a fence and not three copies of the same test
//
// 6.4's L1 row reads "候选序列排序（单 binding / 多 binding / 全失败）" for Trial and
// "同" (same) for Production and Cluster. The obvious way to satisfy that is to
// run the ordering tests three times under three edition flags. That would be
// theater: there are no edition flags on this path. The candidate sequence is
// ONE implementation — no build tag, no `if edition == …`, no per-edition
// registry — compiled into every edition's binary.
//
// So the honest evidence for "same in all three" is not three green runs; it is
// that a per-edition divergence CANNOT be introduced without this test failing.
// Three copies would happily keep passing after somebody added the branch, each
// exercising its own arm.
//
// What genuinely differs per edition is WIRING, not chain logic — which vault
// backs `activeReader`, where the registry gets its routes. Those are covered by
// their own tests; they change what the chain is HANDED, never how it orders.
//
// 能红: add `if edition == "trial"` (or a `//go:build` tag) to any of the chain
// files and TestChainCodeHasNoEditionBranch fails, naming the file and line.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// chainFiles are the files that decide the candidate sequence and how it is
// walked. A new one belongs here the moment it can affect ordering.
var chainFiles = []string{
	"candidate_chain.go",
	"chain_serve.go",
	"chain_activity.go",
	"binding_cooldown.go",
	"chain_app.go",
}

func TestChainCodeHasNoEditionBranch(t *testing.T) {
	// Words that would mean the chain behaves differently per edition. Deliberately
	// narrow: `edition` appears in prose comments across this package, and banning
	// the word would make the fence unmaintainable and get it deleted.
	banned := []string{
		`edition ==`, `edition !=`, `Edition ==`, `Edition !=`,
		`buildinfo.Edition`, `IsTrial(`, `IsPersonal(`, `IsProduction(`, `IsCluster(`,
	}
	for _, name := range chainFiles {
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v — if this file was renamed, update chainFiles; a fence that "+
				"silently stops covering a file is worse than no fence", name, err)
		}
		src := string(body)
		for _, tag := range []string{"//go:build", "// +build"} {
			if strings.Contains(src, tag) {
				t.Errorf("%s carries a %s constraint — the candidate sequence must compile "+
					"identically into every edition", name, tag)
			}
		}
		for _, b := range banned {
			if idx := strings.Index(src, b); idx >= 0 {
				line := 1 + strings.Count(src[:idx], "\n")
				t.Errorf("%s:%d branches on edition (%q).\n"+
					"Failover that differs by edition means an administrator's chain behaves one way\n"+
					"on Trial and another on Cluster, with nothing in the logs to say why — and the\n"+
					"three-edition matrix would still be green, because each copy exercises its own arm.",
					name, line, b)
			}
		}
	}
}

// TestCandidateOrderingMatrixL1 is 6.4's L1 cell itself — single binding,
// multiple bindings, and all-failed — asserted ONCE, which the fence above makes
// a statement about all three editions.
func TestCandidateOrderingMatrixL1(t *testing.T) {
	p := &Proxy{}

	t.Run("single binding stays single-shot", func(t *testing.T) {
		r := route("vk-1", "anthropic", 1)
		r.RouteGroupID = ""
		chain, err := p.chainFrom(r, nil, "anthropic", nil)
		if err != nil {
			t.Fatalf("chainFrom: %v", err)
		}
		if len(chain.candidates) != 1 || chain.canFailover() {
			t.Fatalf("want one candidate and no failover, got %d (canFailover=%v)",
				len(chain.candidates), chain.canFailover())
		}
	})

	t.Run("multiple bindings order by priority", func(t *testing.T) {
		r := route("vk-2", "anthropic", 1)
		r.Bindings = []*vkeys.ResolvedRoute{
			route("vk-2", "openai", 3),
			route("vk-2", "anthropic", 1),
			route("vk-2", "zhipu", 2),
		}
		chain, err := p.chainFrom(r, nil, "anthropic", nil)
		if err != nil {
			t.Fatalf("chainFrom: %v", err)
		}
		got := make([]string, 0, len(chain.candidates))
		for _, c := range chain.candidates {
			got = append(got, c.ProviderCode)
		}
		want := []string{"anthropic", "zhipu", "openai"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("order = %v, want %v — the administrator's configured order is the only "+
				"input to the sequence; nothing may re-sort by latency, cost or health", got, want)
		}
		if !chain.canFailover() {
			t.Error("a three-member chain must be able to fail over")
		}
	})

	t.Run("all-failed reports the right terminal code", func(t *testing.T) {
		// A GROUP of one and a chain of many end differently on purpose: one is
		// "you never configured a fallback", the other "none of yours worked".
		one := route("vk-3", "anthropic", 1)
		one.Bindings = []*vkeys.ResolvedRoute{route("vk-3", "anthropic", 1)}
		chainOne, err := p.chainFrom(one, nil, "anthropic", nil)
		if err != nil {
			t.Fatalf("chainFrom(one): %v", err)
		}
		if got := chainOne.exhaustedCode(); got != "UPSTREAM_FALLBACK_UNCONFIGURED" {
			t.Errorf("one-member exhausted code = %q, want UPSTREAM_FALLBACK_UNCONFIGURED", got)
		}

		many := route("vk-4", "anthropic", 1)
		many.Bindings = []*vkeys.ResolvedRoute{
			route("vk-4", "anthropic", 1), route("vk-4", "zhipu", 2),
		}
		chainMany, err := p.chainFrom(many, nil, "anthropic", nil)
		if err != nil {
			t.Fatalf("chainFrom(many): %v", err)
		}
		if got := chainMany.exhaustedCode(); got != "UPSTREAM_FALLBACK_EXHAUSTED" {
			t.Errorf("multi-member exhausted code = %q, want UPSTREAM_FALLBACK_EXHAUSTED", got)
		}
	})
}
