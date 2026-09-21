package proxy

// grading_hot_swap_test.go — TODO-188 方案 C, proxy half.
//
// The org grading document's two request-level members (escalation[] and
// route_policy[]) used to be plain fields written once at generation build: a
// ladder edit re-spawned the detector and rebuilt the generation, so nothing
// ever mutated a live Proxy. Since C the supervisor installs a new document
// into the LIVE generation (after the detector pool confirmed it), with
// requests in flight. These fences pin the two properties that makes safe.
//
// spec: R-compliance-grading-5.1

import (
	"sync"
	"testing"
)

const (
	swapDocL4 = `{"escalation":[{"min_level":4,"min_count":2,"action":"block"}],` +
		`"route_policy":[{"min_level":4,"allowed_providers":["intranet-*"],"otherwise":"block"}]}`
	swapDocL5 = `{"escalation":[{"min_level":5,"min_count":2,"action":"block"}],` +
		`"route_policy":[{"min_level":5,"allowed_providers":["intranet-*"],"otherwise":"block"}]}`
)

// TestGradingHotSwap_EscalationAndRoutePolicySwapTogether — a request that pins
// the installation (complianceGrading, once per request in applyInboundFilter)
// sees BOTH members from the SAME document, however many swaps race it. A
// request judged by L5's cumulative rule and L4's route policy would be a
// verdict no administrator ever configured. Run with -race: the swap now runs
// on a live Proxy, and a plain field write here is a data race on the request
// path.
//
// 能红: install the two members with two separate stores (or back onto plain
// fields) → -race reports the write, and/or a pinned value mixes 4 and 5.
func TestGradingHotSwap_EscalationAndRoutePolicySwapTogether(t *testing.T) {
	p := &Proxy{}
	if _, _, err := p.SetComplianceGrading([]byte(swapDocL4)); err != nil {
		t.Fatal(err)
	}
	var writer, readers sync.WaitGroup
	stop := make(chan struct{})
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			doc := swapDocL4
			if i%2 == 1 {
				doc = swapDocL5
			}
			if _, _, err := p.SetComplianceGrading([]byte(doc)); err != nil {
				t.Errorf("SetComplianceGrading: %v", err)
				return
			}
		}
	}()
	for r := 0; r < 8; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 2000; i++ {
				g := p.complianceGrading()
				if len(g.escalation) != 1 || len(g.routePolicy) != 1 {
					t.Errorf("pinned installation lost a member: escalation=%d route_policy=%d",
						len(g.escalation), len(g.routePolicy))
					return
				}
				if g.escalation[0].MinLevel != g.routePolicy[0].MinLevel {
					t.Errorf("one request saw escalation from L%d and route_policy from L%d — two documents in one verdict",
						g.escalation[0].MinLevel, g.routePolicy[0].MinLevel)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	writer.Wait()
}

// TestGradingHotSwap_UnreadableMemberKeepsItsPrevious — installing a document
// whose route_policy member does not decode keeps the route policy IN FORCE and
// still takes the escalation member (and vice versa). Unchanged semantics from
// the per-generation install; pinned now that installs land on a live Proxy,
// where "keep the previous" means the previous LIVE value, not an empty one.
func TestGradingHotSwap_UnreadableMemberKeepsItsPrevious(t *testing.T) {
	p := &Proxy{}
	if _, _, err := p.SetComplianceGrading([]byte(swapDocL4)); err != nil {
		t.Fatal(err)
	}
	badRoute := `{"escalation":[{"min_level":5,"min_count":2,"action":"block"}],"route_policy":"not-a-list"}`
	if _, _, err := p.SetComplianceGrading([]byte(badRoute)); err != nil {
		t.Fatalf("escalation member was readable, err must be nil: %v", err)
	}
	g := p.complianceGrading()
	if len(g.routePolicy) != 1 || g.routePolicy[0].MinLevel != 4 {
		t.Fatalf("an unreadable route_policy member replaced the one in force: %+v", g.routePolicy)
	}
	if len(g.escalation) != 1 || g.escalation[0].MinLevel != 5 {
		t.Fatalf("the readable escalation member was not taken: %+v", g.escalation)
	}
}
