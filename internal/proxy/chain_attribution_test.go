package proxy

// chain_attribution_test.go — who gets billed, and how many things happened
// (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 3.2 / 3.3 / 3.9 /
// 3.10 / 3.11 / 3.12, invariants I4 / I25).
//
// # 🔴 Why these need fences rather than review
//
// Every failure in this file is SILENT. The request succeeds, the user has no
// reason to check anything, and the only symptom is a number on a dashboard that
// nobody can prove wrong until an invoice is disputed. Reading the outer `route`
// variable instead of the hop's own even compiles and passes on a single hop —
// it is wrong only when a switch happened, which is the exact case the fields
// exist to describe.

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// capturingEventStore records every usage event so a fence can assert on the
// SHAPE of the row set — how many, which one carries tokens, whether they share a
// trace. Those are the only observable form these defects take.
type capturingEventStore struct {
	mu     sync.Mutex
	events []events.UsageEvent
}

func (c *capturingEventStore) Insert(evs []events.UsageEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, evs...)
	return nil
}
func (c *capturingEventStore) QueryStats() (map[string]int64, map[string]int64, error) {
	return nil, nil, nil
}
func (c *capturingEventStore) Close() error { return nil }

// recorded waits for the async collector to flush before reading.
//
// The collector batches with a short interval; reading immediately would see
// whichever rows happened to have landed, which turns a fence about ROW COUNT
// into a race. A fence that is sometimes right is worse than no fence, because
// its green is meaningless.
func (c *capturingEventStore) recorded() []events.UsageEvent {
	deadline := time.Now().Add(2 * time.Second)
	var last int
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.events)
		c.mu.Unlock()
		if n > 0 && n == last {
			break // stable across one interval — the flush has settled
		}
		last = n
		time.Sleep(20 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]events.UsageEvent(nil), c.events...)
}

// twoHopChainWithStore is twoHopChain wired to a readable event store.
func twoHopChainWithStore(t *testing.T, store *capturingEventStore) (*Proxy, *chainCapture) {
	t.Helper()
	p := setupTestProxyWithStore(t, "http://unused.invalid", store)
	primary := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-chain", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		BaseURL: "https://primary.invalid", PlaintextKey: "key-primary",
		BindingID: "b-primary", CredentialID: "cred-primary",
		Priority: 1, FallbackRole: "primary", RouteGroupID: "rg-1", RouteGroupName: "main",
	}
	fallback := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-chain", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "mock", RouteSource: "team",
		BaseURL: "https://fallback.invalid", PlaintextKey: "key-fallback",
		BindingID: "b-fallback", CredentialID: "cred-fallback",
		Priority: 2, FallbackRole: "fallback", RouteGroupID: "rg-1", RouteGroupName: "main",
	}
	container := *primary
	container.Bindings = []*vkeys.ResolvedRoute{primary, fallback}
	container.BaseURL = ""
	container.PlaintextKey = ""
	container.ProviderCode = ""
	container.ProtocolType = ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_chaintest": &container})
	cap := &chainCapture{statusByHost: map[string]int{}, headerByHost: map[string]http.Header{}, bodyByHost: map[string]string{}}
	p.SetTransport(cap)
	return p, cap
}

// 🔴 3.3 + 3.11: cost follows the hop that SERVED, not the one tried first.
func TestAttribution_CostFollowsTheServingUpstream(t *testing.T) {
	store := &capturingEventStore{}
	p, cap := twoHopChainWithStore(t, store)
	cap.statusByHost["primary.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	evs := store.recorded()
	if len(evs) == 0 {
		t.Fatal("no usage event was recorded for a request that reached an upstream")
	}
	last := evs[len(evs)-1]
	if last.ServedProvider != "mock" {
		t.Errorf("served_provider=%q, want the FALLBACK's provider (mock).\n"+
			"Attributing a call the fallback served to the primary is the most likely "+
			"silent error in this change: the request succeeded, so nobody has a reason "+
			"to check, and the ledger is wrong in a direction that surfaces only when an "+
			"invoice is disputed", last.ServedProvider)
	}
	if last.ServedBindingID != "b-fallback" {
		t.Errorf("served_binding_id=%q, want b-fallback", last.ServedBindingID)
	}
	if last.FallbackAttempt != 2 {
		t.Errorf("fallback_attempt=%d, want 2.\n"+
			"Reading this from the loop's outer `route` variable compiles and passes "+
			"every single-hop test — on one hop the two are equal. It is wrong ONLY "+
			"when a switch happened", last.FallbackAttempt)
	}
	if last.FallbackReason == "" {
		t.Error("fallback_reason is empty on a hop that was switched INTO")
	}
}

// 🔴 The same invariant for `request_id` — and this is the one that actually
// counts, because it is the key the shipped measure dedups on.
//
// Task 3.10 was written against `trace_id`, and the fence below pins that. But
// `trace_id` is never projected into `usage_fact_dwd`: Order 11060 carried
// ODS `request_id` instead and built `usage_reporting_fact.client_request_count`
// on it (one row per request_id gets 1, its siblings get 0). So the dashboard's
// 「请求数」 is a request_id dedup, and until 2026-08-04 nothing asserted that
// request_id survives a hop.
//
// Both ids come from the same TraceContext today, created once at the HTTP entry
// and inherited by every clone — which is exactly why this is worth pinning
// rather than assuming: they are correct by a shared implementation detail, not
// by anything that fails when it changes. Give the hops distinct request_ids and
// every attempt row becomes its own "client request": the count silently
// inflates by the number of upstreams we tried, and nothing anywhere goes red.
func TestAttribution_EveryHopSharesOneRequestID(t *testing.T) {
	store := &capturingEventStore{}
	p, cap := twoHopChainWithStore(t, store)
	cap.statusByHost["primary.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)
	_ = w

	evs := store.recorded()
	if len(evs) < 2 {
		t.Fatalf("recorded %d events for a request that touched two upstreams, want 2", len(evs))
	}
	first := evs[0].RequestID
	if first == "" {
		t.Fatal("no request id on the usage event — client_request_count falls back to " +
			"the stored request_count per row, so an empty id counts every attempt as its own request")
	}
	for i, ev := range evs {
		if ev.RequestID != first {
			t.Fatalf("hop %d has request_id %q, hop 0 has %q.\n"+
				"usage_reporting_fact.client_request_count marks ONE row per request_id as the "+
				"client request; distinct ids per hop make each attempt its own request and the "+
				"reported request count comes out N× too high for every failover. The dashboard "+
				"does not break — it just quietly bills the story wrong", i, ev.RequestID, first)
		}
	}

	// And it must not be shared with a DIFFERENT request: an id that never varies
	// (a constant, a zero value) would satisfy the loop above while collapsing
	// every request in the org into one.
	req2, w2 := chainReq()
	p.Handle(w2, req2)
	_ = w2
	later := store.recorded()
	if len(later) <= len(evs) {
		t.Fatalf("second request recorded no events (%d then %d)", len(evs), len(later))
	}
	if later[len(later)-1].RequestID == first {
		t.Error("a second, independent client request reused the first one's request_id — " +
			"the sharing above would then be vacuous, and the whole org would count as one request")
	}
}

// 🔴 3.10 / I25: one client request is one `trace_id`, however many hops it took.
//
// The risk is concrete: replaying the request body with a fresh trace context
// would break this quietly. No dashboard errors — the request COUNT simply comes
// out too high, and every explanation of the discrepancy would be wrong.
func TestAttribution_EveryHopSharesOneTraceID(t *testing.T) {
	store := &capturingEventStore{}
	p, cap := twoHopChainWithStore(t, store)
	cap.statusByHost["primary.invalid"] = 503

	req, w := chainReq()
	p.Handle(w, req)
	_ = w

	evs := store.recorded()
	if len(evs) < 2 {
		t.Fatalf("recorded %d events for a request that touched two upstreams, want 2.\n"+
			"🚫 Recording only the successful hop would delete the audit evidence that we "+
			"called an upstream at all", len(evs))
	}
	first := evs[0].TraceID
	if first == "" {
		t.Fatal("no trace id on the usage event")
	}
	for i, ev := range evs {
		if ev.TraceID != first {
			t.Fatalf("hop %d has trace_id %q, hop 0 has %q.\n"+
				"'Requests' is defined as trace_id deduplicated, so a fresh trace per hop "+
				"inflates the request count with nothing to signal it. The dashboard does "+
				"not break — it just quietly disagrees with reality", i, ev.TraceID, first)
		}
	}
}

// 🔴 3.12: the failed hops must NOT carry token counts.
//
// One client request = one charge + N audit rows. If a failed attempt carried
// tokens, the same conversation would be billed once per upstream we tried.
func TestAttribution_OnlyTheServingHopCarriesTokens(t *testing.T) {
	store := &capturingEventStore{}
	p, cap := twoHopChainWithStore(t, store)
	cap.statusByHost["primary.invalid"] = 503
	cap.bodyByHost["fallback.invalid"] =
		`{"id":"msg_1","model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":11,"output_tokens":22}}`

	req, w := chainReq()
	p.Handle(w, req)
	_ = w

	evs := store.recorded()
	withTokens := 0
	for _, ev := range evs {
		if ev.InputTokens > 0 || ev.OutputTokens > 0 {
			withTokens++
		}
	}
	if withTokens > 1 {
		t.Fatalf("%d of %d rows carry token counts, want at most 1.\n"+
			"A failed attempt produced no completion, so charging for it bills the same "+
			"conversation once per upstream we tried", withTokens, len(evs))
	}
}
