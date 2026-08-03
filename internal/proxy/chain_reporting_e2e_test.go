package proxy

// chain_reporting_e2e_test.go — does the proxy REPORT a switch correctly?
//
// # 🔴 The gap this closes
//
// Every other chain test reads the ledger out of an in-process
// `capturingEventStore`, which the proxy hands events to directly. That proves
// what the proxy DECIDED. It does not prove anything about what it SENDS: the
// upload path (events.Reporter → WAL → batch → HTTP POST
// `/v1/usage-events:batch`) is a different pipeline with its own serialization,
// its own batching, and its own field set, and up to now the events reaching a
// collector in testing had been posted BY HAND. Hand-posting a payload proves
// the collector accepts that payload; it says nothing about whether the proxy
// produces it.
//
// So this wires a REAL `events.Reporter` at a real HTTP listener and asserts on
// the bytes the proxy actually put on the wire after a real fallback switch.
//
// 🔴 What must survive the trip, and why each one matters if it doesn't:
//
//   - BOTH hops appear. If the refused hop is dropped on upload, the collector's
//     view is "one call, one provider" and a failover is invisible to billing
//     and to the console — the in-process ledger would still look perfect.
//   - fallback_reason / fallback_attempt survive. These are the only fields that
//     say a switch HAPPENED; without them the two rows read as two unrelated
//     calls.
//   - trace_id is shared and non-empty. It is what re-assembles the two rows
//     into one client request downstream.
//   - Exactly one row carries tokens, and it is the hop that served. This is the
//     billing claim (F-12); getting it wrong double-bills or bills the wrong
//     vendor.
//
// 🚫 Still NOT proven here: the collector's own storage, and ODS→DWD
// propagation. This is the proxy's half of the wire — the 6.1 L2 row, not L3.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// collectorSpy implements the collector's ingest contract and keeps every batch.
//
// 🔴 It enforces the contract rather than accepting anything: a wrong method,
// path or missing bearer is recorded as a rejection and fails the test. A spy
// that 200s unconditionally would let the proxy upload to the wrong place, in
// the wrong shape, and still look healthy.
type collectorSpy struct {
	mu         sync.Mutex
	batches    []map[string]any
	rejections []string
	token      string
}

func (c *collectorSpy) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.Method != http.MethodPost {
			c.rejections = append(c.rejections, "method "+r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// 🔴 Exact path, not a suffix. A suffix match accepts
		// "/anything/v1/usage-events:batch", so a misconfigured collector base
		// URL would still look correct here — which it did, the first time this
		// spy was written.
		if r.URL.Path != "/v1/usage-events:batch" {
			c.rejections = append(c.rejections, "path "+r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+c.token {
			c.rejections = append(c.rejections, "auth "+got)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var batch map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			c.rejections = append(c.rejections, "unparseable body: "+err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.batches = append(c.batches, batch)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accepted":true}`)
	})
}

// uploadedEvents flattens every event across every batch received so far.
func (c *collectorSpy) uploadedEvents() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, b := range c.batches {
		raw, ok := b["events"].([]any)
		if !ok {
			continue
		}
		for _, e := range raw {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func (c *collectorSpy) failures() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.rejections...)
}

func TestChain_ProxyUploadsBothHopsToACollector(t *testing.T) {
	const token = "svc-token-for-this-test"
	spy := &collectorSpy{token: token}
	collector := httptest.NewServer(spy.handler())
	defer collector.Close()

	// ── Two real upstreams: one down, one that answers ─────────────────────
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error","message":"down"}}`)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"m1","type":"message","role":"assistant","model":"claude-sonnet-4-5",`+
			`"content":[{"type":"text","text":"served"}],"usage":{"input_tokens":11,"output_tokens":22}}`)
	}))
	defer up.Close()

	// ── A REAL reporter, pointed at the listener ───────────────────────────
	reporter, err := events.NewReporter(&events.ReporterConfig{
		WALDir:         t.TempDir(),
		CollectorURL:   collector.URL,
		CollectorToken: token,
		SourceID:       "src-reporting-e2e",
		BatchSize:      10,
		UploadInterval: 50 * time.Millisecond,
		QueueCapacity:  100,
	})
	if err != nil {
		t.Fatalf("build reporter: %v", err)
	}
	defer reporter.Close()

	store := &capturingEventStore{}
	p := setupTestProxyWithStore(t, "http://unused.invalid", store)
	p.SetReporter(reporter, "proxy-instance-test", "0.0.0-test", "cfg-test", 0, "")

	mk := func(code, url, id string, prio int64, role string) *vkeys.ResolvedRoute {
		return &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-rep", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: code, RouteSource: "team", BaseURL: url, PlaintextKey: "k",
			BindingID: id, CredentialID: "c-" + id, Priority: prio, FallbackRole: role,
			RouteGroupID: "rg-rep", RouteGroupName: "reporting-chain", OrgID: "org-rep",
		}
	}
	primary := mk("anthropic", down.URL, "b-rep-down", 1, "primary")
	fallback := mk("mock", up.URL, "b-rep-up", 2, "fallback")
	container := *primary
	container.Bindings = []*vkeys.ResolvedRoute{primary, fallback}
	container.BaseURL, container.PlaintextKey = "", ""
	container.ProviderCode, container.ProtocolType = "", ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_rep": &container})

	proxySrv := httptest.NewServer(http.HandlerFunc(p.Handle))
	defer proxySrv.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, proxySrv.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_rep")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client got %d, want 200", resp.StatusCode)
	}

	// ── Wait for the upload, then assert on what crossed the wire ──────────
	var uploaded []map[string]any
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if uploaded = spy.uploadedEvents(); len(uploaded) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if fails := spy.failures(); len(fails) > 0 {
		t.Errorf("🔴 the proxy's uploads were REJECTED by the ingest contract: %v — the events "+
			"never reach a collector at all, and nothing in the proxy's own ledger would show it", fails)
	}
	if len(uploaded) < 2 {
		t.Fatalf("the collector received %d event(s), want 2 — the proxy decided a switch "+
			"(its in-process ledger has both hops) but did not REPORT both. A failover is then "+
			"invisible to billing and to the console.", len(uploaded))
	}

	// ── The switch must be reconstructable from the uploaded rows alone ────
	var traceIDs []string
	charged, sawFallbackMarker := 0, false
	for _, ev := range uploaded {
		if tid, _ := ev["trace_id"].(string); tid != "" {
			traceIDs = append(traceIDs, tid)
		}
		if reason, _ := ev["fallback_reason"].(string); reason != "" {
			sawFallbackMarker = true
		}
		in, out := numField(ev, "input_tokens"), numField(ev, "output_tokens")
		if in > 0 || out > 0 {
			charged++
			// 🔴 `provider_code`, NOT `served_provider`. The in-process ledger
			// (events.UsageEvent) and the uploaded shape (events.ReportableEvent)
			// name the serving vendor DIFFERENTLY, and only the uploaded one
			// reaches billing. Asserting the in-process name here produced a
			// confident, wrong "billing is unattributed" reading — pinned so the
			// next reader does not repeat it.
			if got, _ := ev["provider_code"].(string); got != "mock" {
				t.Errorf("the charged upload names provider_code=%q, want mock — billing would "+
					"be attributed to a vendor that refused the call", got)
			}
		}
	}
	if !sawFallbackMarker {
		t.Error("no uploaded event carries fallback_reason — downstream, the two rows read as two " +
			"unrelated calls and nothing records that a switch occurred")
	}
	if len(traceIDs) < 2 {
		t.Errorf("only %d uploaded event(s) carry a trace_id — without it the rows cannot be "+
			"re-assembled into one client request", len(traceIDs))
	} else if traceIDs[0] != traceIDs[1] {
		t.Errorf("uploaded rows carry DIFFERENT trace_ids (%s vs %s)", traceIDs[0], traceIDs[1])
	}
	if charged != 1 {
		t.Errorf("%d uploaded row(s) carry tokens, want exactly 1 — 🔴 the refused hop must not be "+
			"billed and the serving hop must be (F-12)", charged)
	}

	for i, ev := range uploaded {
		b, _ := json.Marshal(map[string]any{
			"binding_id": ev["binding_id"], "provider_code": ev["provider_code"],
			"fallback_attempt": ev["fallback_attempt"], "fallback_reason": ev["fallback_reason"],
			"input_tokens": ev["input_tokens"], "output_tokens": ev["output_tokens"],
			"trace_id": ev["trace_id"],
		})
		t.Logf("uploaded event %d: %s", i, b)
	}
	t.Logf("collector received %d event(s) across %d batch(es); charged=%d marker=%v",
		len(uploaded), len(spy.batches), charged, sawFallbackMarker)
}

func numField(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}
