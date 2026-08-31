package proxy

// upstream_refusal_ledger_test.go — a request that NEVER REACHED an upstream
// must still leave a row in the usage ledger.
//
// # 🔴 The gap this closes (found by live E2E, 2026-08-31)
//
// On a real cluster node, a credential pointed at a dead address returned
// `502 UPSTREAM_ERROR` to the client and wrote an ERROR line to journald — and
// NOTHING to usage_event_ods. Meanwhile a credential whose upstream ANSWERED
// with 401 produced a complete ledger row (request_status=error,
// http_status_code=401, request_count=1, zero tokens, zero cost) that the
// console's ranking/timeline views already render.
//
// So the ledger's answer to "how many requests failed?" silently depended on
// WHICH KIND of failure it was, and the kind that means "we never got out of
// the building" was the invisible one. A customer console could not distinguish
// a quiet hour from a total outage.
//
// E2E: workflow/CI/e2e/cases/2026-08-31-cluster-node-forward-lands-in-usage-ledger.md
//
// # 🔴 Why this test drives a REAL request instead of calling the helper
//
// The defect was never in the emission helper — it was that the ErrorHandler's
// exits did not CALL one. A unit test over `reportUpstreamRefusal` would have
// been green on the day the bug shipped. This drives an actual client request
// at an actual dead port through the actual handler, and asserts on the bytes
// that reach a collector.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// deadUpstreamURL returns a URL that is guaranteed to refuse connections: a real
// listener is bound (so the port is real and the address is well-formed) and then
// closed, which is the closest in-process equivalent of the live defect's
// "connection refused" and cannot flake on a firewall.
func deadUpstreamURL(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := s.URL
	s.Close()
	return url
}

func TestEveryUpstreamRefusalReachesTheLedger(t *testing.T) {
	const token = "svc-token-refusal-test"
	spy := &collectorSpy{token: token}
	collector := httptest.NewServer(spy.handler())
	defer collector.Close()

	reporter, err := events.NewReporter(&events.ReporterConfig{
		WALDir:         t.TempDir(),
		CollectorURL:   collector.URL,
		CollectorToken: token,
		SourceID:       "src-refusal",
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

	p.registry.Merge(map[string]*vkeys.ResolvedRoute{
		"aikey_team_refusal": {
			VirtualKeyID: "vk-refusal", Provider: "anthropic", ProtocolType: "anthropic",
			ProviderCode: "anthropic", RouteSource: "team", BaseURL: deadUpstreamURL(t),
			PlaintextKey: "k", BindingID: "b-refusal", CredentialID: "c-refusal",
			OrgID: "org-refusal",
		},
	})

	proxySrv := httptest.NewServer(http.HandlerFunc(p.Handle))
	defer proxySrv.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, proxySrv.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_refusal")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// The client-facing half is unchanged by this fix and is asserted so a future
	// change cannot "fix" the ledger by turning a refusal into a 200.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("client got %d (%s), want 502 — a refused dial must still be a refusal",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var uploaded []map[string]any
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if uploaded = spy.uploadedEvents(); len(uploaded) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if fails := spy.failures(); len(fails) > 0 {
		t.Errorf("🔴 uploads REJECTED by the ingest contract: %v", fails)
	}
	if len(uploaded) == 0 {
		t.Fatalf("🔴 the client was told 502 and the ledger recorded NOTHING. " +
			"A deployment whose upstream is unreachable then looks, to every console view, " +
			"exactly like a deployment nobody is using.")
	}

	ev := uploaded[0]
	if got := ev["request_status"]; got != "error" {
		t.Errorf("request_status = %v, want \"error\" — a refused dial recorded as anything "+
			"else would be counted as served traffic", got)
	}
	if got := ev["error_code"]; got != observability.ErrCodeUpstreamError {
		t.Errorf("error_code = %v, want %q — the code is what separates \"never left the "+
			"building\" from \"the provider said no\"", got, observability.ErrCodeUpstreamError)
	}
	if got, want := jsonNumber(ev["http_status_code"]), float64(http.StatusBadGateway); got != want {
		t.Errorf("http_status_code = %v, want %v (the status the client actually received)", got, want)
	}
	// 🔴 The accounting claim. usage_fact_dwd feeds billing views; a failed dial
	// consumed nothing and must never carry tokens or money, but it IS one request.
	if got := jsonNumber(ev["request_count"]); got != 1 {
		t.Errorf("request_count = %v, want 1", got)
	}
	for _, k := range []string{"input_tokens", "output_tokens", "total_tokens"} {
		if got := jsonNumber(ev[k]); got != 0 {
			t.Errorf("%s = %v, want 0 — a request that never reached an upstream consumed nothing", k, got)
		}
	}
	if ev["virtual_key_id"] != "vk-refusal" || ev["credential_id"] != "c-refusal" {
		t.Errorf("attribution lost: vk=%v credential=%v — without it the console can say "+
			"\"something failed\" but not WHOSE key or WHICH upstream",
			ev["virtual_key_id"], ev["credential_id"])
	}
	// 🔴 The model. Without it the console buckets every refusal as "unknown
	// model" and the pricing layer marks the row UNPRICED (billable_amount NULL)
	// rather than zero — so the two kinds of failure still do not look alike in
	// the ledger, which is the whole point of this change. The answered-error
	// path gets the model from the request body it already parsed; this path has
	// to read the same cached value rather than re-parse a body it must not touch.
	if got := ev["model"]; got != "claude-sonnet-4-5" {
		t.Errorf("model = %v, want \"claude-sonnet-4-5\" — a refusal with no model is "+
			"unattributable in every per-model view and prices as UNPRICED, not as zero", got)
	}
	if s, _ := ev["trace_id"].(string); s == "" {
		t.Error("trace_id empty — it is the only thing that joins this row to the proxy's ERROR log line")
	}
}

// jsonNumber reads a JSON-decoded number (float64) defensively; a missing key
// reads as 0, which is what the zero-token assertions want anyway.
func jsonNumber(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

// TestAClientHangupIsNotAnUpstreamFailure pins the one exclusion that matters.
//
// httputil.ReverseProxy routes a client that hung up into the SAME ErrorHandler
// with context.Canceled. If those were recorded, the "requests that never went
// out" number — the number an operator would act on — would be dominated by the
// customer's own disconnects, and the signal this whole change exists to create
// would be worthless on its first busy day.
func TestAClientHangupIsNotAnUpstreamFailure(t *testing.T) {
	store := &capturingEventStore{}
	p := setupTestProxyWithStore(t, "http://unused.invalid", store)

	spy := &collectorSpy{token: "t"}
	collector := httptest.NewServer(spy.handler())
	defer collector.Close()
	reporter, err := events.NewReporter(&events.ReporterConfig{
		WALDir: t.TempDir(), CollectorURL: collector.URL, CollectorToken: "t",
		SourceID: "src-cancel", BatchSize: 1, UploadInterval: 20 * time.Millisecond,
		QueueCapacity: 10,
	})
	if err != nil {
		t.Fatalf("build reporter: %v", err)
	}
	defer reporter.Close()
	p.SetReporter(reporter, "pi", "0.0.0-test", "cfg", 0, "")

	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-cancel", ProviderCode: "anthropic", ProtocolType: "anthropic",
		RouteSource: "team", CredentialID: "c-cancel", OrgID: "org-cancel",
	}
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://x/v1/messages", nil)

	p.reportUpstreamRefusal(r, route, "k", "b", time.Now(),
		http.StatusBadGateway, observability.ErrCodeUpstreamError, context.Canceled)

	time.Sleep(300 * time.Millisecond)
	if got := spy.uploadedEvents(); len(got) != 0 {
		t.Fatalf("a client hangup produced %d ledger row(s), want 0 — the failure view would "+
			"then count the customer's own disconnects as upstream outages", len(got))
	}
}
