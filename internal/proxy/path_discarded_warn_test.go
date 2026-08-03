package proxy

// path_discarded_warn_test.go — R-9 (2026-08-02, provider-credential-cascade).
//
// # The defect this fences
//
// A host's fallback route row (path_prefix "") matches ANY path. So an
// un-upgraded worker, whose embedded table does not yet carry the new
// `/anthropic` row, resolves a credential stored as
// `https://api.deepseek.com/anthropic/v1` to the plain deepseek row, DISCARDS
// the `/anthropic` segment, and posts an Anthropic-shaped body to the OpenAI
// endpoint.
//
// The pre-existing `proxy.route.not_found` WARN cannot catch it: that WARN fires
// on a host MISS, and this is a host HIT — `LookupByBaseURL` returns ok=true.
// The failure is therefore *completely silent*. The admin sees a malformed
// upstream error and has no way to tell it apart from a bad key.
//
// This change takes that shape from one provider (zhipu) to five, and has the
// console hand administrators exactly those URLs. R-9 was signed off on that
// basis: a rare latent trap was about to move onto the main road.
//
// 🔴 The two assertions below are equally load-bearing:
//   - the WARN fires in the discarding case, and
//   - it does NOT fire in the ordinary case.
//
// A WARN that fires for everyone is indistinguishable from no WARN at all — it
// gets filtered out within a week and the failure is silent again.

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// oldTableFallbackOnly is the "un-upgraded worker": the host is known, but only
// through its catch-all row. Anything extra in the stored path gets swallowed.
func oldTableFallbackOnly(t *testing.T, hostPort string) {
	t.Helper()
	installTable(t, "provider_routes:\n"+
		"  - { host: \""+hostPort+"\", protocol: openai_compatible, provider: fencevendor, base_url: \"http://"+hostPort+"\", version: \"/v1\" }\n")
}

// newTableWithExplicitPrefix is the upgraded worker: the /anthropic row exists,
// so nothing is discarded and the WARN must stay quiet.
func newTableWithExplicitPrefix(t *testing.T, hostPort string) {
	t.Helper()
	installTable(t, "provider_routes:\n"+
		"  - { host: \""+hostPort+"\", protocol: openai_compatible, provider: fencevendor, base_url: \"http://"+hostPort+"\", version: \"/v1\" }\n"+
		"  - { host: \""+hostPort+"\", path_prefix: \"/anthropic\", protocol: anthropic, provider: fencevendor, base_url: \"http://"+hostPort+"/anthropic\", version: \"/v1\" }\n")
}

func installTable(t *testing.T, yaml string) {
	t.Helper()
	tbl, err := providerroutes.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse test routing table: %v", err)
	}
	t.Cleanup(provider.OverrideRoutesForTest(tbl))
}

// serveOnceCapturingLogs drives the real serveRoute path with a capturing logger
// and returns everything it logged at WARN or above.
func serveOnceCapturingLogs(t *testing.T, storedBaseURL, upstreamURL string) string {
	t.Helper()
	p := setupTestProxyWithStore(t, upstreamURL, &capturingEventStore{})
	prov, err := provider.NewRegistry().Get("anthropic")
	if err != nil {
		t.Fatalf("get anthropic adapter: %v", err)
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-r9", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "fencevendor", RouteSource: "team",
		BaseURL: storedBaseURL, PlaintextKey: "k",
		BindingID: "b-r9", CredentialID: "c-r9",
		Priority: 1, FallbackRole: "primary",
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := httptest.NewRequest(http.MethodPost, "/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.serveRoute(w, r, route, prov, "k", "", time.Now(), logger)
	return logBuf.String()
}

// fenceUpstream answers anything with a minimal well-formed Anthropic response
// and records the path it was actually asked for.
func fenceUpstream(t *testing.T, seen *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":3,"output_tokens":1}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFence_R9_PathDiscardedWarnFiresOnTheSilentMisroute is the positive half.
func TestFence_R9_PathDiscardedWarnFiresOnTheSilentMisroute(t *testing.T) {
	var seen []string
	upstream := fenceUpstream(t, &seen)
	hostPort := strings.TrimPrefix(upstream.URL, "http://")
	oldTableFallbackOnly(t, hostPort)

	stored := "http://" + hostPort + "/anthropic/v1"
	logs := serveOnceCapturingLogs(t, stored, upstream.URL)

	if !strings.Contains(logs, "proxy.route.path_discarded") {
		t.Errorf("no proxy.route.path_discarded WARN for stored base_url %q.\n"+
			"  The /anthropic segment was dropped and the request went to the OpenAI endpoint,\n"+
			"  and nothing said so. That silence IS the defect R-9 exists to remove.\n"+
			"  captured logs:\n%s", stored, logs)
	}
	// The WARN must carry enough to diagnose without a second round trip.
	for _, field := range []string{"stored_base_url", "matched_row", "effective_upstream"} {
		if !strings.Contains(logs, field) {
			t.Errorf("WARN is missing %q — an operator cannot tell WHICH row swallowed the path.\n  logs:\n%s", field, logs)
		}
	}
	// 🔴 And the pre-existing host-miss WARN must NOT be the thing that fired:
	// if it did, the host was not actually known and this test is exercising the
	// other failure shape entirely.
	if strings.Contains(logs, "proxy.route.not_found") {
		t.Errorf("proxy.route.not_found fired — the host was NOT known, so this test is asserting the\n"+
			"  wrong failure shape (B, the loud one) rather than A, the silent one.\n  logs:\n%s", logs)
	}
}

// TestFence_R9_ForwardingIsUnchanged is P1d.3: R-9 adds a log line and nothing
// else. If the WARN had come with a behaviour change, the mitigation would have
// become a second, unreviewed routing decision.
func TestFence_R9_ForwardingIsUnchanged(t *testing.T) {
	var seen []string
	upstream := fenceUpstream(t, &seen)
	hostPort := strings.TrimPrefix(upstream.URL, "http://")
	oldTableFallbackOnly(t, hostPort)

	serveOnceCapturingLogs(t, "http://"+hostPort+"/anthropic/v1", upstream.URL)

	if len(seen) == 0 {
		t.Fatal("upstream was never called — the request did not get forwarded at all, so this test proves nothing about forwarding")
	}
	// The old (discarding) behaviour: /anthropic dropped, version re-attached.
	if got := seen[len(seen)-1]; got != "/v1/messages" {
		t.Errorf("forwarding CHANGED: upstream received %q, expected the unchanged discarding result %q.\n"+
			"  R-9 was signed off as log-only. Changing where requests go would make an\n"+
			"  observability fix into a silent routing change on every already-deployed worker.", got, "/v1/messages")
	}
}

// TestFence_R9_NoWarnWhenNothingIsDiscarded is the noise half, and the reason
// this file has three tests instead of one.
func TestFence_R9_NoWarnWhenNothingIsDiscarded(t *testing.T) {
	cases := []struct {
		name    string
		install func(*testing.T, string)
		stored  func(hostPort string) string
		why     string
	}{
		{
			name:    "upgraded worker knows the /anthropic row",
			install: newTableWithExplicitPrefix,
			stored:  func(h string) string { return "http://" + h + "/anthropic/v1" },
			why:     "an explicit prefix row matched on purpose; nothing was swallowed",
		},
		{
			name:    "ordinary credential on the fallback row",
			install: oldTableFallbackOnly,
			stored:  func(h string) string { return "http://" + h + "/v1" },
			why:     "the everyday case — if this warns, every request in the fleet warns",
		},
		{
			name:    "bare domain, no path at all",
			install: oldTableFallbackOnly,
			stored:  func(h string) string { return "http://" + h },
			why:     "the commonest shape in old data. The row ADDS path here, it discards nothing",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var seen []string
			upstream := fenceUpstream(t, &seen)
			hostPort := strings.TrimPrefix(upstream.URL, "http://")
			c.install(t, hostPort)

			logs := serveOnceCapturingLogs(t, c.stored(hostPort), upstream.URL)
			if strings.Contains(logs, "proxy.route.path_discarded") {
				t.Errorf("spurious proxy.route.path_discarded WARN: %s\n  logs:\n%s", c.why, logs)
			}
		})
	}
}
