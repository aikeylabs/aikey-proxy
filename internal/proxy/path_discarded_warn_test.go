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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

// ─────────────────────────────────────────────────────────────────────────────
// P4.7 / test-plan T-33 — the mixed-version manifest, driven through the real
// forwarding path rather than computed.
// ─────────────────────────────────────────────────────────────────────────────

// manifestRow mirrors pkg/providerroutes/testdata/mixed_version_affected_rows.json.
type manifestRow struct {
	Provider      string `json:"provider"`
	Protocol      string `json:"protocol"`
	StoredURL     string `json:"stored_base_url"`
	ClientPath    string `json:"client_path"`
	OldUpstream   string `json:"old_proxy_upstream"`
	NewUpstream   string `json:"new_proxy_upstream"`
	OldRouteKnown bool   `json:"old_route_known"`
}

// TestMixedVersion_ManifestDescribesWhatTheProxyActuallyDoes closes the gap
// between "we computed a difference" and "a request goes there".
//
// TestFence_I11 in pkg/providerroutes compares the two tables through Stitch.
// This drives a REAL request through serveRoute — adapter selection, rewrite,
// reverse proxy, the lot — against an httptest upstream that records the path it
// was actually asked for, and checks it against the same manifest.
//
// 🔴 Why the distinction is not pedantic: the manifest is what the release notes
// quote, and what an operator uses to decide which credentials to re-point during
// a staggered rollout. "Stitch would compute X" and "the proxy sends X" have been
// different things before — the response-truncation defect lived entirely in the
// gap between a computed value and a delivered one.
//
// The upstream host is rewritten to a local server per row, because the table is
// host-keyed and a test cannot dial api.deepseek.com. The PATH — the thing every
// assertion is about — is untouched.
func TestMixedVersion_ManifestDescribesWhatTheProxyActuallyDoes(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("..", "..", "..", "pkg", "providerroutes", "testdata", "mixed_version_affected_rows.json"))
	if err != nil {
		t.Fatalf("read mixed-version manifest: %v\n"+
			"  This test FAILS rather than skips: the manifest is what the release notes quote, "+
			"and an unchecked manifest is worse than none.", err)
	}
	var rows []manifestRow
	if err := json.Unmarshal(blob, &rows); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("manifest is empty — anti-vacuous assertion")
	}

	silent, loud := 0, 0
	for _, row := range rows {
		row := row
		t.Run(row.Provider+"/"+row.Protocol+row.PathPrefixSuffix(), func(t *testing.T) {
			stored, err := url.Parse(row.StoredURL)
			if err != nil {
				t.Fatalf("manifest stored_base_url does not parse: %v", err)
			}
			oldUp, err := url.Parse(row.OldUpstream)
			if err != nil {
				t.Fatalf("manifest old_proxy_upstream does not parse: %v", err)
			}

			var seen []string
			upstream := fenceUpstream(t, &seen)
			hostPort := strings.TrimPrefix(upstream.URL, "http://")

			// Rebuild the PRE-CASCADE table with this row's vendor host swapped for
			// the local one, so the same host-keyed matching happens.
			installOldTableWithHost(t, stored.Host, hostPort)

			logs := serveOnceCapturingLogsAt(t, "http://"+hostPort+stored.Path, upstream.URL, row.ClientPath, row.Protocol)

			if len(seen) == 0 {
				t.Fatalf("the upstream was never called — nothing about forwarding was proved")
			}
			got := seen[len(seen)-1]
			if got != oldUp.Path {
				t.Errorf("🔴 the manifest is WRONG for %s.\n"+
					"  it says an un-upgraded worker sends this to %q\n"+
					"  the proxy actually sent it to        %q\n"+
					"  Operators use this table to decide which credentials to re-point mid-rollout.",
					row.StoredURL, oldUp.Path, got)
			}

			// And the shape classification must match what actually gets logged.
			hasNotFound := strings.Contains(logs, "proxy.route.not_found")
			hasDiscarded := strings.Contains(logs, "proxy.route.path_discarded")
			if row.OldRouteKnown {
				silent++
				// Shape A: the host WAS known, so the pre-existing miss WARN cannot fire.
				// Before R-9 this produced no log line at all; that silence is the defect.
				if hasNotFound {
					t.Errorf("manifest classifies this as shape A (host known, path discarded) but the proxy logged proxy.route.not_found — the classification is wrong")
				}
				if !hasDiscarded {
					t.Errorf("shape A row produced NO proxy.route.path_discarded WARN. Pre-R-9 this failure was completely silent; the WARN is the entire mitigation.\n  logs:\n%s", logs)
				}
			} else {
				loud++
				// Shape B: brand-new host, degraded literal-prepend, duplicate version segment.
				if !hasNotFound {
					t.Errorf("manifest classifies this as shape B (unknown host) but no proxy.route.not_found WARN fired.\n  logs:\n%s", logs)
				}
				if !strings.Contains(got, doubledVersion(stored.Path)) && strings.Count(got, "/v1") < 2 && strings.Count(got, "/v4") < 2 && strings.Count(got, "/v2") < 2 && strings.Count(got, "/v3") < 2 {
					t.Logf("note: %s produced %q — no duplicated version segment, which is fine but worth reading", row.StoredURL, got)
				}
			}
		})
	}
	t.Logf("replayed %d manifest row(s) through the real forwarding path: %d shape A (silent), %d shape B (loud)", len(rows), silent, loud)
}

// PathPrefixSuffix keeps subtest names unique when one provider appears twice.
func (m manifestRow) PathPrefixSuffix() string {
	u, err := url.Parse(m.StoredURL)
	if err != nil || u.Path == "" {
		return ""
	}
	return strings.ReplaceAll(u.Path, "/", "_")
}

func doubledVersion(p string) string {
	for _, v := range []string{"/v1", "/v2", "/v3", "/v4"} {
		if strings.HasSuffix(p, v) {
			return v + v
		}
	}
	return "//"
}

// installOldTableWithHost rebuilds the PRE-CASCADE table from the frozen
// baseline fixture, swapping one vendor host for a local one.
//
// 🔴 Built from the fixture, not hand-written: a hand-written "old table" would
// drift from what the previous release actually embedded, and this test's whole
// claim is about what a real older binary does.
func installOldTableWithHost(t *testing.T, vendorHost, localHostPort string) {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("..", "..", "..", "pkg", "providerroutes", "testdata", "baseline_routes_pre_cascade.json"))
	if err != nil {
		t.Fatalf("read pre-cascade baseline: %v", err)
	}
	var entries []struct {
		Host       string `json:"host"`
		PathPrefix string `json:"path_prefix"`
		Protocol   string `json:"protocol"`
		Provider   string `json:"provider"`
		BaseURL    string `json:"base_url"`
		Version    string `json:"version"`
	}
	if err := json.Unmarshal(blob, &entries); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	var b strings.Builder
	b.WriteString("provider_routes:\n")
	for _, e := range entries {
		host := e.Host
		base := e.BaseURL
		if strings.EqualFold(host, vendorHost) {
			host = localHostPort
		}
		// Rewrite the base_url's host too, keeping its path.
		if u, err := url.Parse(base); err == nil && strings.EqualFold(u.Host, vendorHost) {
			u.Scheme = "http"
			u.Host = localHostPort
			base = u.String()
		}
		fmt.Fprintf(&b, "  - { host: %q, path_prefix: %q, protocol: %s, provider: %s, base_url: %q, version: %q }\n",
			host, e.PathPrefix, e.Protocol, e.Provider, base, e.Version)
	}
	installTable(t, b.String())
}

// serveOnceCapturingLogsAt is serveOnceCapturingLogs with an explicit client
// path and protocol, so each manifest row is replayed the way its own client
// would send it.
func serveOnceCapturingLogsAt(t *testing.T, storedBaseURL, upstreamURL, clientPath, protocol string) string {
	t.Helper()
	p := setupTestProxyWithStore(t, upstreamURL, &capturingEventStore{})
	adapter := protocol
	if adapter == "" {
		adapter = "openai_compatible"
	}
	prov, err := provider.NewRegistry().Get(adapter)
	if err != nil {
		t.Fatalf("get %s adapter: %v", adapter, err)
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-mv", Provider: adapter, ProtocolType: protocol,
		ProviderCode: "fencevendor", RouteSource: "team",
		BaseURL: storedBaseURL, PlaintextKey: "k",
		BindingID: "b-mv", CredentialID: "c-mv",
		Priority: 1, FallbackRole: "primary",
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	body := `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`
	r := httptest.NewRequest(http.MethodPost, clientPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.serveRoute(w, r, route, prov, "k", "", time.Now(), logger)
	return logBuf.String()
}
