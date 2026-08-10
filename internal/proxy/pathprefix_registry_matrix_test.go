package proxy

// pathprefix_registry_matrix_test.go — registry-derived end-to-end matrix for
// provider path-prefix routing (`aikey use` → /<proxy_path>/... → upstream).
//
// WHY THIS FILE EXISTS
//
// `aikey use <provider>` hands the client two values (aikey-cli
// executor.rs:build_run_env):
//
//	<X>_API_KEY   = aikey_active_<client_route>      (Tier-3 active sentinel)
//	<X>_BASE_URL  = http://127.0.0.1:<port>/<proxy_path>
//
// where <proxy_path> comes from provider_registry.yaml. The whole contract is
// therefore: `http://127.0.0.1:<port>/<proxy_path>` must be a DROP-IN
// REPLACEMENT for the vendor's real versioned base URL. Anything the client
// appends to one must land, byte-identical, on the other.
//
// Two independent hand-written lists used to sit between those two
// declarations. Both are gone as of 2026-08-08 (plan A); the defects they caused
// are what this file measures:
//
//	D-1  proxy/middleware.go extractProviderFromPath's `known[]` slice — the
//	     list of path prefixes the proxy would even recognise. Hand-written,
//	     16 entries against the registry's 28 picker:true providers, so 15 of
//	     them were selectable in the CLI picker and completely unroutable.
//	     FIXED: the prefix table is derived from provider_registry.yaml
//	     (pathprefix_table.go).
//	D-2  the prefix strip removed exactly ONE segment ("/"+code) while six
//	     `proxy_path` values MIRRORED the vendor's own base path
//	     (groq/openai/v1, zhipu/api/paas/v4, …). The leftover segments were
//	     handed to providerroutes.Stitch as if the client had sent them and
//	     Stitch re-prepended the row's canonical base path — so the vendor got
//	     it twice and answered 404. FIXED on both sides: the whole matched
//	     proxy_path is stripped (longest-prefix-wins), AND the six mirrored
//	     values were corrected to the canonical `<code>/<version>` shape.
//
// This test derives every case from the registry, so a provider added
// tomorrow is covered automatically. That auto-coverage IS the deliverable —
// a hard-coded provider list here would reproduce exactly the defect it is
// meant to catch.
//
// HOW THIS FILE IS LANDED
//
// It shipped in two halves while the defects were open, and both halves are kept
// now that they are closed:
//
//	default CI    TestPathPrefixMatrix_MatchesKnownDefectLedger — the matrix
//	              outcome must equal knownDefects EXACTLY. The ledger is now
//	              EMPTY, so this asserts "all 28 route and stitch correctly".
//	              It goes red when (a) a NEW provider drifts in (registry gained
//	              a row the derivation cannot serve), (b) a working provider
//	              regresses, or (c) somebody re-adds a ledger entry to excuse a
//	              regression.
//	`-tags pathprefix_matrix`
//	              TestPathPrefixMatrix_Strict (separate file) — same bar, stated
//	              directly, with the per-provider table printed.
//	              `make test-pathprefix-matrix`
//
// The five hard-regression bars the fix had to clear (shipped providers' upstream
// paths byte-identical, legacy short-prefix env still routing, `mock` still not a
// namespace, aliases unchanged, app-path precedence) live in
// pathprefix_registry_matrix_regression_test.go.
//
// 🚫 The assertions are NOT weakened anywhere. See
// workflow/CI/bugfix/20260808-provider-path-prefix-routing-registry-drift.md.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/pkg/providerregistry"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// ── case derivation ──────────────────────────────────────────────────────────

// matrixCase is one fully-derived expectation. Every field comes from
// provider_registry.yaml + provider_fingerprint.yaml; nothing is hand-written.
type matrixCase struct {
	Code        string // registry canonical code
	ProxyPath   string // registry proxy_path (what the CLI prints as base_url)
	Protocol    string // route row protocol
	ClientRoute string // "anthropic" | "openai" — what the sentinel names
	VaultBase   string // base_url the vault/console stores = EffectiveUpstream(row)

	RequestPath  string // what the client actually sends to the proxy
	ExpectedPath string // what the vendor must receive
}

// endpointSuffix is the endpoint a client appends to the VERSIONED base URL.
// Only two wire protocols reach path-prefix routing today; a third would fail
// loudly here rather than silently skip.
func endpointSuffix(protocol string) (string, bool) {
	switch protocol {
	case "anthropic":
		return "/messages", true
	case "openai_compatible":
		return "/chat/completions", true
	default:
		return "", false
	}
}

func clientRouteFor(protocol string) string {
	if protocol == "anthropic" {
		return "anthropic"
	}
	return "openai"
}

// deriveMatrixCases builds one case per picker:true registry provider.
//
// The derivation encodes the drop-in-replacement contract:
//
//	localBase  = "/" + proxy_path                        (what `aikey use` prints)
//	vendorBase = row.BaseURL + row.Version               (what the vendor serves)
//	The client appends the version segment ONLY when localBase does not already
//	carry it — this is the same rule aikey-cli main.rs `provider_needs_v1_hint`
//	applies when telling the user whether to add /v1.
//
// so:
//
//	RequestPath  = localBase [+ row.Version] + endpointSuffix
//	ExpectedPath = path(vendorBase)          + endpointSuffix
func deriveMatrixCases(t *testing.T) []matrixCase {
	t.Helper()
	reg := providerregistry.Default()
	table := provider.Routes()

	var cases []matrixCase
	for _, e := range reg.Entries() {
		if !e.Picker {
			continue // picker:false (mock, google) is not offered in the CLI picker
		}
		if strings.TrimSpace(e.ProxyPath) == "" {
			t.Errorf("registry: provider %q is picker:true but has an empty proxy_path — "+
				"the CLI cannot print a base_url for it", e.Code)
			continue
		}
		row, ok := table.LookupByBaseURL(e.DefaultBaseURL)
		if !ok {
			t.Errorf("registry/routes split: provider %q default_base_url %q has no provider_routes row; "+
				"the proxy cannot resolve a canonical upstream for it", e.Code, e.DefaultBaseURL)
			continue
		}
		suffix, ok := endpointSuffix(row.Protocol)
		if !ok {
			t.Errorf("provider %q route row declares protocol %q, which this matrix does not model; "+
				"add its endpoint suffix to endpointSuffix()", e.Code, row.Protocol)
			continue
		}

		localBase := "/" + strings.Trim(e.ProxyPath, "/")
		requestPath := localBase
		if row.Version != "" && !strings.HasSuffix(localBase, row.Version) {
			requestPath += row.Version
		}
		requestPath += suffix

		vendorBase := providerroutes.EffectiveUpstream(row)
		u, err := url.Parse(vendorBase)
		if err != nil {
			t.Errorf("provider %q: unparseable effective upstream %q: %v", e.Code, vendorBase, err)
			continue
		}
		cases = append(cases, matrixCase{
			Code:         e.Code,
			ProxyPath:    e.ProxyPath,
			Protocol:     row.Protocol,
			ClientRoute:  clientRouteFor(row.Protocol),
			VaultBase:    vendorBase,
			RequestPath:  requestPath,
			ExpectedPath: strings.TrimRight(u.Path, "/") + suffix,
		})
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Code < cases[j].Code })
	return cases
}

// ── upstream capture ─────────────────────────────────────────────────────────

// captureTransport is the ONLY thing this test mocks. It does not replace any
// proxy routing logic: the proxy has already resolved the credential, stitched
// the upstream URL and built the reverse-proxy Director by the time a request
// reaches here. The transport records the fully-stitched upstream URL (host +
// path exactly as the vendor would have seen it) and then re-points the TCP
// destination at a local httptest server so the response pipeline runs for
// real without touching the network.
type captureTransport struct {
	mock  *url.URL
	inner http.RoundTripper

	mu      sync.Mutex
	gotURL  string
	gotHost string
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.gotURL = req.URL.String()
	c.gotHost = req.URL.Host
	c.mu.Unlock()

	out := req.Clone(req.Context())
	out.URL.Scheme = c.mock.Scheme
	out.URL.Host = c.mock.Host
	out.Host = c.mock.Host
	return c.inner.RoundTrip(out)
}

func (c *captureTransport) snapshot() (upstreamURL, upstreamHost string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gotURL, c.gotHost
}

// upstreamResponseFor returns a minimal but protocol-shaped success body so the
// proxy's response adapters and usage extraction run their normal course.
func upstreamResponseFor(protocol string) string {
	if protocol == "anthropic" {
		return `{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
			`"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",` +
			`"usage":{"input_tokens":1,"output_tokens":1}}`
	}
	return `{"id":"chatcmpl-1","object":"chat.completion","model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
}

// matrixRequestModel is the model name every case sends.
//
// It must survive provider_model_maps: zhipu declares `unmatched: reject`, so
// an arbitrary name is refused by the model-mapping layer BEFORE forwarding and
// the case would report a routing failure that is really a fixture problem.
// "claude-opus-4-8" matches zhipu's literal rule (and its `opus` role rule), and
// is inert for every provider without a model map.
const matrixRequestModel = "claude-opus-4-8"

// ── the matrix ───────────────────────────────────────────────────────────────

type matrixResult struct {
	matrixCase
	Recognized   bool // proxy accepted the path-prefix route at all (D-1)
	Status       int
	UpstreamHost string
	UpstreamPath string
	MockPath     string
	Failure      string
}

func runMatrixCase(t *testing.T, c matrixCase) matrixResult {
	t.Helper()

	var mockPath string
	var mockMu sync.Mutex
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockMu.Lock()
		mockPath = r.URL.Path
		mockMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponseFor(c.Protocol)))
	}))
	defer mock.Close()
	mockURL, err := url.Parse(mock.URL)
	if err != nil {
		t.Fatalf("parse mock url: %v", err)
	}

	// Vault state == what `aikey add` + `aikey use <provider>` leave behind:
	// one personal API key bound to this provider, stored with the canonical
	// vendor base_url the console/CLI writes.
	alias := "matrix-" + c.Code
	av := &mockActiveVault{
		personalAlias:   alias,
		personalText:    "sk-matrix-" + c.Code,
		personalProv:    c.Code,
		personalBaseURL: c.VaultBase,
		providerBindings: map[string]*vault.ProviderBinding{
			c.Code: {
				ClientRoute:   c.Code,
				ProviderCode:  c.Code,
				ProtocolType:  c.Protocol,
				KeySourceType: "personal",
				KeySourceRef:  alias,
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	cap := &captureTransport{mock: mockURL, inner: http.DefaultTransport}
	p.SetTransport(cap)

	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],"max_tokens":8}`,
		matrixRequestModel)
	req := httptest.NewRequest(http.MethodPost, c.RequestPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Exactly what `aikey use` injects: the Tier-3 per-provider active sentinel.
	req.Header.Set("Authorization", "Bearer aikey_active_"+c.ClientRoute)
	w := httptest.NewRecorder()
	p.Handle(w, req)

	gotURL, gotHost := cap.snapshot()
	mockMu.Lock()
	gotMockPath := mockPath
	mockMu.Unlock()

	res := matrixResult{
		matrixCase:   c,
		Status:       w.Code,
		UpstreamHost: gotHost,
		UpstreamPath: gotURL,
		MockPath:     gotMockPath,
	}
	// "Recognized" == the request reached the path-prefix pipeline. When
	// extractProviderFromPath does not know the prefix the request falls to
	// token routing, which rejects an aikey_active_* sentinel with 401
	// TOKEN_INVALID and never touches the upstream.
	res.Recognized = gotHost != ""

	switch {
	case !res.Recognized:
		res.Failure = fmt.Sprintf("D-1 path prefix not recognized (status %d, body %s)",
			w.Code, strings.TrimSpace(w.Body.String()))
	case w.Code != http.StatusOK:
		res.Failure = fmt.Sprintf("status %d — %s", w.Code, strings.TrimSpace(w.Body.String()))
	case gotMockPath != c.ExpectedPath:
		res.Failure = fmt.Sprintf("D-2 upstream path mismatch: got %q, want %q", gotMockPath, c.ExpectedPath)
	}
	return res
}

func renderMatrix(results []matrixResult) string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%-16s %-26s %-34s %-38s %-38s %s\n",
		"PROVIDER", "PROXY_PATH", "CLIENT REQUEST PATH", "EXPECTED UPSTREAM", "ACTUAL UPSTREAM", "RESULT"))
	b.WriteString(strings.Repeat("─", 210) + "\n")
	for _, r := range results {
		actual := r.MockPath
		if !r.Recognized {
			actual = "(never reached upstream)"
		}
		verdict := "ok"
		if r.Failure != "" {
			verdict = r.Failure
		}
		b.WriteString(fmt.Sprintf("%-16s %-26s %-34s %-38s %-38s %s\n",
			r.Code, r.ProxyPath, r.RequestPath, r.ExpectedPath, actual, verdict))
	}
	return b.String()
}

func runWholeMatrix(t *testing.T) []matrixResult {
	t.Helper()
	cases := deriveMatrixCases(t)
	if len(cases) == 0 {
		t.Fatal("no picker:true providers derived from the registry — derivation is broken")
	}
	results := make([]matrixResult, 0, len(cases))
	for _, c := range cases {
		results = append(results, runMatrixCase(t, c))
	}
	return results
}

// ── KNOWN-DEFECT LEDGER ──────────────────────────────────────────────────────

type defectID string

const (
	// D-1 — extractProviderFromPath (middleware.go) USED TO CARRY a HAND-WRITTEN
	// `known[]` prefix list that did not derive from provider_registry.yaml.
	// A picker:true provider missing from that slice is invisible to
	// path-prefix routing: the request falls through to token routing, which
	// rejects the `aikey_active_*` sentinel `aikey use` just injected. The
	// resulting 401 tells the user to "use /<provider>/v1/... URL" — which is
	// exactly the URL they are already using. Effect: the provider is
	// selectable in the CLI picker and completely unusable.
	defectPrefixNotRecognized defectID = "D-1/prefix-not-in-known[]"

	// D-2 — the prefix strip REMOVED ONE segment ("/"+code) while `proxy_path`
	// could be multi-segment. The surplus segments survived into strippedPath,
	// providerroutes.Stitch treats them as client path and re-prepends the
	// row's own canonical base path — so the vendor receives its own base path
	// twice and answers 404.
	defectUpstreamPathDoubled defectID = "D-2/upstream-path-doubled"
)

// knownDefect pins ONE broken provider, including the exact wrong output. The
// observed path is recorded so a change in the failure SHAPE is also caught —
// "still broken" is not the same fact as "broken in the same way".
type knownDefect struct {
	Defect       defectID
	ObservedPath string // upstream path actually received; "" when it never got there
}

// knownDefects is the ledger.
//
// 🟢 EMPTY SINCE 2026-08-08 — both D-1 and D-2 are FIXED (plan A: the prefix
// table is derived from provider_registry.yaml with longest-prefix-wins
// matching, and the six proxy_path values that mirrored upstream path segments
// were corrected). All 28 picker:true providers route and stitch, so the ledger
// test below is now identical in strength to TestPathPrefixMatrix_Strict, and it
// runs in DEFAULT CI.
//
// 🚫 An empty ledger is the correct steady state — do NOT re-add entries to make
// a red build green. The ledger mechanism is kept (rather than deleted along with
// the defects) because it is what turns a future drift into a NAMED failure:
//
//	a new picker:true provider that does not route      → "NEW path-prefix
//	                                                       routing defect, not in
//	                                                       the ledger"
//	a working provider that starts sending a wrong path → same, with the exact
//	                                                       expected-vs-received
//	                                                       upstream paths printed
//
// The pre-fix contents (15 × D-1, 5 × D-2 + fireworks masked behind D-1, with
// each doubled upstream path recorded verbatim) are preserved in
// workflow/CI/bugfix/20260808-provider-path-prefix-routing-registry-drift.md.
var knownDefects = map[string]knownDefect{}

// TestPathPrefixMatrix_MatchesKnownDefectLedger is the DEFAULT-CI fence.
//
// It asserts that the set of broken providers, and the exact way each one is
// broken, is EXACTLY the recorded ledger. Since 2026-08-08 the ledger is EMPTY,
// so in practice it asserts "all 28 picker:true providers route and stitch".
// Drift in either direction is a failure:
//
//	provider broken but not in the ledger → new drift (most likely: a
//	  provider_registry.yaml row the derived prefix table cannot serve, e.g. a
//	  proxy_path that mirrors upstream segments again, or a missing
//	  provider_routes row)
//	provider in the ledger but now passing → a fix landed; prune the ledger
//	provider passing but broken differently → regression
func TestPathPrefixMatrix_MatchesKnownDefectLedger(t *testing.T) {
	results := runWholeMatrix(t)
	t.Log(renderMatrix(results))

	seen := map[string]bool{}
	for _, r := range results {
		seen[r.Code] = true
		want, listed := knownDefects[r.Code]

		if r.Failure == "" {
			if listed {
				t.Errorf("%s: is in the KNOWN-DEFECT ledger (%s) but now PASSES.\n"+
					"  If you fixed it: delete its entry from knownDefects in this file "+
					"and update workflow/CI/bugfix/20260808-provider-path-prefix-routing-registry-drift.md.",
					r.Code, want.Defect)
			}
			continue
		}

		if !listed {
			t.Errorf("%s: NEW path-prefix routing defect, not in the ledger.\n"+
				"  proxy_path      = %s\n"+
				"  client sent     = %s\n"+
				"  vendor expected = %s\n"+
				"  vendor received = %s\n"+
				"  failure         = %s\n"+
				"  Most likely causes: (a) proxy_path mirrors upstream path segments again "+
				"(the vendor then receives its base path twice — defect D-2; see "+
				"TestPathPrefix_NoProxyPathMirrorsUpstream), (b) the provider has no "+
				"provider_routes row, or (c) somebody re-introduced a hand-written prefix "+
				"list in place of the registry-derived table (pathprefix_table.go).",
				r.Code, r.ProxyPath, r.RequestPath, r.ExpectedPath, r.MockPath, r.Failure)
			continue
		}

		gotDefect := defectUpstreamPathDoubled
		if !r.Recognized {
			gotDefect = defectPrefixNotRecognized
		}
		if gotDefect != want.Defect {
			t.Errorf("%s: fails as %q, ledger records %q — the failure changed shape",
				r.Code, gotDefect, want.Defect)
		}
		if r.MockPath != want.ObservedPath {
			t.Errorf("%s: upstream received %q, ledger records %q — the failure changed shape",
				r.Code, r.MockPath, want.ObservedPath)
		}
	}

	for code := range knownDefects {
		if !seen[code] {
			t.Errorf("ledger lists %q but the registry no longer derives a case for it "+
				"(row removed or picker flipped to false) — prune the ledger", code)
		}
	}
}
