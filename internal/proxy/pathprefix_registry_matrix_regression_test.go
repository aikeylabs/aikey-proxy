package proxy

// pathprefix_registry_matrix_regression_test.go — the five hard regressions the
// 2026-08-08 path-prefix routing fix (plan A) had to hold while fixing D-1/D-2.
//
// Context: `extractProviderFromPath` is the FIRST gate every data-plane request
// passes. Getting it wrong does not degrade one provider, it cuts off all of
// them, so the fix was accepted only against explicit regression bars. Each test
// below is one of those bars, in the order they were agreed:
//
//	1. the 8 providers that already worked keep working, and the vendor receives
//	   a BYTE-IDENTICAL path to before the fix
//	2. a base_url that carries only the SHORT prefix (what an older aikey wrote
//	   into users' shell env) still routes and still stitches correctly
//	3. `mock` is still not a URL namespace
//	4. brand aliases (`claude`, deprecated `kimi`, …) behave as before
//	5. App-pipeline paths still win over provider prefixes
//
// Bar 5 is held by TestHandle_AppPathTakesPrecedenceOverProviderPrefix
// (app_pipeline_wiring_test.go); asserted here only at the parser level so the
// two halves of the ordering invariant are visible together.
//
// Full evidence + the rejected alternative:
// workflow/CI/bugfix/20260808-provider-path-prefix-routing-registry-drift.md

import (
	"sort"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/providerregistry"
)

// ── BAR 1: shipped / already-working providers keep their exact upstream path ──

// shippedUpstreamPaths is the frozen "upstream received" column measured on
// 2026-08-08 BEFORE the fix, for the 8 providers that were already working.
//
// 🔴 These are golden values, not derived ones. The matrix test derives its
// expectation from the registry, which means a registry edit moves the
// expectation with it — exactly what you want for coverage of NEW providers, and
// exactly what you do NOT want for the guarantee "shipped providers did not
// move". So this table is written out by hand, on purpose, and a change to any
// line has to be justified as a product decision.
//
// anthropic + openai are GA. Their proxy_path is frozen and any change to their
// upstream path is a breaking change for every existing user.
var shippedUpstreamPaths = map[string]string{
	"anthropic":   "/v1/messages",
	"openai":      "/v1/chat/completions",
	"deepseek":    "/v1/chat/completions",
	"moonshot":    "/v1/chat/completions",
	"siliconflow": "/v1/chat/completions",
	"xai":         "/v1/chat/completions",
	// perplexity's route row declares version "" — Stitch drops the client's
	// version segment and attaches nothing.
	"perplexity": "/chat/completions",
	// kimi_code deliberately does NOT mirror upstream: proxy_path "kimi/v1" while
	// the vendor serves api.kimi.com/coding/v1. This row is the precedent the
	// whole "proxy_path is a client namespace" rule was generalized from, so it is
	// also the single most important row to keep byte-stable.
	"kimi_code": "/coding/v1/chat/completions",
}

func TestPathPrefix_ShippedProvidersUpstreamPathUnchanged(t *testing.T) {
	byCode := map[string]matrixCase{}
	for _, c := range deriveMatrixCases(t) {
		byCode[c.Code] = c
	}

	for code, wantUpstream := range shippedUpstreamPaths {
		c, ok := byCode[code]
		if !ok {
			t.Errorf("%s: no matrix case derived — the registry lost a provider that "+
				"was already in production use", code)
			continue
		}
		res := runMatrixCase(t, c)
		if res.Failure != "" {
			t.Errorf("%s: %s\n  This provider WORKED before the 2026-08-08 path-prefix fix. "+
				"Breaking it is worse than the bug that was being fixed.", code, res.Failure)
			continue
		}
		if res.MockPath != wantUpstream {
			t.Errorf("%s: vendor received %q, but before the fix it received %q.\n"+
				"  proxy_path   = %s\n  client sent  = %s\n"+
				"  The stripped path may change; the UPSTREAM path may not.",
				code, res.MockPath, wantUpstream, c.ProxyPath, c.RequestPath)
		}
	}
}

// TestPathPrefix_ShippedProxyPathsFrozen guards the two GA values at the source.
// The upstream-path test above would also catch a change, but only indirectly;
// this one names the actual invariant so the failure message points at the yaml.
func TestPathPrefix_ShippedProxyPathsFrozen(t *testing.T) {
	frozen := map[string]string{
		"anthropic": "anthropic",
		"openai":    "openai",
		// Deprecated but SHIPPED: old shell hooks wrote
		// KIMI_BASE_URL=…:27200/kimi/v1 into users' env. Unlike the six providers
		// whose mirrored proxy_path was corrected on 2026-08-08 (never GA, so no
		// env to break), this one cannot be changed without a dual-prefix window.
		"kimi_code": "kimi/v1",
	}
	reg := providerregistry.Default()
	for code, want := range frozen {
		got, ok := reg.ProxyPath(code)
		if !ok {
			t.Errorf("%s: missing from provider_registry.yaml", code)
			continue
		}
		if got != want {
			t.Errorf("%s: proxy_path = %q, want %q — this provider is SHIPPED. Users' "+
				"shell env already contains http://127.0.0.1:<port>/%s; changing it "+
				"silently breaks their clients. A change needs a deprecated dual-prefix "+
				"window, not an edit.", code, got, want, want)
		}
	}
}

// TestPathPrefix_NoProxyPathMirrorsUpstream is the forward-looking half of the
// D-2 fix: it stops the mirrored shape from coming back.
//
// The rule: after the leading `<code>` segment, a proxy_path may carry AT MOST a
// single version segment (/v1, /v3, /v4 …). Anything else is a mirror of the
// vendor's base path, which the proxy re-derives from provider_routes anyway, so
// mirroring it means the vendor receives it twice.
func TestPathPrefix_NoProxyPathMirrorsUpstream(t *testing.T) {
	for _, e := range providerregistry.Default().Entries() {
		proxyPath := strings.Trim(strings.TrimSpace(e.ProxyPath), "/")
		if proxyPath == "" {
			continue // mock — no client namespace at all
		}
		segs := strings.Split(proxyPath, "/")
		if len(segs) == 1 {
			continue // "<code>" — SDK appends the version itself
		}
		if len(segs) == 2 && isVersionSegment(segs[1]) {
			continue // "<code>/<version>" — canonical shape
		}
		t.Errorf("provider %q: proxy_path %q mirrors upstream path segments.\n"+
			"  proxy_path is a CLIENT namespace only: the proxy strips it whole and rebuilds\n"+
			"  the upstream path from provider_fingerprint.yaml's provider_routes row, so a\n"+
			"  mirrored segment reaches the vendor TWICE (defect D-2, 2026-08-08).\n"+
			"  Use %q or %q + the row's version segment instead.",
			e.Code, e.ProxyPath, e.Code, e.Code)
	}
}

func isVersionSegment(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ── BAR 2: legacy short-prefix base_urls in users' shell env still work ────────

// TestPathPrefix_LegacyShortPrefixStillRoutes covers the shape
// `http://127.0.0.1:<port>/<code>/v1/...` for providers whose proxy_path is NOT
// just `<code>`.
//
// Why it is a real shape and not a hypothetical: `aikey use` writes the base_url
// into the user's shell env / active.env, and that value survives an aikey
// upgrade. Anybody who ran `aikey use` while the registry said `moonshot/v1` and
// then upgraded still has the older string. A short prefix is also what a user
// types by hand when following a vendor's own docs.
//
// The interesting arm is a provider whose upstream version is NOT /v1 (zhipu /v4,
// doubao /v3): the client sends /v1 because that is the OpenAI-SDK convention,
// and Stitch must swap it for the row's real version instead of concatenating.
func TestPathPrefix_LegacyShortPrefixStillRoutes(t *testing.T) {
	byCode := map[string]matrixCase{}
	for _, c := range deriveMatrixCases(t) {
		byCode[c.Code] = c
	}

	cases := []struct {
		code         string
		requestPath  string
		wantUpstream string
	}{
		// proxy_path "moonshot/v1" — short prefix + client-supplied /v1.
		{"moonshot", "/moonshot/v1/chat/completions", "/v1/chat/completions"},
		// proxy_path "kimi/v1" — the deprecated brand prefix, short form.
		{"kimi_code", "/kimi/chat/completions", "/coding/v1/chat/completions"},
		// proxy_path "groq/v1" — short prefix, upstream base carries /openai.
		{"groq", "/groq/v1/chat/completions", "/openai/v1/chat/completions"},
		// proxy_path "zhipu/v4" — client sends the SDK-conventional /v1 while the
		// vendor serves /v4. Stitch must replace, not append.
		{"zhipu", "/zhipu/v1/chat/completions", "/api/paas/v4/chat/completions"},
		// proxy_path "doubao/v3" — same, /v3.
		{"doubao", "/doubao/v1/chat/completions", "/api/v3/chat/completions"},
		// proxy_path "qwen/v1" — upstream base carries /compatible-mode.
		{"qwen", "/qwen/v1/chat/completions", "/compatible-mode/v1/chat/completions"},
		// proxy_path "openrouter/v1" — upstream base carries /api.
		{"openrouter", "/openrouter/v1/chat/completions", "/api/v1/chat/completions"},
		// proxy_path "fireworks/v1" — upstream base carries /inference.
		{"fireworks", "/fireworks/v1/chat/completions", "/inference/v1/chat/completions"},
	}

	for _, tc := range cases {
		t.Run(tc.requestPath, func(t *testing.T) {
			base, ok := byCode[tc.code]
			if !ok {
				t.Fatalf("no matrix case derived for %q", tc.code)
			}
			c := base
			c.RequestPath = tc.requestPath
			c.ExpectedPath = tc.wantUpstream
			res := runMatrixCase(t, c)
			if res.Failure != "" {
				t.Fatalf("%s via legacy short prefix: %s\n"+
					"  A base_url already sitting in a user's shell env must keep working; the "+
					"short-prefix candidate in the derived table (proxy_path first segment + "+
					"canonical code) is what covers it.", tc.code, res.Failure)
			}
		})
	}
}

// ── BAR 3: mock is not a URL namespace ────────────────────────────────────────
//
// The positive assertion lives in
// TestExtractProviderFromPath_MockProviderHasNoClientNamespace
// (middleware_kimi_split_test.go). This one pins the DERIVATION rule that makes
// it true, so the guarantee does not depend on `mock` happening to be absent from
// some list: an empty proxy_path contributes NO candidate, not even the code.
func TestClientPathPrefixTable_EmptyProxyPathContributesNothing(t *testing.T) {
	tbl := buildClientPathPrefixTable([]providerregistry.Entry{
		{Code: "mock", ProxyPath: "", OAuthAliases: []string{"fake"}},
		{Code: "anthropic", ProxyPath: "anthropic", OAuthAliases: []string{"claude"}},
	})
	for _, c := range tbl.all() {
		if c.code == "mock" {
			t.Errorf("mock contributed prefix %q — a provider with an empty proxy_path must "+
				"never become a URL namespace (Mock credentials enter through /anthropic or "+
				"/openai according to their stored protocol)", c.prefix)
		}
	}
	if got, _ := extractProviderFromPath("/mock/v1/messages"); got != "" {
		t.Errorf("extractProviderFromPath(\"/mock/v1/messages\") = %q, want \"\"", got)
	}
}

// ── BAR 4: brand aliases behave as before ─────────────────────────────────────

func TestPathPrefix_BrandAliasesStillRoute(t *testing.T) {
	cases := []struct {
		path     string
		wantCode string
		why      string
	}{
		{"/claude/v1/messages", "anthropic",
			"`claude` has been an accepted path prefix since before the registry existed; " +
				"old active.env files contain it"},
		{"/kimi/v1/chat/completions", "kimi_code",
			"deprecated but SHIPPED — old shell hooks wrote KIMI_BASE_URL=…/kimi/v1 into " +
				"users' env, so removing it cuts off live traffic"},
		{"/gemini/v1beta/models", "google",
			"google is picker:false, which governs VISIBILITY only — existing credentials " +
				"must keep routing"},
		{"/glm/v1/chat/completions", "zhipu", "registry alias"},
		{"/grok/v1/chat/completions", "xai", "registry alias"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got, stripped := extractProviderFromPath(tc.path)
			if got != tc.wantCode {
				t.Errorf("extractProviderFromPath(%q) = %q, want %q — %s",
					tc.path, got, tc.wantCode, tc.why)
			}
			if stripped == tc.path {
				t.Errorf("extractProviderFromPath(%q) did not strip anything (stripped = %q)",
					tc.path, stripped)
			}
		})
	}
}

// ── BAR 5: reserved pipeline paths are not swallowed by the provider parser ────
//
// The ordering itself (probe → apps → provider prefix) is enforced in
// Handle and fenced by TestHandle_AppPathTakesPrecedenceOverProviderPrefix. This
// asserts the complementary half: no registry-derived prefix can ever claim one
// of those namespaces, so the ordering is a belt on top of a brace rather than
// the only thing standing between an app route and a provider route.
func TestClientPathPrefixTable_DoesNotClaimReservedNamespaces(t *testing.T) {
	reserved := []string{"apps", "probe", "v1", "health", "healthz", "metrics", "admin", "debug"}
	claimed := map[string]string{}
	for _, c := range clientPathPrefixes().all() {
		seg := c.prefix
		if i := strings.IndexByte(seg, '/'); i >= 0 {
			seg = seg[:i]
		}
		claimed[seg] = c.code
	}
	for _, r := range reserved {
		if code, bad := claimed[r]; bad {
			t.Errorf("provider %q claims the reserved first segment %q — a provider prefix "+
				"must never collide with a pipeline namespace", code, r)
		}
	}
}

// ── derivation invariants ─────────────────────────────────────────────────────

// TestClientPathPrefixTable_NoConflictingPrefixes asserts that no two providers
// want the same prefix.
//
// buildClientPathPrefixTable resolves such a clash first-wins so behavior stays
// deterministic, but first-wins on a real clash is a SILENT MISROUTE: one
// provider's traffic would be resolved with another's credential and base_url.
// The registry's own invariants (unique codes, aliases that cannot collide) make
// it unreachable today; this test is what keeps it unreachable.
func TestClientPathPrefixTable_NoConflictingPrefixes(t *testing.T) {
	type claim struct{ prefix, code string }
	var claims []claim
	for _, e := range providerregistry.Default().Entries() {
		proxyPath := strings.Trim(strings.TrimSpace(e.ProxyPath), "/")
		if proxyPath == "" {
			continue
		}
		cands := []string{proxyPath, e.Code}
		if i := strings.IndexByte(proxyPath, '/'); i >= 0 {
			cands = append(cands, proxyPath[:i])
		}
		cands = append(cands, e.OAuthAliases...)
		for _, c := range cands {
			c = strings.ToLower(strings.TrimSpace(c))
			if c == "" {
				continue
			}
			claims = append(claims, claim{prefix: c, code: e.Code})
		}
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].prefix < claims[j].prefix })

	owner := map[string]string{}
	for _, c := range claims {
		if prev, ok := owner[c.prefix]; ok && prev != c.code {
			t.Errorf("path prefix %q is claimed by BOTH %q and %q — the loser's traffic would "+
				"be resolved with the winner's credential and base_url. Fix the registry, not "+
				"the table builder.", c.prefix, prev, c.code)
			continue
		}
		owner[c.prefix] = c.code
	}
}

// TestClientPathPrefixTable_LongestPrefixFirst pins the ordering the D-2 fix
// depends on. Kept as a direct assertion because the failure mode of getting it
// wrong is not a crash — it is a silently doubled upstream path.
func TestClientPathPrefixTable_LongestPrefixFirst(t *testing.T) {
	tbl := clientPathPrefixes()
	for _, e := range providerregistry.Default().Entries() {
		proxyPath := strings.Trim(strings.TrimSpace(e.ProxyPath), "/")
		if proxyPath == "" {
			continue
		}
		seg := proxyPath
		if i := strings.IndexByte(seg, '/'); i >= 0 {
			seg = seg[:i]
		}
		bucket := tbl.candidatesFor(seg)
		if len(bucket) == 0 {
			t.Errorf("provider %q: no candidate bucket for first segment %q", e.Code, seg)
			continue
		}
		for i := 1; i < len(bucket); i++ {
			if len(bucket[i-1].prefix) < len(bucket[i].prefix) {
				t.Errorf("bucket %q is not longest-first: %q before %q. A shorter prefix "+
					"matching first is exactly defect D-2 — the surplus segments would be "+
					"handed to Stitch as client path and the vendor's base path duplicated.",
					seg, bucket[i-1].prefix, bucket[i].prefix)
			}
		}
	}
}

// TestClientPathPrefixTable_CoversEveryPickerProvider is the D-1 fence stated at
// the parser level: everything the CLI can offer must be routable. The matrix
// test proves the same thing end-to-end; this one fails with a message that
// points straight at the derivation when a registry row is shaped unexpectedly.
func TestClientPathPrefixTable_CoversEveryPickerProvider(t *testing.T) {
	for _, e := range providerregistry.Default().Entries() {
		if !e.Picker {
			continue
		}
		proxyPath := strings.Trim(strings.TrimSpace(e.ProxyPath), "/")
		if proxyPath == "" {
			t.Errorf("provider %q is picker:true with an empty proxy_path — the CLI has no "+
				"base_url to print for it", e.Code)
			continue
		}
		gotCode, stripped := extractProviderFromPath("/" + proxyPath + "/chat/completions")
		if gotCode != e.Code {
			t.Errorf("provider %q: extractProviderFromPath(\"/%s/chat/completions\") = %q, "+
				"want %q — it is selectable in the CLI picker but not routable, which returns "+
				"a 401 telling the user to use path-prefix routing they are already using "+
				"(defect D-1)", e.Code, proxyPath, gotCode, e.Code)
			continue
		}
		if stripped != "/chat/completions" {
			t.Errorf("provider %q: proxy_path %q was not stripped whole (left %q). The full "+
				"proxy_path must win over its own first segment, or the leftover segments "+
				"reach the vendor twice (defect D-2)", e.Code, proxyPath, stripped)
		}
	}
}
