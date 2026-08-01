package events

import (
	"encoding/json"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/usagehash"
)

// deriveKeyLabel's contract is the single place where RouteSource mis-population
// bites the UI: a route built without the right RouteSource falls through the
// `oauth/team/personal/personal_byok` switch and lands in the VK-id-prefix
// fallback, producing labels like `oauth:sessio` or `personal:my` instead of
// the user's email or alias. These tests pin each branch so a future caller
// forgetting the field gets loud feedback rather than a silent UI regression.
// (Historical prior art: bugfix/20260418-third-party-review-fixes.md and the
// re-review that caught the personal/team startup paths.)

func TestDeriveKeyLabel_OAuth_UsesIdentity(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:   "oauth",
		VirtualKeyID:  "oauth:session_abcdef12345678",
		OAuthIdentity: "user@example.com",
		KeyAlias:      "__oauth__",
	}
	if got := deriveKeyLabel(r); got != "user@example.com" {
		t.Fatalf("oauth: want email label, got %q", got)
	}
}

func TestDeriveKeyLabel_OAuth_FallsBackWhenIdentityMissing(t *testing.T) {
	// OAuth branch only hits the fallback when identity is empty — rare but
	// possible when the broker lookup raced with token creation.
	r := &vkeys.ResolvedRoute{
		RouteSource:  "oauth",
		VirtualKeyID: "oauth:session_abcdef12345678",
		KeyAlias:     "__oauth__",
	}
	if got := deriveKeyLabel(r); got != "oauth:sessio" {
		t.Fatalf("oauth-missing-identity: want VK prefix, got %q", got)
	}
}

func TestDeriveKeyLabel_Team_UsesAlias(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:  "team",
		VirtualKeyID: "vk_team_12345",
		KeyAlias:     "prod-shared",
	}
	if got := deriveKeyLabel(r); got != "prod-shared" {
		t.Fatalf("team: want alias, got %q", got)
	}
}

func TestDeriveKeyLabel_Personal_UsesAlias(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:  "personal",
		VirtualKeyID: "personal:my-anthropic-key",
		KeyAlias:     "my-anthropic-key",
	}
	if got := deriveKeyLabel(r); got != "my-anthropic-key" {
		t.Fatalf("personal: want alias, got %q", got)
	}
}

func TestDeriveKeyLabel_PersonalBYOK_UsesAlias(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:  "personal_byok",
		VirtualKeyID: "aikey_team_xxx",
		KeyAlias:     "anthropic-dev",
	}
	if got := deriveKeyLabel(r); got != "anthropic-dev" {
		t.Fatalf("personal_byok: want alias, got %q", got)
	}
}

// Regression guard: an empty RouteSource is the footprint of the bug class
// the third-party review found twice (OAuth first, then personal/team
// startup paths). When this fires in CI, the fix is at the ResolvedRoute
// *construction site*, not here — search for `&vkeys.ResolvedRoute{` under
// supervisor.go / proxy.go and ensure every literal sets RouteSource.
func TestDeriveKeyLabel_EmptyRouteSource_FallsThrough(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		// RouteSource deliberately empty — simulates a caller that forgot
		// to populate it. Should land in the VK-id-prefix fallback, *not*
		// silently use KeyAlias/OAuthIdentity (which would hide the bug).
		VirtualKeyID:  "personal:alias",
		KeyAlias:      "alias",
		OAuthIdentity: "would-be-email@example.com",
	}
	got := deriveKeyLabel(r)
	if got == "alias" || got == "would-be-email@example.com" {
		t.Fatalf("empty RouteSource should not unlock alias/identity path; got %q — "+
			"this means some caller is populating KeyAlias/OAuthIdentity without "+
			"RouteSource, which is the bug class we're guarding against", got)
	}
	if got != "personal:ali" {
		t.Fatalf("want VK prefix fallback, got %q", got)
	}
}

func TestDeriveKeyLabel_NilRoute_Empty(t *testing.T) {
	if got := deriveKeyLabel(nil); got != "" {
		t.Fatalf("nil route: want empty, got %q", got)
	}
}

// Verifies the prefix truncation handles short VK ids without panicking.
func TestDeriveKeyLabel_ShortVK_NoTruncation(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:  "oauth",
		VirtualKeyID: "short",
		// OAuthIdentity empty → fallback path
	}
	if got := deriveKeyLabel(r); got != "short" {
		t.Fatalf("short vk: want verbatim, got %q", got)
	}
}

// Regression guard for third-party review finding #3: path-prefix-routed
// (non-aikey_-namespace) personal requests through handlePathPrefixRoute must carry
// KeyAlias into the ResolvedRoute. Before the fix, tokenRoute was constructed
// WITHOUT KeyAlias — dropping the user-facing label and silently falling back
// to a truncated VirtualKeyID like "personal:my-…" instead of "my-kimi-key".
//
// This test mirrors the exact literal produced by the two fixed construction
// sites (proxy.go path-prefix, both aikey_team_/aikey_personal_ and legacy-active-key branches).
// A future refactor that drops KeyAlias from either literal will fail here
// even though the deriveKeyLabel unit tests continue passing.
func TestDeriveKeyLabel_PathPrefix_PersonalKey_CarriesAlias(t *testing.T) {
	// Literal shape: personal route constructed by handlePathPrefixRoute
	// after review finding #3 fix.
	r := &vkeys.ResolvedRoute{
		VirtualKeyID: "personal:my-kimi-key",
		RouteSource:  "personal",
		KeyAlias:     "my-kimi-key",
		ProviderCode: "kimi",
	}
	got := deriveKeyLabel(r)
	if got != "my-kimi-key" {
		t.Fatalf("path-prefix personal: want alias 'my-kimi-key', got %q — "+
			"if this fails, handlePathPrefixRoute dropped KeyAlias again; "+
			"search proxy.go for `ResolvedRoute{` and restore the field",
			got)
	}
}

// And the aikey-namespace variant of finding #3 — non-OAuth route-token path.
func TestDeriveKeyLabel_PathPrefix_TokenRoute_CarriesAlias(t *testing.T) {
	// Literal shape: tokenRoute produced by the namespace-authority dispatch branch of
	// handlePathPrefixRoute after the fix. OAuth uses "__oauth__" sentinel
	// which deriveKeyLabel explicitly ignores — we test the non-OAuth case.
	r := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk_abc123",
		RouteSource:  "team",
		KeyAlias:     "prod-shared-anthropic",
	}
	got := deriveKeyLabel(r)
	if got != "prod-shared-anthropic" {
		t.Fatalf("path-prefix token route: want alias, got %q", got)
	}
}

// TestBuildReportableEvent_AppPipelineFieldsIsolated pins AKL-207 §5.3
// close-out: the ReportableEvent shape (collector wire + WAL) must carry
// the 6 app-attribution fields when the request came through the App
// pipeline in isolated mode. Without these fields the central collector
// receives degrade-detector traffic with empty app_slug and the billing /
// usage dashboard cannot attribute it.
func TestBuildReportableEvent_AppPipelineFieldsIsolated(t *testing.T) {
	route := &vkeys.ResolvedRoute{
		VirtualKeyID:     "app:degrade-detector",
		RouteSource:      "app",
		ProviderCode:     "anthropic",
		AppSlug:          "degrade-detector",
		AppKind:          "first-party",
		AppKeyID:         "key-uuid-abc",
		FollowUserActive: false, // isolated mode
	}
	ev := BuildReportableEvent(&ReportOpts{
		EventID:    "evt-1",
		Route:      route,
		Model:      "claude-3-5-sonnet-20241022",
		StatusCode: 200,
	})
	if ev.AppSlug != "degrade-detector" {
		t.Errorf("AppSlug = %q, want degrade-detector", ev.AppSlug)
	}
	if ev.AppKeyID != "key-uuid-abc" {
		t.Errorf("AppKeyID = %q, want key-uuid-abc", ev.AppKeyID)
	}
	if ev.AppMode != "isolated" {
		t.Errorf("AppMode = %q, want isolated (FollowUserActive=false)", ev.AppMode)
	}
	if ev.BoundVia != "app:degrade-detector" {
		t.Errorf("BoundVia = %q, want app:degrade-detector", ev.BoundVia)
	}
	if ev.RequestedModel != "claude-3-5-sonnet-20241022" {
		t.Errorf("RequestedModel = %q, want claude-3-5-sonnet-20241022", ev.RequestedModel)
	}
	if ev.ResolvedProvider != "anthropic" {
		t.Errorf("ResolvedProvider = %q, want anthropic", ev.ResolvedProvider)
	}
}

// TestBuildReportableEvent_EgressExtJSON pins the durable per-request egress
// audit (B layer, 2026-07-19): when the route had an egress spec, the event's
// ext_json carries the egress block (applied/engine/fingerprint) — so a usage
// row can be traced to the egress it exited through. Personal direct traffic
// (engine "none") writes NO ext_json so the pre-existing wire is unchanged.
// 能红: remove the ExtJSON stamping in BuildReportableEvent → the egress block
// assertion fails.
func TestBuildReportableEvent_EgressExtJSON(t *testing.T) {
	route := &vkeys.ResolvedRoute{VirtualKeyID: "aikey_team_x", RouteSource: "team_managed", OrgID: "org1", ProviderCode: "openai", AccountID: "acc-1"}

	// With egress → ext_json.egress present.
	ev := BuildReportableEvent(&ReportOpts{
		EventID: "evt-eg", Route: route, StatusCode: 200,
		EgressApplied: true, EgressEngine: "mihomo", EgressFingerprint: "abc123def456",
	})
	m, ok := ev.ExtJSON.(map[string]any)
	if !ok {
		t.Fatalf("ExtJSON = %T, want map with egress block", ev.ExtJSON)
	}
	eg, ok := m["egress"].(map[string]any)
	if !ok {
		t.Fatalf("ext_json.egress missing: %+v", m)
	}
	if eg["applied"] != true || eg["engine"] != "mihomo" || eg["fingerprint"] != "abc123def456" {
		t.Errorf("egress block = %+v, want applied=true engine=mihomo fingerprint=abc123def456", eg)
	}

	// No egress (engine none) → ext_json omitted (wire unchanged for direct traffic).
	ev2 := BuildReportableEvent(&ReportOpts{
		EventID: "evt-direct", Route: route, StatusCode: 200,
		EgressApplied: false, EgressEngine: "none", EgressFingerprint: "",
	})
	if ev2.ExtJSON != nil {
		t.Errorf("direct traffic must write no ext_json, got %+v", ev2.ExtJSON)
	}
}

// TestBuildReportableEvent_AppPipelineFieldsFollowActive pins the
// follow-active variant — degrade-detector's expected steady-state mode
// (first-party, follow_user_active=true). AppMode + BoundVia must
// reflect "follow-active" + "default" so the central collector can
// distinguish "this app traffic used the user's currently-selected key"
// from "this app traffic used its own isolated key".
func TestBuildReportableEvent_AppPipelineFieldsFollowActive(t *testing.T) {
	route := &vkeys.ResolvedRoute{
		VirtualKeyID:     "app:degrade-detector",
		RouteSource:      "app",
		ProviderCode:     "anthropic",
		AppSlug:          "degrade-detector",
		AppKind:          "first-party",
		AppKeyID:         "key-uuid-xyz",
		FollowUserActive: true, // dynamic follow mode
	}
	ev := BuildReportableEvent(&ReportOpts{
		EventID:    "evt-2",
		Route:      route,
		Model:      "claude-3-5-sonnet-20241022",
		StatusCode: 200,
	})
	if ev.AppMode != "follow-active" {
		t.Errorf("AppMode = %q, want follow-active (FollowUserActive=true)", ev.AppMode)
	}
	if ev.BoundVia != "default" {
		t.Errorf("BoundVia = %q, want default (follow-active reads default profile)", ev.BoundVia)
	}
}

// TestBuildReportableEvent_LegacyRoutesOmitAppFields pins the regression
// gate — pre-Phase-4 callers (personal/team/oauth routes) must NOT have
// any of the 6 app fields populated, so omitempty drops them on JSON
// wire and pre-v5 collector consumers continue to parse correctly. If
// this test ever fails, the "if route.RouteSource == app" gate broke.
func TestBuildReportableEvent_LegacyRoutesOmitAppFields(t *testing.T) {
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-personal-1",
		RouteSource:  "personal",
		ProviderCode: "openai",
		// Even if a buggy caller set AppSlug, the gate must drop it.
		AppSlug:  "ghost-app",
		AppKeyID: "ghost-key",
	}
	ev := BuildReportableEvent(&ReportOpts{
		EventID:    "evt-3",
		Route:      route,
		Model:      "gpt-4o",
		StatusCode: 200,
	})
	if ev.AppSlug != "" || ev.AppKeyID != "" || ev.AppMode != "" || ev.BoundVia != "" || ev.RequestedModel != "" || ev.ResolvedProvider != "" {
		t.Errorf("legacy route leaked App fields: AppSlug=%q AppKeyID=%q AppMode=%q BoundVia=%q RequestedModel=%q ResolvedProvider=%q",
			ev.AppSlug, ev.AppKeyID, ev.AppMode, ev.BoundVia, ev.RequestedModel, ev.ResolvedProvider)
	}
}

// TestBuildReportableEvent_ProbeBearerFirstPartyAttribution pins
// BR-rc.5-54 (2026-05-25): probe pipeline events fired with a known
// first-party constant bearer MUST be attributed to that app via
// AppSlug, even though the probe URL itself carries no slug. Without
// this, the /user/apps/<slug> dashboard's `WHERE app_slug=...` filter
// drops every successful manual Trust Check probe and the user sees a
// misleading "no token consumption" picture.
//
// The other 5 App-pipeline fields (AppKeyID / AppMode / BoundVia /
// RequestedModel / ResolvedProvider) MUST stay empty for probe events
// — they're App-pipeline-specific (probe has no app_keys row, no
// profile binding, the alias is explicit in the URL). The dashboard
// reads AppSlug only, so this minimal attribution is enough; the
// other fields would inject false semantics for downstream consumers.
func TestBuildReportableEvent_ProbeBearerFirstPartyAttribution(t *testing.T) {
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "probe:FreySilvaqzs@qualityservice.com",
		RouteSource:  "probe",
		ProviderCode: "anthropic",
	}
	ev := BuildReportableEvent(&ReportOpts{
		EventID:     "evt-probe-1",
		Route:       route,
		BearerToken: "aikey_app_internal_degrade_detector_v1",
		Model:       "claude-opus-4-7",
		StatusCode:  200,
	})
	if ev.AppSlug != "degrade-detector" {
		t.Errorf("expected AppSlug=\"degrade-detector\" for first-party probe bearer; got %q", ev.AppSlug)
	}
	// Probe events MUST NOT carry App-pipeline-specific fields — they
	// don't have an app_keys row, no profile binding, no Mode A/B
	// dispatch. Only the slug attribution is meaningful for dashboard
	// filtering; anything else would invent semantics.
	if ev.AppKeyID != "" || ev.AppMode != "" || ev.BoundVia != "" || ev.RequestedModel != "" || ev.ResolvedProvider != "" {
		t.Errorf("probe attribution leaked App-pipeline-specific fields: AppKeyID=%q AppMode=%q BoundVia=%q RequestedModel=%q ResolvedProvider=%q",
			ev.AppKeyID, ev.AppMode, ev.BoundVia, ev.RequestedModel, ev.ResolvedProvider)
	}
}

// TestBuildReportableEvent_ProbeUnknownBearerNoAttribution pins the
// negative path: when a probe is fired with a bearer NOT in the
// first-party constant set (e.g. an `aikey_app_<64hex>` third-party
// bearer somehow reached probe, or a future caller misuses), we MUST
// NOT fabricate an AppSlug — empty result tells the dashboard to leave
// it in the "ungrouped probe traffic" bucket.
func TestBuildReportableEvent_ProbeUnknownBearerNoAttribution(t *testing.T) {
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "probe:my-alias",
		RouteSource:  "probe",
		ProviderCode: "anthropic",
	}
	ev := BuildReportableEvent(&ReportOpts{
		EventID:     "evt-probe-2",
		Route:       route,
		BearerToken: "aikey_app_unknown_third_party_xyz_64hex_xyz_64hex_xyz_64hex_xyz_64hex",
		Model:       "claude-opus-4-7",
		StatusCode:  200,
	})
	if ev.AppSlug != "" {
		t.Errorf("expected empty AppSlug for unknown bearer; got %q (don't fabricate attribution)", ev.AppSlug)
	}
}

// TestBuildReportableEvent_StampsContentHash verifies stage C: the proxy stamps
// a content hash over the metering tuple that the collector can recompute. The
// hash must equal an independent usagehash.Compute over the same values, prove
// scheme-known, and CHANGE when any metering field is corrupted (the silent-zero
// guard). Building the event via the real BuildReportableEvent (not a hand-rolled
// struct) is what makes this a true fence against client/server hash drift.
func TestBuildReportableEvent_StampsContentHash(t *testing.T) {
	route := &vkeys.ResolvedRoute{
		OrgID:        "personal",
		ProviderCode: "anthropic",
		RouteSource:  "personal",
	}
	opts := ReportOpts{
		EventID:                  "e-hash-1",
		Route:                    route,
		Model:                    "claude-opus-4-7",
		StatusCode:               200,
		InputTokens:              100,
		OutputTokens:             50,
		CacheReadInputTokens:     10,
		CacheCreationInputTokens: 20,
	}
	ev := BuildReportableEvent(&opts)

	if ev.ContentHash == "" {
		t.Fatal("ContentHash not stamped")
	}
	if !usagehash.SchemeKnown(ev.ContentHash) {
		t.Fatalf("ContentHash %q not a known scheme", ev.ContentHash)
	}
	// Independently recompute the same tuple — must match byte-for-byte. 方案 A:
	// InputTokens=100 is PURE; total_tokens = pure + cache_read(10) + cache_creation(20)
	// + output(50) = 180 (cache added back so total stays the full token count).
	want := usagehash.Compute(usagehash.Input{
		InputTokens: 100, OutputTokens: 50, TotalTokens: 180,
		CacheReadInputTokens: 10, CacheCreationInputTokens: 20,
		Model: "claude-opus-4-7", ProviderCode: "anthropic",
	})
	if ev.ContentHash != want {
		t.Fatalf("ContentHash = %s, want %s (client stamp must match server recompute)", ev.ContentHash, want)
	}

	// Corrupting a token value must change the stamp (the whole point of C).
	opts.OutputTokens = 0
	if BuildReportableEvent(&opts).ContentHash == ev.ContentHash {
		t.Fatal("output_tokens 50→0 did not change ContentHash — corruption would slip through")
	}
}

// TestBuildReportableEvent_RequestPathOnWire pins the 2026-07-15
// 非生成流量不进用量审计 contract: the wire event must carry the inbound
// request path (the FACT the projector's generation/non-generation
// classifier keys on), and must omit the field entirely when the caller
// didn't capture one (legacy shape — older consumers keep parsing).
func TestBuildReportableEvent_RequestPathOnWire(t *testing.T) {
	route := &vkeys.ResolvedRoute{VirtualKeyID: "vk-1", RouteSource: "team", OrgID: "org-1"}

	ev := BuildReportableEvent(&ReportOpts{
		EventID:     "evt-path",
		Route:       route,
		RequestPath: "/openai/v1/models",
		StatusCode:  200,
	})
	if ev.RequestPath != "/openai/v1/models" {
		t.Errorf("RequestPath = %q, want /openai/v1/models", ev.RequestPath)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, _ := wire["request_path"].(string); got != "/openai/v1/models" {
		t.Errorf(`wire request_path = %q, want "/openai/v1/models"`, got)
	}

	// Legacy shape: no path captured → field absent on the wire (omitempty).
	ev2 := BuildReportableEvent(&ReportOpts{EventID: "evt-nopath", Route: route, StatusCode: 200})
	b2, err := json.Marshal(ev2)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	var wire2 map[string]any
	if err := json.Unmarshal(b2, &wire2); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if _, present := wire2["request_path"]; present {
		t.Error("legacy event unexpectedly carries request_path on the wire")
	}
}

// The local UsageEvent and Collector ReportableEvent are two projections of
// one request. Removing either assignment in BuildReportableEvent must turn
// this fence red; otherwise ODS request-level investigations collapse back to
// seat/model guesses and cannot prove per-operation Team Usage continuity.
func TestBuildReportableEvent_PreservesRequestAndTraceCorrelation(t *testing.T) {
	route := &vkeys.ResolvedRoute{OrgID: "org-correlation", SeatID: "seat-correlation"}
	ev := BuildReportableEvent(&ReportOpts{
		EventID:    "event-correlation",
		RequestID:  "request-correlation",
		TraceID:    "trace-correlation",
		Route:      route,
		StatusCode: 200,
	})
	if ev.RequestID != "request-correlation" || ev.TraceID != "trace-correlation" {
		t.Fatalf("collector correlation drifted: request_id=%q trace_id=%q",
			ev.RequestID, ev.TraceID)
	}
}

// TestBuildReportableEvent_FallbackAttemptDistinguishesChainFromSingleShot pins
// the 2026-07-31 correction. Three values, three DIFFERENT meanings, and the
// middle one used to be erased:
//
//	0 (single-shot, no chain walked) → omitted  → NULL in the warehouse
//	1 (a chain WAS walked, primary)  → emitted  → 1
//	2 (a chain was walked, hop 2)    → emitted  → 2
//
// Attempt 1 was previously omitted too, as "the overwhelming majority, says
// nothing". That holds for single-shot traffic and not for a chain, and the two
// share one column — so a real staging run with a failing primary recorded
// {NULL, 2}: the failed hop's audit row was byte-identical to a row written
// before the field existed. The projector documents NULL as exactly that and
// warns the two would be "indistinguishable forever", so the producer was
// manufacturing the ambiguity the consumer forbids.
//
// 能红: restore `route.FallbackAttempt > 1` in reportable.go → the chain-primary
// case below reports nil and fails.
func TestBuildReportableEvent_FallbackAttemptDistinguishesChainFromSingleShot(t *testing.T) {
	build := func(attempt int) *int {
		return BuildReportableEvent(&ReportOpts{
			EventID:    "evt-fb",
			Route:      &vkeys.ResolvedRoute{VirtualKeyID: "vk-1", ProviderCode: "anthropic", FallbackAttempt: attempt},
			Model:      "claude-sonnet-4-5",
			StatusCode: 200,
		}).FallbackAttempt
	}

	if got := build(0); got != nil {
		t.Errorf("single-shot must omit fallback_attempt, got %d — a value on every row is one\n"+
			"more column readers learn to ignore, and then they ignore the row where it is a 2", *got)
	}
	got1 := build(1)
	if got1 == nil {
		t.Fatal("a chain's PRIMARY hop must report attempt=1.\n" +
			"nil here writes the same NULL the projector reserves for 'before this field existed',\n" +
			"so 'the primary was tried and failed' becomes indistinguishable from 'we have no record'.")
	}
	if *got1 != 1 {
		t.Errorf("chain primary attempt = %d, want 1", *got1)
	}
	got2 := build(2)
	if got2 == nil || *got2 != 2 {
		t.Errorf("chain hop 2 attempt = %v, want 2", got2)
	}
}
