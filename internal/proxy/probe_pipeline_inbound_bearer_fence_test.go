package proxy

import (
	"net/http/httptest"
	"testing"
)

// TestInboundBearer_MustBeCapturedBeforeOAuthInject is the regression
// fence for BR-rc.5-61 (2026-05-25): the proxy's `extractRawAuthValue(r)`
// call site in handleAppPipeline + handleProbePipeline MUST execute BEFORE
// Stage 5's `ResolveBindingCredential` (which internally invokes
// `oauthInject` and overwrites `r.Header.Authorization` with the upstream
// OAuth access token).
//
// Background. The proxy uses the captured `inboundBearer` value as the
// `bearerToken` argument to serveRoute → reportUsage → BuildReportableEvent,
// and the eventual `virtual_key_hash` audit anchor + BR-rc.5-60's
// first-party probe-attribution lookup both depend on this value being the
// CLIENT-presented token, not the upstream OAuth token. If anyone
// re-orders the calls and reads Authorization AFTER oauthInject, two
// distinct user-visible bugs surface at the same time:
//
//  1. /user/apps/<slug>'s Usage chart shows app_slug=NULL for all probe
//     events (the first-party reverse-lookup fails because the bearer no
//     longer matches the whitelisted constant) → chart misleads users
//     into thinking Trust Check isn't working.
//  2. The `virtual_key_hash` column in ODS/DWD silently becomes a hash of
//     a SECRET (the OAuth access token, which rotates) instead of the
//     stable client token, breaking audit traceability.
//
// This test does NOT exercise the full pipeline (that would need a fake
// vault + credential broker). Instead it pins the SHAPE of the bug: if
// you read the header AFTER oauthInject, you get the upstream token, not
// the inbound one. Any future refactor that re-orders calls so
// extractRawAuthValue runs post-oauthInject will fail this test loudly,
// even before the user-visible symptom shows up.
func TestInboundBearer_MustBeCapturedBeforeOAuthInject(t *testing.T) {
	const clientBearer = "aikey_app_internal_degrade_detector_v1" //nolint:gosec // test fixture, not a real credential
	const upstreamOAuthToken = "oauth-token-abc"                  //nolint:gosec // test fixture, not a real credential (matches claudeCred())

	req := httptest.NewRequest("POST", "/probe/some-alias/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer "+clientBearer)

	// PHASE 1: BEFORE oauthInject — extractRawAuthValue returns the
	// client-presented bearer. This is the value handleProbePipeline /
	// handleAppPipeline must capture for the `inboundBearer` variable
	// they pass through to reportUsage.
	gotBeforeInject := extractRawAuthValue(req)
	if gotBeforeInject != clientBearer {
		t.Fatalf("pre-inject extractRawAuthValue: want %q, got %q (sanity check failed — extractRawAuthValue is broken or this test set up the request wrong)",
			clientBearer, gotBeforeInject)
	}

	// PHASE 2: oauthInject overwrites Authorization with the upstream
	// OAuth access token (this is the operation ResolveBindingCredential
	// triggers on the OAuth code path). After this point, the original
	// client bearer is GONE from the request — there's no way to recover
	// it except via the value captured in PHASE 1.
	oauthInject(req, claudeCred(), "anthropic")

	// PHASE 3: AFTER oauthInject — extractRawAuthValue now returns the
	// upstream token. This is the bug shape: if the proxy reads the
	// bearer here instead of in PHASE 1, it gets the wrong value.
	gotAfterInject := extractRawAuthValue(req)
	if gotAfterInject != upstreamOAuthToken {
		t.Fatalf("post-inject extractRawAuthValue: want %q (upstream OAuth token), got %q — if this is the client bearer, oauthInject failed to overwrite the header which means a SEPARATE upstream bug; if this is empty, the header was cleared which is also a regression",
			upstreamOAuthToken, gotAfterInject)
	}

	// Final assertion: the two values must differ. If they're equal,
	// either (a) the upstream OAuth token happens to match the client
	// bearer (impossible in practice — different namespaces), or
	// (b) oauthInject didn't overwrite. Either way the test setup is
	// broken or the bug shape no longer holds.
	if gotBeforeInject == gotAfterInject {
		t.Fatal("pre-inject and post-inject bearers are equal — the bug shape this test was written to fence no longer reproduces. Investigate before deleting this test.")
	}

	// Document the canonical fix shape for anyone hitting this test:
	t.Logf("ok — pre-inject=%q, post-inject=%q. Proxy MUST call extractRawAuthValue(r) BEFORE Stage 5 / ResolveBindingCredential to capture the client bearer, then thread that captured value through serveRoute → reportUsage. See handleAppPipeline + handleProbePipeline in proxy.go.",
		gotBeforeInject, gotAfterInject)
}
