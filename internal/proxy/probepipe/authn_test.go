package probepipe

import (
	"net/http"
	"testing"
)

// stubHeaders is a tiny RequestHeaders implementation backed by an http.Header
// — lets the test set arbitrary headers without constructing a full request.
type stubHeaders http.Header

func (s stubHeaders) Get(k string) string { return http.Header(s).Get(k) }

const validFirstPartyBearer = "aikey_app_internal_degrade_detector_v1" //nolint:gosec // test fixture, not a real credential

// TestAuthenticate_AcceptsAuthorizationBearer pins the happy path with the
// OpenAI-style header form.
func TestAuthenticate_AcceptsAuthorizationBearer(t *testing.T) {
	h := stubHeaders{}
	http.Header(h).Set("Authorization", "Bearer "+validFirstPartyBearer)
	if err := Authenticate(h); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// TestAuthenticate_AcceptsXApiKey pins the Anthropic-style header form (used
// by the Anthropic SDK and curl examples in the README).
func TestAuthenticate_AcceptsXApiKey(t *testing.T) {
	h := stubHeaders{}
	http.Header(h).Set("x-api-key", validFirstPartyBearer)
	if err := Authenticate(h); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// TestAuthenticate_RejectsMissingBearer enforces 401 PROBE_AUTH_FAILED on a
// request with no auth header.
func TestAuthenticate_RejectsMissingBearer(t *testing.T) {
	h := stubHeaders{}
	err := Authenticate(h)
	if err == nil {
		t.Fatalf("expected AuthError, got nil")
	}
	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", err.StatusCode)
	}
	if err.ErrorCode != "PROBE_AUTH_FAILED" {
		t.Errorf("error code: got %q, want PROBE_AUTH_FAILED", err.ErrorCode)
	}
}

// TestAuthenticate_RejectsUnknownBearer is the security-critical case: a
// strict-form app bearer that is NOT in the first-party whitelist must be
// rejected. We deliberately use a value with the well-known prefix to
// confirm the check is on the FULL token, not just the prefix.
func TestAuthenticate_RejectsUnknownBearer(t *testing.T) {
	h := stubHeaders{}
	http.Header(h).Set("Authorization",
		"Bearer aikey_app_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	err := Authenticate(h)
	if err == nil {
		t.Fatalf("expected AuthError, got nil")
	}
	if err.ErrorCode != "PROBE_AUTH_FAILED" {
		t.Errorf("error code: got %q, want PROBE_AUTH_FAILED", err.ErrorCode)
	}
}

// TestAuthenticate_AuthorizationTrumpsXApiKey verifies header precedence —
// when both are present, Authorization wins (mirrors apppipe convention).
func TestAuthenticate_AuthorizationTrumpsXApiKey(t *testing.T) {
	h := stubHeaders{}
	http.Header(h).Set("Authorization", "Bearer "+validFirstPartyBearer)
	http.Header(h).Set("x-api-key", "garbage")
	if err := Authenticate(h); err != nil {
		t.Fatalf("expected nil (Authorization should win), got %v", err)
	}
}
