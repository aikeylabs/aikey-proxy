package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
)

// Tests for GET /health/keys message disambiguation.
//
// GAP 4 (bugfix 2026-06-09-proxy-architecture-review-findings): a credential
// that exists but fails to resolve/decrypt used to collapse into the same
// "no active key configured" 200 response as the genuinely-no-key case, so a
// broken key was misreported as "not configured" and the only signal lived in
// logs. HealthKeys now splits the KeyChecksFn error case into a DISTINCT
// "key resolution failed: ..." message while keeping HTTP 200 (contract) and
// keeping len==0 → "no active key configured".

func getHealthKeys(t *testing.T, h *Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/health/keys", nil)
	rr := httptest.NewRecorder()
	h.HealthKeys(rr, req)
	return rr
}

func decodeHealthKeysMessage(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Keys    []any  `json:"keys"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body = %q", err, rr.Body.String())
	}
	return resp.Message
}

func TestHealthKeys_DecryptFailure_DistinctMessage(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.KeyChecksFn = func() ([]KeyCheckTarget, error) {
		return nil, errors.New("resolve personal key: cipher mismatch")
	}

	rr := getHealthKeys(t, h)

	// Contract preserved: still HTTP 200.
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (contract preserved); body = %q", rr.Code, rr.Body.String())
	}
	msg := decodeHealthKeysMessage(t, rr)
	if msg == "no active key configured" {
		t.Fatalf("decrypt failure must NOT be reported as 'no active key configured'; got %q", msg)
	}
	// The error-specific message must be present so the failure is externally readable.
	if want := "key resolution failed:"; !strings.Contains(msg, want) {
		t.Errorf("message = %q, want it to contain %q", msg, want)
	}
}

func TestHealthKeys_NoKey_KeepsNoActiveKeyMessage(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.KeyChecksFn = func() ([]KeyCheckTarget, error) {
		return nil, nil // no error, no targets → genuinely no key configured
	}

	rr := getHealthKeys(t, h)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	msg := decodeHealthKeysMessage(t, rr)
	if msg != "no active key configured" {
		t.Errorf("message = %q, want %q", msg, "no active key configured")
	}
}

func TestHealthKeys_NotWired_ServiceUnavailable(t *testing.T) {
	h := newHandlerForTest(&config.Config{}) // KeyChecksFn nil
	rr := getHealthKeys(t, h)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when KeyChecksFn is not wired", rr.Code)
	}
}
