package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
)

// TestAppHealth_ReturnsWiredSnapshot verifies the happy path: the handler
// calls AppHealthFn and serializes its result to the JSON envelope the
// Web UI expects.
func TestAppHealth_ReturnsWiredSnapshot(t *testing.T) {
	t1 := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)
	fixture := []apppipe.AppHealth{
		{AppSlug: "alpha", LastCallAt: t1, StatusCode: 200},
		{AppSlug: "zeta", LastCallAt: t1.Add(time.Minute), StatusCode: 502, ErrorType: "bad_gateway"},
	}
	h := &Handler{AppHealthFn: func() []apppipe.AppHealth { return fixture }}

	req := httptest.NewRequest("GET", "/admin/apps/health", nil)
	rec := httptest.NewRecorder()
	h.AppHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var got AppHealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.Apps) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got.Apps))
	}
	if got.Apps[0].AppSlug != "alpha" || got.Apps[0].StatusCode != 200 {
		t.Errorf("first entry wrong: %+v", got.Apps[0])
	}
	if got.Apps[1].AppSlug != "zeta" || got.Apps[1].StatusCode != 502 || got.Apps[1].ErrorType != "bad_gateway" {
		t.Errorf("second entry wrong: %+v", got.Apps[1])
	}
}

// TestAppHealth_NilFn_Returns503 verifies the wiring guard: a Handler built
// without AppHealthFn (e.g. older binary, or a test harness) returns 503
// so the Web UI can distinguish "feature disabled" from "no data yet"
// (which would be 200 + empty array).
func TestAppHealth_NilFn_Returns503(t *testing.T) {
	h := &Handler{} // AppHealthFn left nil
	req := httptest.NewRequest("GET", "/admin/apps/health", nil)
	rec := httptest.NewRecorder()
	h.AppHealth(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when AppHealthFn nil, got %d", rec.Code)
	}
}

// TestAppHealth_EmptyResult_ReturnsEmptyArray verifies the "proxy started
// but no traffic yet" case: AppHealthFn returns nil or [] → the response
// is 200 + {"apps":[]} (not 200 + {"apps":null}). The Web UI's JSON
// decode pattern expects an array, not null.
func TestAppHealth_EmptyResult_ReturnsEmptyArray(t *testing.T) {
	for name, fn := range map[string]func() []apppipe.AppHealth{
		"nil":   func() []apppipe.AppHealth { return nil },
		"empty": func() []apppipe.AppHealth { return []apppipe.AppHealth{} },
	} {
		t.Run(name, func(t *testing.T) {
			h := &Handler{AppHealthFn: fn}
			req := httptest.NewRequest("GET", "/admin/apps/health", nil)
			rec := httptest.NewRecorder()
			h.AppHealth(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
			// Read raw bytes to confirm the JSON shape says "[]" not "null".
			body := rec.Body.String()
			if want := `"apps":[]`; !contains(body, want) {
				t.Errorf("expected response to contain %q, got %s", want, body)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
