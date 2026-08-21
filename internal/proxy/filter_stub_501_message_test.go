package proxy

// Fence for the fail-loud filter 501 body (bugfix 2026-08-19
// filterpipe-501-stale-copy): the client-visible message must carry the SAME
// facts the supervisor logs — real cause, expected path, an executable next
// step — and must never regress to the P3-era lies ("not implemented yet",
// "wait for the proxy build", "server-side", "temporary") that survived two
// months past the P4 dispatcher and sent a staging user chasing ghosts. The
// org-mandate flavor must NOT suggest clearing local settings (that cannot
// lift a mandate block).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandle_FilterStub501_RendersCausePerReason(t *testing.T) {
	staleLies := []string{
		"not implemented yet", "wait for the proxy build", "server-side", "temporary",
	}
	cases := []struct {
		name        string
		cause       FilterStubCause
		mustContain []string
		mustAbsent  []string
	}{
		{
			name: "mandate_not_installed",
			cause: FilterStubCause{
				Reason: FilterStubReasonMandateNotInstalled, Slug: "ai-compliance-detector",
				ExpectedPath: `C:\Users\u\.aikey\apps\ai-compliance-detector\bin\ai-compliance-detector.exe`,
				Mandated:     true,
			},
			mustContain: []string{
				"organization requires",
				"aikey app install ai-compliance-detector",
				"will not lift this block",
			},
			// A mandated block must not advertise any local disable exit.
			mustAbsent: []string{"filter-off", "compliance off"},
		},
		{
			name: "binary_missing_local_declaration",
			cause: FilterStubCause{
				Reason: FilterStubReasonBinaryMissing, Slug: "ai-compliance-detector",
				ExpectedPath: "/home/u/.aikey/apps/ai-compliance-detector/bin/ai-compliance-detector",
			},
			mustContain: []string{
				"binary was not found",
				"aikey app install ai-compliance-detector",
				"aikey compliance off",
			},
		},
		{
			name: "spawn_failed",
			cause: FilterStubCause{
				Reason: FilterStubReasonSpawnFailed, Slug: "ai-compliance-detector",
				ExpectedPath: "/home/u/.aikey/apps/ai-compliance-detector/bin/ai-compliance-detector",
			},
			mustContain: []string{"failed to start", "proxy logs", "aikey app install"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := setupTestProxy(t, "http://unused.invalid")
			cause := tc.cause
			p.SetFilterStub501(&cause)

			req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			p.Handle(w, req)

			if w.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501", w.Code)
			}
			body := w.Body.String()
			for _, want := range tc.mustContain {
				if !strings.Contains(body, want) {
					t.Errorf("body missing %q:\n%s", want, body)
				}
			}
			for _, lie := range append(append([]string{}, staleLies...), tc.mustAbsent...) {
				if strings.Contains(body, lie) {
					t.Errorf("body contains forbidden text %q:\n%s", lie, body)
				}
			}
			// Machine fields: additive reason_code + facts for tooling.
			var parsed struct {
				Error struct {
					ReasonCode   string `json:"reason_code"`
					FilterSlug   string `json:"filter_slug"`
					ExpectedPath string `json:"expected_path"`
					OrgMandated  bool   `json:"org_mandated"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("501 body is not JSON: %v\n%s", err, body)
			}
			if parsed.Error.ReasonCode != tc.cause.Reason {
				t.Errorf("reason_code = %q, want %q (body: %s)", parsed.Error.ReasonCode, tc.cause.Reason, body)
			}
			if parsed.Error.OrgMandated != tc.cause.Mandated {
				t.Errorf("org_mandated = %v, want %v", parsed.Error.OrgMandated, tc.cause.Mandated)
			}
			if parsed.Error.ExpectedPath != tc.cause.ExpectedPath {
				t.Errorf("expected_path = %q, want %q", parsed.Error.ExpectedPath, tc.cause.ExpectedPath)
			}
		})
	}
}
