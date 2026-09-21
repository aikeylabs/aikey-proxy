package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

// GET /health: top-level Status is always liveness "ok" (200); the bypass
// usage pipeline verdict rides in usage_pipeline (缺口3). These tests pin both
// the liveness/pipeline split and the degrade triggers.

func getHealth(t *testing.T, h *Handler) (int, healthResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h.Health(rr, req)
	var resp healthResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	return rr.Code, resp
}

func TestHealth_NoPipelineWired_OmitsUsagePipeline(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	code, resp := getHealth(t, h)
	if code != http.StatusOK || resp.Status != "ok" {
		t.Fatalf("want 200 status=ok, got code=%d status=%q", code, resp.Status)
	}
	if resp.UsagePipeline != nil {
		t.Fatalf("usage_pipeline must be omitted when reporter+canary are not wired, got %+v", resp.UsagePipeline)
	}
}

func TestHealth_HealthyPipeline_ReportsOk(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.ReporterMetricsFn = func() *events.ReporterMetrics {
		return &events.ReporterMetrics{WALAppendFail: 0, ConsecutiveFailures: 0}
	}
	h.CanaryResultFn = func() *events.CanaryResult {
		return &events.CanaryResult{Status: "ok"}
	}
	code, resp := getHealth(t, h)
	if code != http.StatusOK || resp.Status != "ok" {
		t.Fatalf("want 200 status=ok, got code=%d status=%q", code, resp.Status)
	}
	if resp.UsagePipeline == nil || resp.UsagePipeline.State != "ok" || len(resp.UsagePipeline.Reasons) != 0 {
		t.Fatalf("want usage_pipeline state=ok no reasons, got %+v", resp.UsagePipeline)
	}
}

func TestHealth_WALAppendFailure_Degraded(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.ReporterMetricsFn = func() *events.ReporterMetrics {
		return &events.ReporterMetrics{WALAppendFail: 5}
	}
	code, resp := getHealth(t, h)
	// Liveness stays ok even though the bypass pipeline degraded.
	if code != http.StatusOK || resp.Status != "ok" {
		t.Fatalf("liveness must stay 200/ok on bypass degradation, got code=%d status=%q", code, resp.Status)
	}
	if resp.UsagePipeline == nil || resp.UsagePipeline.State != "degraded" {
		t.Fatalf("want usage_pipeline degraded, got %+v", resp.UsagePipeline)
	}
	if !hasReason(resp.UsagePipeline.Reasons, "wal_append_failed") {
		t.Fatalf("want reason wal_append_failed, got %v", resp.UsagePipeline.Reasons)
	}
}

func TestHealth_SustainedUploadFailure_Degraded(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.ReporterMetricsFn = func() *events.ReporterMetrics {
		return &events.ReporterMetrics{ConsecutiveFailures: uploadDegradedThreshold}
	}
	_, resp := getHealth(t, h)
	if resp.UsagePipeline == nil || resp.UsagePipeline.State != "degraded" ||
		!hasReason(resp.UsagePipeline.Reasons, "upload_failing") {
		t.Fatalf("want degraded+upload_failing at %d consecutive failures, got %+v", uploadDegradedThreshold, resp.UsagePipeline)
	}
	// Below threshold must NOT flap to degraded.
	h.ReporterMetricsFn = func() *events.ReporterMetrics {
		return &events.ReporterMetrics{ConsecutiveFailures: uploadDegradedThreshold - 1}
	}
	_, resp = getHealth(t, h)
	if resp.UsagePipeline == nil || resp.UsagePipeline.State != "ok" {
		t.Fatalf("a single transient blip below threshold must stay ok, got %+v", resp.UsagePipeline)
	}
}

func TestHealth_SustainedCanaryFailure_Degraded(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.CanaryResultFn = func() *events.CanaryResult {
		return &events.CanaryResult{Status: "failed", ConsecutiveFailures: canaryDegradedThreshold}
	}
	_, resp := getHealth(t, h)
	if resp.UsagePipeline == nil || resp.UsagePipeline.State != "degraded" ||
		!hasReason(resp.UsagePipeline.Reasons, "canary_pipeline_failed") {
		t.Fatalf("want degraded+canary_pipeline_failed, got %+v", resp.UsagePipeline)
	}
}

func hasReason(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Task 3.8 — GET /health must carry the org compliance-policy follower's
// verdict (R-compliance-grading-14.S2).
//
// Why on the ENDPOINT and not in a log: keeping the last valid grading ladder
// when the master's answer is unusable is the safe behavior, but it makes a
// machine enforcing a stale ladder indistinguishable from a healthy one. 「健康
// 信号必须可被外部读取」 forbids leaving that in a WARN line only.
// ---------------------------------------------------------------------------

// TestHealth_NoCompliancePolicyFollower_OmitsBlock: a proxy with no team/org
// never polls the compliance master, so the block is omitted rather than
// claiming "ok" for a follower that does not exist.
func TestHealth_NoCompliancePolicyFollower_OmitsBlock(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	_, resp := getHealth(t, h)
	if resp.CompliancePolicy != nil {
		t.Fatalf("compliance_policy must be omitted when the follower never polled, got %+v", resp.CompliancePolicy)
	}
	// Wired, but the follower has not polled (Personal / no org) — same answer.
	h.CompliancePolicyHealthFn = func() (int, bool) { return 0, false }
	_, resp = getHealth(t, h)
	if resp.CompliancePolicy != nil {
		t.Fatalf("compliance_policy must be omitted while the follower is idle, got %+v", resp.CompliancePolicy)
	}
}

// TestHealth_CompliancePolicyFollowing_ReportsOk: the follower polled and the
// last answer was usable — including ① "this master does not speak grading",
// which reaches this layer as zero rejects and must NOT read as a fault.
func TestHealth_CompliancePolicyFollowing_ReportsOk(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.CompliancePolicyHealthFn = func() (int, bool) { return 0, true }
	_, resp := getHealth(t, h)
	if resp.CompliancePolicy == nil || resp.CompliancePolicy.State != "ok" {
		t.Fatalf("want state=ok for a following proxy, got %+v", resp.CompliancePolicy)
	}
	if len(resp.CompliancePolicy.Reasons) != 0 {
		t.Fatalf("an ok verdict must carry no reasons, got %v", resp.CompliancePolicy.Reasons)
	}
}

// TestHealth_CompliancePolicyRejected_ReportsDegraded is the endpoint half of
// 3.A10: ONE unusable answer is already a divergence between what this machine
// enforces and what the console shows, so it goes degraded immediately — unlike
// the upload/canary lanes above, whose thresholds exist to ride out transport
// blips that mean nothing on their own.
//
// 能红 check: derive the verdict without the reason code, or leave the block off
// healthResponse (log-only), and these fail.
func TestHealth_CompliancePolicyRejected_ReportsDegraded(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.CompliancePolicyHealthFn = func() (int, bool) { return 1, true }
	_, resp := getHealth(t, h)
	if resp.CompliancePolicy == nil || resp.CompliancePolicy.State != "degraded" {
		t.Fatalf("want state=degraded on the first rejected policy, got %+v", resp.CompliancePolicy)
	}
	if !hasReason(resp.CompliancePolicy.Reasons, complianceGradingRejectedReason) {
		t.Fatalf("want reason %q so an operator knows WHICH signal is stale, got %v",
			complianceGradingRejectedReason, resp.CompliancePolicy.Reasons)
	}
	if resp.CompliancePolicy.ConsecutiveFailures != 1 {
		t.Fatalf("the streak must ride along so a blip and a sustained outage are "+
			"distinguishable from outside, got %+v", resp.CompliancePolicy)
	}

	// The usage pipeline is a separate lane and must not be dragged along —
	// 主链路/旁路 isolation, and a false restart of a healthy usage pipeline is
	// its own outage.
	if resp.UsagePipeline != nil {
		t.Fatalf("compliance degradation must not fabricate a usage_pipeline verdict, got %+v", resp.UsagePipeline)
	}
	if resp.Status != "ok" {
		t.Fatalf("top-level status stays liveness-only, got %q", resp.Status)
	}
}

// TestHealth_CompliancePolicyRawJSON pins the WIRE, not just the struct: the
// field names below are what an operator's monitor and the release E2E grep for.
func TestHealth_CompliancePolicyRawJSON(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.CompliancePolicyHealthFn = func() (int, bool) { return 4, true }
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h.Health(rr, req)
	for _, want := range []string{
		`"compliance_policy"`, `"state":"degraded"`,
		`"grading_policy_rejected"`, `"consecutive_failures":4`,
	} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("GET /health body is missing %s — the signal is not externally "+
				"readable.\nbody: %s", want, rr.Body.String())
		}
	}
}

// TestHealth_CompliancePolicyRefusedByDetector_ReportsDegraded — TODO-188 方案 C,
// 用户拍板 C.7-3. When the running detector refuses a grading change, the node
// keeps the previous document while the console shows the new one. That must be
// readable from outside, under its OWN reason code (the remedy is "upgrade the
// detector", not "fix the master's answer"), without a threshold, and it must
// clear when the refusal streak does. The raw wire string is pinned because it
// is what a monitor greps.
//
// 能红: drop the detectorRefusals branch → the degraded row fails.
// spec: R-compliance-grading-5.1
func TestHealth_CompliancePolicyRefusedByDetector_ReportsDegraded(t *testing.T) {
	h := newHandlerForTest(&config.Config{})
	h.CompliancePolicyHealthFn = func() (int, bool) { return 0, true } // the master's answer was fine
	refusals := 1
	h.GradingHotSwapRefusalsFn = func() int { return refusals }

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h.Health(rr, req)
	for _, want := range []string{`"state":"degraded"`, `"grading_policy_refused_by_detector"`, `"consecutive_failures":1`} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("GET /health is missing %s after a detector refusal.\nbody: %s", want, rr.Body.String())
		}
	}
	if strings.Contains(rr.Body.String(), `"grading_policy_rejected"`) {
		t.Fatalf("a detector refusal must not borrow the master-rejection reason.\nbody: %s", rr.Body.String())
	}

	refusals = 0
	_, resp := getHealth(t, h)
	if resp.CompliancePolicy == nil || resp.CompliancePolicy.State != "ok" {
		t.Fatalf("the verdict must clear with the streak, got %+v", resp.CompliancePolicy)
	}
}
