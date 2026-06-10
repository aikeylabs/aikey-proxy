package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
