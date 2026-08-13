package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompliancePacksExposesFilterPerformance(t *testing.T) {
	h := &Handler{
		EffectivePacksFn: func(context.Context) ([]byte, error) {
			return []byte(`{"action_policy":{"bundle_sha256":"bundle"}}`), nil
		},
		FilterPerformanceFn: func() ComplianceFilterPerformance {
			return ComplianceFilterPerformance{
				WindowSize: 2048,
				Incremental: ComplianceFilterLatencyLane{
					Count: 20, WindowSamples: 20, P50Ms: 2.1, P95Ms: 3.4, Under15MsPercent: 100,
				},
			}
		},
	}
	recorder := httptest.NewRecorder()
	h.CompliancePacks(recorder, httptest.NewRequest(http.MethodGet, "/admin/compliance/packs", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var got CompliancePacksEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Available || got.Performance == nil || got.Performance.Incremental.P95Ms != 3.4 {
		t.Fatalf("performance health surface drift: %+v", got)
	}
}

func TestCompliancePacksKeepsPerformanceWhenDetectorReportUnavailable(t *testing.T) {
	h := &Handler{FilterPerformanceFn: func() ComplianceFilterPerformance {
		return ComplianceFilterPerformance{WindowSize: 2048}
	}}
	recorder := httptest.NewRecorder()
	h.CompliancePacks(recorder, httptest.NewRequest(http.MethodGet, "/admin/compliance/packs", nil))
	var got CompliancePacksEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Available || got.Performance == nil || got.Performance.WindowSize != 2048 {
		t.Fatalf("unavailable detector must not hide the performance health surface: %+v", got)
	}
}
