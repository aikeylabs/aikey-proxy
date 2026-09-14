package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestUploadAsyncComplianceBatch_NeverMixesWithFastLayer proves the blast-radius
// property: async events travel in their own POST, so an old master rejecting
// them cannot take the synchronous audit trail down.
func TestUploadAsyncComplianceBatch_NeverMixesWithFastLayer(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(b)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		// An OLD master: it refuses anything carrying the new field.
		if strings.Contains(string(b), "scan_coverage") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unknown field scan_coverage"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestReporterForURL(t, srv.URL)

	fast := [][]byte{mustJSON(t, map[string]any{"event_id": "au_1", "tenant_id": "org_a", "scenario": "compliance_scan"})}
	async := [][]byte{mustJSON(t, map[string]any{"event_id": "ar_1", "tenant_id": "org_a", "scenario": "async_rule_leak",
		"scan_coverage": map[string]any{"status": "partial", "scanned_bytes": 1, "total_bytes": 2}})}

	if err := r.UploadComplianceEvents(context.Background(), "team", fast); err != nil {
		t.Fatalf("the FAST-LAYER batch must succeed against an old master: %v", err)
	}
	// The async batch is expected to fail here — that is the point.
	_ = r.UploadAsyncComplianceBatch(context.Background(), "team", async)

	// POSITIVE CONTROL. Without it this test would be true by construction: two
	// calls obviously produce two posts. This proves the hazard the separation
	// exists to avoid is REAL — put the same two events in ONE batch and the old
	// master rejects the whole thing, taking the fast-layer event down with the
	// async one.
	if err := r.UploadComplianceEvents(context.Background(), "team", [][]byte{fast[0], async[0]}); err == nil {
		t.Error("positive control failed: a MIXED batch was accepted by the old master, so this test proves nothing " +
			"about why async events must be batched apart")
	} else {
		mu.Lock()
		mixed := bodies[len(bodies)-1]
		mu.Unlock()
		if !strings.Contains(mixed, "au_1") || !strings.Contains(mixed, "ar_1") {
			t.Errorf("positive control did not actually send both events together: %s", mixed)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("want three posts (fast, async, mixed control), got %d: %v", len(bodies), bodies)
	}
	// The first two posts (the ones the product actually makes) must each carry
	// only one kind. The third is the control and is expected to carry both.
	for i, b := range bodies[:2] {
		hasFast := strings.Contains(b, "au_1")
		hasAsync := strings.Contains(b, "ar_1")
		if hasFast && hasAsync {
			t.Errorf("post %d mixed fast-layer and async events; one old-master rejection would lose both: %s", i, b)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// newTestReporterForURL builds a real Reporter whose "team" compliance route
// points at srvURL. Real production code path — the test only supplies the
// destination.
func newTestReporterForURL(t *testing.T, srvURL string) *Reporter {
	t.Helper()
	r, err := NewReporter(&ReporterConfig{
		WALDir:          t.TempDir(),
		UploadInterval:  time.Hour, // keep the background loop idle
		CollectorURL:    srvURL,
		CollectorRoutes: map[string]string{"team": srvURL, "personal": srvURL},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
