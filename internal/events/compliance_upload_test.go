package events

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestUploadComplianceEvents_ReusesRouteAndCredential proves the team→master
// compliance upload reuses the SAME per-RouteSource URL + credential as usage
// reporting: it POSTs to <route>/v1/compliance/events with the route's bearer
// and a {"events":[...]} envelope. (update doc 20260603 §3)
func TestUploadComplianceEvents_ReusesRouteAndCredential(t *testing.T) {
	var (
		gotPath string
		gotAuth string
		gotBody []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(map[string][]string{"accepted_ids": {"ok"}})
	}))
	defer srv.Close()

	r, err := NewReporter(&ReporterConfig{
		CollectorRoutes:           map[string]string{"team": srv.URL},
		CollectorRouteCredentials: map[string]Credential{"team": &StaticTokenCredential{Token: "member-jwt-x"}},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	evs := [][]byte{[]byte(`{"event_id":"e1","action_taken":"block"}`), []byte(`{"event_id":"e2","action_taken":"mask"}`)}
	if err := r.UploadComplianceEvents(ctx, "team", evs); err != nil {
		t.Fatalf("UploadComplianceEvents: %v", err)
	}

	if gotPath != "/v1/compliance/events" {
		t.Errorf("path: got %q want /v1/compliance/events", gotPath)
	}
	if gotAuth != "Bearer member-jwt-x" {
		t.Errorf("auth: got %q want 'Bearer member-jwt-x' (route credential reused)", gotAuth)
	}
	var pb struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(gotBody, &pb); err != nil {
		t.Fatalf("body not valid JSON envelope: %v (%s)", err, gotBody)
	}
	if len(pb.Events) != 2 {
		t.Errorf("events: got %d want 2", len(pb.Events))
	}

	// Empty source / no route → error (fail-loud, not silent).
	if err := r.UploadComplianceEvents(ctx, "nope", evs); err == nil {
		t.Error("expected error when no route URL configured for source")
	}
}
