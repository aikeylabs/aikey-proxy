package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TestComplianceLocal_NodeShapeTeamRouteOnlySendsNothing fences TODO-119: the
// Cluster-node proxy config shape — `collector_routes` holds ONLY `team`, and the
// legacy `collector_url` is non-empty (both = the control-master gateway,
// workflow/CD/installer/cluster-install/cluster-install.sh collector_block) — has
// NO local self-view store, so neither local-lane method may send anything.
//
// The hole this closes: both methods used to ask urlForRouteSource("personal"),
// which falls back to CollectorURL when the key is ABSENT. On a node that
// fallback is master, so every team compliance batch was followed by a
// route_source-stamped "mirror" POSTed to master (whose strict decoder does not
// know route_source). Pre-existing fences only used configs with an explicit
// `personal` key, so this shape was never exercised.
//
// Negative control: the same config plus an explicit `personal` key must still
// deliver exactly one batch per call to that local store — the fix narrows the
// judgment to "explicit key", it does not switch the local lane off.
//
// bugfix: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/task-execution/TODO.md (TODO-119)
func TestComplianceLocal_NodeShapeTeamRouteOnlySendsNothing(t *testing.T) {
	evs := [][]byte{[]byte(`{"event_id":"e1","action_taken":"mask","tenant_id":"t"}`)}
	methods := []struct {
		name string
		call func(context.Context, *Reporter) error
	}{
		{"MirrorComplianceEventsLocally", func(ctx context.Context, r *Reporter) error {
			return r.MirrorComplianceEventsLocally(ctx, "team", evs)
		}},
		{"UploadComplianceEventsLocally", func(ctx context.Context, r *Reporter) error {
			return r.UploadComplianceEventsLocally(ctx, evs)
		}},
	}

	for _, m := range methods {
		t.Run(m.name+"/node shape: team key only + collector_url", func(t *testing.T) {
			collector, collectorHits := countingComplianceServer(t)
			team, teamHits := countingComplianceServer(t)
			dir := t.TempDir()
			r, err := NewReporter(&ReporterConfig{
				CollectorURL:    collector.URL,
				CollectorRoutes: map[string]string{"team": team.URL},
				WALDir:          dir,
				DBPath:          filepath.Join(dir, "events.db"),
			})
			if err != nil {
				t.Fatalf("NewReporter: %v", err)
			}
			t.Cleanup(func() { r.Close() })

			if err := m.call(context.Background(), r); err != nil {
				t.Fatalf("a host without an explicit personal route must be a silent no-op, got: %v", err)
			}
			if n := collectorHits.Load(); n != 0 {
				t.Fatalf("collector_url (master on a Cluster node) received %d request(s) from the local-only lane; "+
					"the absent `personal` key was resolved through the CollectorURL fallback", n)
			}
			if n := teamHits.Load(); n != 0 {
				t.Fatalf("the team route received %d request(s) from the local-only lane", n)
			}
			if got := readDeadLetterEntries(t, dir); len(got) != 0 {
				t.Fatalf("the local-only lane must never dead-letter; got %d entries", len(got))
			}
		})

		t.Run(m.name+"/negative control: explicit personal key", func(t *testing.T) {
			collector, collectorHits := countingComplianceServer(t)
			team, teamHits := countingComplianceServer(t)
			local, localHits := countingComplianceServer(t)
			dir := t.TempDir()
			r, err := NewReporter(&ReporterConfig{
				CollectorURL:    collector.URL,
				CollectorRoutes: map[string]string{"team": team.URL, "personal": local.URL},
				WALDir:          dir,
				DBPath:          filepath.Join(dir, "events.db"),
			})
			if err != nil {
				t.Fatalf("NewReporter: %v", err)
			}
			t.Cleanup(func() { r.Close() })

			if err := m.call(context.Background(), r); err != nil {
				t.Fatalf("local delivery: %v", err)
			}
			if n := localHits.Load(); n != 1 {
				t.Fatalf("the explicit personal route received %d batch(es), want exactly 1", n)
			}
			if c, tm := collectorHits.Load(), teamHits.Load(); c != 0 || tm != 0 {
				t.Fatalf("with an explicit personal route nothing else may be hit; collector_url=%d team=%d", c, tm)
			}
		})
	}
}

// countingComplianceServer is an accepting compliance intake that counts POSTs.
func countingComplianceServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string][]string{"accepted_ids": {"e1"}})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}
