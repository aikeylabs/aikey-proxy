package events

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

// An EMPTY collector_routes entry means "this route has no destination — hold
// the events in the WAL", per EventsConfig.CollectorRoutes. It used to fall
// through to CollectorURL instead, which on a Personal install is the LOCAL
// collector — so an employee's TEAM usage was written into their PERSONAL
// database, silently and with no log. That inverts the isolation the per-route
// split exists to enforce (20260510-personal-team-数据隔离与合并显示.md), and
// downstream it wedged the Personal projector, which has no
// managed_key_control_events table to enrich a team VK from.
//
// 能红: restore the `&& u != ""` guard in urlForRouteSource and the team event
// lands on the local collector, failing this test with a count of 1.
func TestReporter_EmptyRouteDoesNotLeakToLocalCollector(t *testing.T) {
	var localCount, personalCount atomic.Int64
	mk := func(counter *atomic.Int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req batchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad", 400)
				return
			}
			counter.Add(int64(len(req.Events)))
			_ = json.NewEncoder(w).Encode(batchResponse{Accepted: len(req.Events)})
		}))
	}
	// localSrv stands in for the Personal install's own collector — the value
	// CollectorURL always holds there, and therefore the exact place team data
	// must never end up.
	localSrv := mk(&localCount)
	personalSrv := mk(&personalCount)
	defer localSrv.Close()
	defer personalSrv.Close()

	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL: localSrv.URL,
		CollectorRoutes: map[string]string{
			"personal": personalSrv.URL,
			// Present and EMPTY: the shipped template's state before
			// `aikey account login --control-url <REMOTE>` writes a team URL.
			"team":  "",
			"oauth": personalSrv.URL,
		},
		QueueCapacity:  100,
		WALDir:         t.TempDir(),
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	mkEvent := func(id, routeSource string) ReportableEvent {
		return ReportableEvent{
			EventID:       id,
			OrgID:         "org-real-team",
			RouteSource:   routeSource,
			EventTime:     aikeytime.Now(),
			OccurredAt:    aikeytime.Now(),
			RequestStatus: "success",
			RequestCount:  1,
		}
	}
	evTeam := mkEvent("team-1", "team")
	reporter.Report(&evTeam)
	// A personal event in the same batch proves the hold is scoped to the
	// unrouted source — "nothing uploads at all" would also pass the team
	// assertion, and would be a different (equally broken) product.
	evPersonal := mkEvent("personal-1", "personal")
	reporter.Report(&evPersonal)

	time.Sleep(300 * time.Millisecond)
	reporter.Close()

	if got := localCount.Load(); got != 0 {
		t.Errorf("the local collector received %d event(s) for an empty-routed source — "+
			"team usage leaked into the personal store; urlForRouteSource must treat an "+
			"empty route as 'no destination', not as 'fall back to CollectorURL'", got)
	}
	if got := personalCount.Load(); got != 1 {
		t.Errorf("personal collector got %d events, want 1 — the empty team route must not "+
			"stop the routes that ARE configured", got)
	}
}

// urlForRouteSource's three documented states, asserted directly so a future
// refactor cannot quietly collapse two of them into one.
func TestURLForRouteSource_ThreeStates(t *testing.T) {
	r := &Reporter{cfg: ReporterConfig{
		CollectorURL: "http://legacy-sink",
		CollectorRoutes: map[string]string{
			"personal": "http://personal-sink",
			"team":     "", // present + empty → no destination
		},
	}}
	cases := []struct{ name, route, want string }{
		{"present and non-empty → that URL", "personal", "http://personal-sink"},
		{"present and empty → no destination", "team", ""},
		{"absent → legacy CollectorURL fallback", "oauth", "http://legacy-sink"},
	}
	for _, c := range cases {
		if got := r.urlForRouteSource(c.route); got != c.want {
			t.Errorf("%s: urlForRouteSource(%q) = %q, want %q", c.name, c.route, got, c.want)
		}
	}
}

// A usage batch that reaches an aikey-proxy LLM gateway instead of a collector
// comes back as a plain 401, indistinguishable from a bad token — which is how
// a team member's uploads were dead-lettered for days with the only on-disk
// clue naming a component nobody expected in this path (bugfix 2026-08-20).
//
// 能红: drop the warnMisroutedCollectorOnce call in uploadGroupTo and the
// diagnostic disappears from the log.
func TestReporter_MisroutedCollectorIsNamed(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Byte-for-byte the shape aikey-proxy's own gateway returns.
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"TOKEN_MISSING","message":"AiKey: Missing virtual key.",` +
			`"type":"authentication_error"},"origin":"worker-proxy.TOKEN_MISSING"}`))
	}))
	defer gateway.Close()

	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   gateway.URL,
		QueueCapacity:  10,
		WALDir:         t.TempDir(),
		BatchSize:      5,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := ReportableEvent{
		EventID: "m1", OrgID: "o", RouteSource: "team",
		EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(),
		RequestStatus: "success", RequestCount: 1,
	}
	reporter.Report(&ev)
	time.Sleep(250 * time.Millisecond)
	reporter.Close()

	got := buf.String()
	if !strings.Contains(got, "usage.reporter.collector_misrouted") {
		t.Errorf("a usage batch was answered by an LLM gateway and the log never said so — "+
			"the operator sees only a generic 401. log was:\n%s", got)
	}
	if !strings.Contains(got, "COLLECTOR_URL_NOT_INGEST") {
		t.Errorf("diagnostic is missing its error code; log was:\n%s", got)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
