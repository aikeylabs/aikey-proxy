package supervisor

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"

	_ "modernc.org/sqlite"
)

// ── cycle-level integration: the full production path per rail cycle ────────
// gate → control URL → credential (vault refresh_token + derived refresh URL)
// → fetch (real HTTP) → apply (cache) → persist (vault column) → state machine
// → sync-health file. Everything real except the master (httptest).

// addPlatformAccount gives the openable vault a platform_account row so the
// teamCredentialSource can mint (same table GetPlatformRefreshToken reads).
func addPlatformAccount(t *testing.T, dbPath, refreshToken string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE platform_account (
		id INTEGER PRIMARY KEY, refresh_token TEXT)`); err != nil {
		t.Fatalf("create platform_account: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO platform_account (id, refresh_token) VALUES (1, ?)`,
		refreshToken); err != nil {
		t.Fatalf("insert platform_account: %v", err)
	}
}

// mockMaster serves the token-refresh + routing endpoints like a real control
// service. `down` (atomic) simulates an outage without changing the URL.
func mockMaster(t *testing.T, name string, version int64, accountID string, down *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down != nil && down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case cliTokenRefreshPath:
			_, _ = fmt.Fprintf(w, `{"access_token":"tok-%s","expires_in":3600}`, name)
		case "/accounts/me/routing":
			if r.Header.Get("Authorization") != "Bearer tok-"+name {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = fmt.Fprintf(w,
				`{"routing_version":%d,"routes":[{"seat_id":"seat-1","group_id":"grp-1","account_id":"%s"}]}`,
				version, accountID)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newCycleHarness(t *testing.T) (*Supervisor, *railRunner, string) {
	t.Helper()
	t.Setenv("AIKEY_PROXY_OAUTH_GROUP_ENABLED", "1")
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	dbPath, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-a", "seat": "seat-1", "group": "grp-1", "override": ""},
	})
	addPlatformAccount(t, dbPath, "refresh-token-1")

	cfg := &config.Config{}
	cfg.Vault.Path = dbPath
	s := &Supervisor{
		cfg:              cfg,
		routingOverrides: proxy.NewRoutingOverrideCache(),
		teamCred:         &teamCredentialSource{},
		ctx:              context.Background(),
	}
	s.active.Store(&generation{vault: reader})
	s.railset = newRailSet(s.routingOverrideRail())
	return s, s.railset.rails[0], dbPath
}

// THE INCIDENT, as an integration test: the control URL drifts between cycles
// (server A dies, config now points at server B). The very next cycle must
// rebuild the credential against B, pull B's newer assignment, apply AND
// persist it — no restart, no reload, no manual step. 能红: bake the
// credential/URL at rail start (the old behavior) and cycle 2 still dials A →
// this test fails on the stale assignment.
func TestRailCycleIntegration_URLDriftSelfHeals(t *testing.T) {
	s, runner, dbPath := newCycleHarness(t)

	serverA := mockMaster(t, "A", 41, "acc-from-A", nil)
	t.Setenv("AIKEY_HUB_CONTROL_URL", serverA.URL)

	runner.cycle(s)
	if got := s.routingOverrides.Assignment("seat-1", "grp-1"); got != "acc-from-A" {
		t.Fatalf("cycle 1 assignment=%q want acc-from-A", got)
	}

	// Drift: A is gone; the config now names B (fresh URL, newer version).
	serverB := mockMaster(t, "B", 42, "acc-from-B", nil)
	defer serverB.Close()
	serverA.Close()
	t.Setenv("AIKEY_HUB_CONTROL_URL", serverB.URL)

	runner.cycle(s)
	if got := s.routingOverrides.Assignment("seat-1", "grp-1"); got != "acc-from-B" {
		t.Fatalf("post-drift assignment=%q want acc-from-B (rail did not self-heal onto the new URL)", got)
	}
	if v := s.routingOverrides.Version(); v != 42 {
		t.Fatalf("post-drift version=%d want 42", v)
	}
	// Persisted for the next restart, from the NEW server.
	if col := readOverrideColumn(t, dbPath, "vk-a"); !strings.Contains(col, "acc-from-B") {
		t.Fatalf("persisted column must carry the new assignment: %q", col)
	}
	// The rail is healthy again — visible state agrees.
	if st, _ := s.railHealthFor("routing_override"); st != "ok" {
		t.Fatalf("rail state=%q want ok after self-heal", st)
	}
}

// Outage semantics end-to-end: the master goes down mid-life → the rail turns
// STALE (visible in /status AND the statusline sync-health file) while the
// cache keeps serving the last-known assignment (offline-first); the master
// returns → one cycle recovers everything and removes the file.
func TestRailCycleIntegration_OutageKeepsLastKnownAndRecovers(t *testing.T) {
	s, runner, _ := newCycleHarness(t)

	var down atomic.Bool
	master := mockMaster(t, "M", 7, "acc-live", &down)
	defer master.Close()
	t.Setenv("AIKEY_HUB_CONTROL_URL", master.URL)

	runner.cycle(s)
	if got := s.routingOverrides.Assignment("seat-1", "grp-1"); got != "acc-live" {
		t.Fatalf("baseline assignment=%q want acc-live", got)
	}

	down.Store(true)
	for i := 0; i < railStaleAfterFailures; i++ {
		runner.cycle(s)
	}
	if st, secs := s.railHealthFor("routing_override"); st != "stale" || secs < 0 {
		t.Fatalf("after %d failed cycles state=%q want stale", railStaleAfterFailures, st)
	}
	// Offline-first: the data path still serves the last-known assignment.
	if got := s.routingOverrides.Assignment("seat-1", "grp-1"); got != "acc-live" {
		t.Fatalf("outage must keep last-known assignment, got %q", got)
	}
	// The statusline bypass file appeared on the transition.
	healthPath, _ := syncHealthPath()
	if _, err := os.Stat(healthPath); err != nil {
		t.Fatalf("stale transition must write the sync-health file: %v", err)
	}
	// /status snapshot carries the failure detail.
	snap := s.ControlPlaneSyncSnapshot()
	if st := snap["routing_override"]; st.State != "stale" || st.ConsecutiveFailures != railStaleAfterFailures || st.LastError == "" {
		t.Fatalf("/status snapshot wrong: %+v", st)
	}

	// Recovery: one healthy cycle heals state and removes the file.
	down.Store(false)
	runner.cycle(s)
	if st, _ := s.railHealthFor("routing_override"); st != "ok" {
		t.Fatalf("post-recovery state=%q want ok", st)
	}
	if _, err := os.Stat(healthPath); !os.IsNotExist(err) {
		t.Fatalf("recovery must remove the sync-health file, stat err=%v", err)
	}
}

// Reload convergence (§5.2): invalidate + kickAll make the NEXT cycle rebuild
// the credential even when the URL string is unchanged (e.g. same host, new
// refresh_token after re-login). Exercised at the same integration level.
func TestRailCycleIntegration_InvalidateRebuildsCredential(t *testing.T) {
	s, runner, _ := newCycleHarness(t)

	var mints atomic.Int32
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case cliTokenRefreshPath:
			mints.Add(1)
			_, _ = fmt.Fprintf(w, `{"access_token":"tok-M","expires_in":3600}`)
		case "/accounts/me/routing":
			_, _ = fmt.Fprintf(w, `{"routing_version":7,"routes":[{"seat_id":"seat-1","group_id":"grp-1","account_id":"acc-live"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer master.Close()
	t.Setenv("AIKEY_HUB_CONTROL_URL", master.URL)

	runner.cycle(s)
	runner.cycle(s)
	if got := mints.Load(); got != 1 {
		t.Fatalf("steady state must reuse the minted token (1 refresh), got %d", got)
	}
	// Reload's convergence hook: drop the credential → next cycle re-mints.
	s.teamCred.invalidate()
	runner.cycle(s)
	if got := mints.Load(); got != 2 {
		t.Fatalf("invalidate must force a rebuild on the next cycle, got %d refreshes", got)
	}
}
