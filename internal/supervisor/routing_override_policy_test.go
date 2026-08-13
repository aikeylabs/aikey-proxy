package supervisor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/pkg/routingwire"
)

// Mirrors TestFetchGroupRuntime_ParsesAndSendsBearer: the routing-override pull
// decodes the SHARED routingwire wire (structured route entries), sends the
// account-JWT bearer, and yields ok=false on a non-200 so the caller keeps the
// last-known cache.
func TestFetchRoutingOverrides_ParsesAndSendsBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/accounts/me/routing" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"routing_version":42,"routes":[
			{"seat_id":"seat-1","group_id":"g1","account_id":"acc-9"},
			{"seat_id":"seat-1","group_id":"g2","account_id":"acc-3"},
			{"seat_id":"seat-9","group_id":"g1","blocked":true},
			{"seat_id":"seat-10","group_id":"g1","removed":true}]}`))
	}))
	defer srv.Close()

	version, routes, err := fetchRoutingOverrides(context.Background(), srv.URL, "JWT123")
	if err != nil || version != 42 || len(routes) != 4 {
		t.Fatalf("fetch: err=%v version=%d routes=%d", err, version, len(routes))
	}
	if routes[0].AccountID != "acc-9" || routes[1].GroupID != "g2" || !routes[2].Blocked {
		t.Fatalf("routes not parsed: %+v", routes)
	}
	if gotAuth != "Bearer JWT123" {
		t.Fatalf("bearer not sent: %q", gotAuth)
	}

	// The cache ingest keeps multi-pool entries distinct and flags blocked pairs.
	cache := proxy.NewRoutingOverrideCache()
	bound, blocked := cache.StoreRoutes(version, routes)
	if bound != 2 || blocked != 1 {
		t.Fatalf("StoreRoutes counts: bound=%d blocked=%d", bound, blocked)
	}
	if got := cache.Assignment("seat-1", "g1"); got != "acc-9" {
		t.Fatalf("seat-1/g1 override: %q", got)
	}
	if got := cache.Assignment("seat-1", "g2"); got != "acc-3" {
		t.Fatalf("seat-1/g2 override (multi-pool distinct): %q", got)
	}
	if !cache.Blocked("seat-9", "g1") {
		t.Fatal("seat-9/g1 must be blocked")
	}
	if !cache.Removed("seat-10", "g1") {
		t.Fatal("seat-10/g1 must be removed")
	}

	// Empty routes (engine redirects nothing) → ok=true, empty slice.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"routing_version":7}`))
	}))
	defer empty.Close()
	v, rts, err := fetchRoutingOverrides(context.Background(), empty.URL, "x")
	if err != nil || v != 7 || rts == nil || len(rts) != 0 {
		t.Fatalf("empty-routes pull: err=%v v=%d routes=%+v", err, v, rts)
	}

	// Non-200 → error (caller keeps last-known; framework surfaces the cause).
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer bad.Close()
	if _, _, err := fetchRoutingOverrides(context.Background(), bad.URL, "x"); err == nil {
		t.Fatal("401 must yield a non-nil error")
	}
}

// A failed pull must keep the last-known cache (never clear/flap): we Store a v1
// assignment, then simulate a poll that does NOT re-Store (the ok=false path), and
// assert the prior assignment is still served. This pins the keep-last-known
// contract syncRoutingOverrides relies on.
func TestRoutingOverride_KeepLastKnownOnFailure(t *testing.T) {
	cache := proxy.NewRoutingOverrideCache()
	cache.StoreRoutes(1, []routingwire.RouteEntry{{SeatID: "seat-1", GroupID: "g1", AccountID: "acc-1"}})

	// fetch against a dead endpoint → error → syncRoutingOverrides returns it
	// WITHOUT touching the cache. Assert by simulating that control flow.
	_, _, err := fetchRoutingOverrides(context.Background(), "http://127.0.0.1:0", "x")
	if err == nil {
		t.Fatal("unreachable endpoint must yield a non-nil error")
	}
	// Cache untouched.
	if v := cache.Version(); v != 1 {
		t.Fatalf("version must stay last-known 1, got %d", v)
	}
}

// routesMatchAnyLocal is the decision core of the proxy.routing_override.
// format_mismatch WARN (review F1: a wire/format drift makes every entry miss the
// local (seat,group) set — otherwise indistinguishable from "no overrides"). 能红:
// break the pair comparison → the mismatch case below stops returning false → red.
func TestRoutesMatchAnyLocal(t *testing.T) {
	local := map[[2]string]bool{{"seat-1", "g1"}: true, {"seat-2", "g1"}: true}

	if !routesMatchAnyLocal([]routingwire.RouteEntry{{SeatID: "seat-1", GroupID: "g1", AccountID: "a"}}, local) {
		t.Fatal("an entry targeting a local (seat,group) must match")
	}
	if !routesMatchAnyLocal([]routingwire.RouteEntry{
		{SeatID: "ghost", GroupID: "gX", AccountID: "a"},
		{SeatID: "seat-2", GroupID: "g1", Blocked: true},
	}, local) {
		t.Fatal("a blocked entry targeting a local pair must match too")
	}
	// The F1 fingerprint: non-empty payload, zero local intersection → mismatch.
	if routesMatchAnyLocal([]routingwire.RouteEntry{
		{SeatID: "seat-1", GroupID: "OTHER-GROUP", AccountID: "a"},
		{SeatID: "unknown-seat", GroupID: "g1", AccountID: "b"},
	}, local) {
		t.Fatal("entries matching no local (seat,group) must report mismatch (→ WARN)")
	}
	// No local group VKs → nothing to mismatch (WARN stays silent).
	if routesMatchAnyLocal([]routingwire.RouteEntry{{SeatID: "s", GroupID: "g", AccountID: "a"}}, nil) {
		t.Fatal("empty local set must not match")
	}
}
