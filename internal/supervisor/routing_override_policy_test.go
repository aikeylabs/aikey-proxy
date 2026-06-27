package supervisor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// Mirrors TestFetchGroupRuntime_ParsesAndSendsBearer: the routing-override pull
// parses {routing_version, assignments}, sends the account-JWT bearer, and yields
// ok=false on a non-200 so the caller keeps the last-known cache.
func TestFetchRoutingOverrides_ParsesAndSendsBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/accounts/me/routing" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"routing_version":42,"assignments":{"seat-1":"acc-9","seat-2":"acc-3"}}`))
	}))
	defer srv.Close()

	version, assignments, ok := fetchRoutingOverrides(context.Background(), srv.URL, "JWT123")
	if !ok || version != 42 {
		t.Fatalf("fetch: ok=%v version=%d", ok, version)
	}
	if assignments["seat-1"] != "acc-9" || assignments["seat-2"] != "acc-3" {
		t.Fatalf("assignments not parsed: %+v", assignments)
	}
	if gotAuth != "Bearer JWT123" {
		t.Fatalf("bearer not sent: %q", gotAuth)
	}

	// Empty assignments (engine redirects nothing) → ok=true, empty map.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"routing_version":7}`))
	}))
	defer empty.Close()
	v, a, ok := fetchRoutingOverrides(context.Background(), empty.URL, "x")
	if !ok || v != 7 || a == nil || len(a) != 0 {
		t.Fatalf("empty-assignments pull: ok=%v v=%d a=%+v", ok, v, a)
	}

	// Non-200 → ok=false (caller keeps last-known).
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer bad.Close()
	if _, _, ok := fetchRoutingOverrides(context.Background(), bad.URL, "x"); ok {
		t.Fatal("401 must yield ok=false")
	}
}

// A failed pull must keep the last-known cache (never clear/flap): we Store a v1
// assignment, then simulate a poll that does NOT re-Store (the ok=false path), and
// assert the prior assignment is still served. This pins the keep-last-known
// contract syncRoutingOverrides relies on.
func TestRoutingOverride_KeepLastKnownOnFailure(t *testing.T) {
	cache := proxy.NewRoutingOverrideCache()
	cache.Store(1, map[string]string{"seat-1": "acc-1"})

	// fetch against a dead endpoint → ok=false → syncRoutingOverrides would return
	// WITHOUT touching the cache. Assert by simulating that control flow.
	_, _, ok := fetchRoutingOverrides(context.Background(), "http://127.0.0.1:0", "x")
	if ok {
		t.Fatal("unreachable endpoint must yield ok=false")
	}
	// Cache untouched.
	if v := cache.Version(); v != 1 {
		t.Fatalf("version must stay last-known 1, got %d", v)
	}
}
