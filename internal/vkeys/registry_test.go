package vkeys

import (
	"sync"
	"testing"
)

// Helpers for tests after Stage C-2.c removed Registry.Load (which took
// []config.VirtualKeyConfig). These tests now seed the registry via
// Merge / ReplaceAll using ResolvedRoute directly — the same path
// production code uses now that vault is the only route source.

// seedRoute builds a ResolvedRoute for tests. The bearer token is the
// map key in the registry, not a struct field, so it isn't included here.
func seedRoute(id, provider string) *ResolvedRoute {
	return &ResolvedRoute{
		VirtualKeyID: id,
		Provider:     provider,
		BaseURL:      "https://api." + provider + ".test/v1",
		KeyAlias:     provider + ":default",
		ProtocolType: provider,
		RouteSource:  "managed", // any non-deprecated source works for these tests
	}
}

func TestRegistry_ResolveAfterMerge(t *testing.T) {
	reg := NewRegistry()
	reg.Merge(map[string]*ResolvedRoute{
		"aikey_team_abc": seedRoute("vk1", "openai"),
		"aikey_team_def": withModels(seedRoute("vk2", "anthropic"), "claude-sonnet-4-5-20250929"),
	})

	route := reg.Resolve("aikey_team_abc")
	if route == nil {
		t.Fatal("expected route for aikey_team_abc")
	}
	if route.Provider != "openai" {
		t.Fatalf("expected provider openai, got %s", route.Provider)
	}
	if route.VirtualKeyID != "vk1" {
		t.Fatalf("expected vk1, got %s", route.VirtualKeyID)
	}

	route2 := reg.Resolve("aikey_team_def")
	if route2 == nil {
		t.Fatal("expected route for aikey_team_def")
	}
	if route2.Provider != "anthropic" {
		t.Fatalf("expected provider anthropic, got %s", route2.Provider)
	}

	if reg.Resolve("aikey_team_unknown") != nil {
		t.Fatal("expected nil for unknown token")
	}
	if reg.Count() != 2 {
		t.Fatalf("expected count 2, got %d", reg.Count())
	}
}

func TestRegistry_ReplaceAllRotatesEntries(t *testing.T) {
	reg := NewRegistry()
	reg.Merge(map[string]*ResolvedRoute{
		"token_a": seedRoute("vk1", "openai"),
	})
	if reg.Resolve("token_a") == nil {
		t.Fatal("expected route for token_a")
	}

	reg.ReplaceAll(map[string]*ResolvedRoute{
		"token_b": seedRoute("vk2", "anthropic"),
	})
	if reg.Resolve("token_a") != nil {
		t.Fatal("old token should be gone after ReplaceAll")
	}
	if reg.Resolve("token_b") == nil {
		t.Fatal("expected route for token_b after ReplaceAll")
	}
}

func TestRegistry_ConcurrentReads(t *testing.T) {
	reg := NewRegistry()
	reg.Merge(map[string]*ResolvedRoute{
		"aikey_team_concurrent": seedRoute("vk1", "openai"),
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if reg.Resolve("aikey_team_concurrent") == nil {
				t.Error("expected route")
			}
		}()
	}
	wg.Wait()
}

func TestResolvedRoute_IsModelAllowed(t *testing.T) {
	route := &ResolvedRoute{
		AllowedModels: []string{"gpt-4o-mini", "gpt-4.1"},
	}

	if !route.IsModelAllowed("gpt-4o-mini") {
		t.Fatal("gpt-4o-mini should be allowed")
	}
	if !route.IsModelAllowed("gpt-4.1") {
		t.Fatal("gpt-4.1 should be allowed")
	}
	if route.IsModelAllowed("gpt-4o") {
		t.Fatal("gpt-4o should not be allowed")
	}

	routeAll := &ResolvedRoute{}
	if !routeAll.IsModelAllowed("anything") {
		t.Fatal("empty allowlist should allow all")
	}
}

func withModels(r *ResolvedRoute, models ...string) *ResolvedRoute {
	r.AllowedModels = models
	return r
}
