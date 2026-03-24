package vkeys

import (
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
)

func TestRegistry_ResolveAndLoad(t *testing.T) {
	reg := NewRegistry()

	keys := []config.VirtualKeyConfig{
		{
			ID:       "vk1",
			Token:    "aikey_vk_abc",
			Provider: "openai",
			BaseURL:  "https://api.openai.com",
			KeyAlias: "openai:default",
		},
		{
			ID:            "vk2",
			Token:         "aikey_vk_def",
			Provider:      "anthropic",
			BaseURL:       "https://api.anthropic.com",
			KeyAlias:      "anthropic:default",
			AllowedModels: []string{"claude-sonnet-4-5-20250929"},
		},
	}

	reg.Load(keys)

	// Resolve known token.
	route := reg.Resolve("aikey_vk_abc")
	if route == nil {
		t.Fatal("expected route for aikey_vk_abc")
	}
	if route.Provider != "openai" {
		t.Fatalf("expected provider openai, got %s", route.Provider)
	}
	if route.VirtualKeyID != "vk1" {
		t.Fatalf("expected vk1, got %s", route.VirtualKeyID)
	}

	// Resolve another known token.
	route2 := reg.Resolve("aikey_vk_def")
	if route2 == nil {
		t.Fatal("expected route for aikey_vk_def")
	}
	if route2.Provider != "anthropic" {
		t.Fatalf("expected provider anthropic, got %s", route2.Provider)
	}

	// Unknown token returns nil.
	if reg.Resolve("aikey_vk_unknown") != nil {
		t.Fatal("expected nil for unknown token")
	}

	// Count.
	if reg.Count() != 2 {
		t.Fatalf("expected count 2, got %d", reg.Count())
	}
}

func TestRegistry_Reload(t *testing.T) {
	reg := NewRegistry()

	reg.Load([]config.VirtualKeyConfig{
		{ID: "vk1", Token: "token_a", Provider: "openai", BaseURL: "http://x", KeyAlias: "a"},
	})

	if reg.Resolve("token_a") == nil {
		t.Fatal("expected route for token_a")
	}

	// Reload with different keys.
	reg.Load([]config.VirtualKeyConfig{
		{ID: "vk2", Token: "token_b", Provider: "anthropic", BaseURL: "http://y", KeyAlias: "b"},
	})

	if reg.Resolve("token_a") != nil {
		t.Fatal("old token should be gone after reload")
	}
	if reg.Resolve("token_b") == nil {
		t.Fatal("expected route for token_b after reload")
	}
}

func TestRegistry_ConcurrentReads(t *testing.T) {
	reg := NewRegistry()
	reg.Load([]config.VirtualKeyConfig{
		{ID: "vk1", Token: "aikey_vk_concurrent", Provider: "openai", BaseURL: "http://x", KeyAlias: "a"},
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			route := reg.Resolve("aikey_vk_concurrent")
			if route == nil {
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

	// Empty allowlist means all allowed.
	routeAll := &ResolvedRoute{}
	if !routeAll.IsModelAllowed("anything") {
		t.Fatal("empty allowlist should allow all")
	}
}
