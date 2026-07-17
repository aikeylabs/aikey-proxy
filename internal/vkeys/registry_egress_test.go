package vkeys

import (
	"encoding/json"
	"testing"
)

// EgressSpecs must enumerate DISTINCT per-account egress specs across all group
// routes: one row per account (deduped even when the same account appears under
// many seat VK tokens), accounts without an egress spec skipped, labelled by the
// account's own display identity (never an internal id).
func TestEgressSpecs_EnumeratesDedupsAndLabels(t *testing.T) {
	mat := func(accs map[string]GroupRuntimeAccount) string {
		b, _ := json.Marshal(accs)
		return string(b)
	}
	// Two seats' VKs, SAME pool: acc-1 has an egress spec (appears under both
	// tokens → must dedup to one), acc-2 has none (skipped).
	runtime := mat(map[string]GroupRuntimeAccount{
		"acc-1": {Identity: "pool-a@example.com", EgressProxyURL: "socks5://exit-a:1080"},
		"acc-2": {Identity: "pool-b@example.com"}, // no egress → skipped
	})
	reg := NewRegistry()
	reg.Merge(map[string]*ResolvedRoute{
		"aikey_team_seat1": {OauthGroupID: "grp", GroupRuntime: runtime},
		"aikey_team_seat2": {OauthGroupID: "grp", GroupRuntime: runtime},
		"aikey_personal_x": {}, // non-group route → no GroupRuntime, ignored
	})

	specs := reg.EgressSpecs()
	if len(specs) != 1 {
		t.Fatalf("want 1 distinct egress spec (acc-1, deduped across 2 tokens), got %d: %+v", len(specs), specs)
	}
	if specs[0].Label != "pool-a@example.com" {
		t.Errorf("label must be the account display identity, got %q", specs[0].Label)
	}
	if specs[0].Spec != "socks5://exit-a:1080" {
		t.Errorf("spec = %q", specs[0].Spec)
	}
}

// An account carrying an egress spec but no identity falls back to a non-leaking
// "account <id>" label rather than an empty string.
func TestEgressSpecs_LabelFallback(t *testing.T) {
	runtime, _ := json.Marshal(map[string]GroupRuntimeAccount{
		"acc-9": {EgressProxyURL: "socks5://x:1080"}, // no Identity
	})
	reg := NewRegistry()
	reg.Merge(map[string]*ResolvedRoute{"t": {GroupRuntime: string(runtime)}})
	specs := reg.EgressSpecs()
	if len(specs) != 1 || specs[0].Label != "account acc-9" {
		t.Fatalf("want fallback label 'account acc-9', got %+v", specs)
	}
}

// No group routes (Personal node) → empty, never nil-panic.
func TestEgressSpecs_EmptyWhenNoGroups(t *testing.T) {
	reg := NewRegistry()
	reg.Merge(map[string]*ResolvedRoute{"aikey_personal_x": {}})
	if got := reg.EgressSpecs(); len(got) != 0 {
		t.Fatalf("want no specs, got %+v", got)
	}
}
