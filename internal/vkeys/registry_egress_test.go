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

func TestEgressSpecForGroupCredential_ScopesPoolAndRejectsDrift(t *testing.T) {
	mat := func(accounts map[string]GroupRuntimeAccount) string {
		value, _ := json.Marshal(accounts)
		return string(value)
	}
	reg := NewRegistry()
	reg.Merge(map[string]*ResolvedRoute{
		"seat-1": {OauthGroupID: "group-1", GroupRuntime: mat(map[string]GroupRuntimeAccount{
			"account-1": {CredentialID: "credential-1", EgressProxyURL: "http://127.0.0.1:10808"},
		})},
		"seat-2": {OauthGroupID: "group-1", GroupRuntime: mat(map[string]GroupRuntimeAccount{
			"account-1": {CredentialID: "credential-1", EgressProxyURL: "http://127.0.0.1:10808"},
		})},
		"unrelated-malformed": {OauthGroupID: "group-2", GroupRuntime: "{"},
	})

	if got, found, err := reg.EgressSpecForGroupCredential("group-1", "credential-1"); err != nil || !found || got != "http://127.0.0.1:10808" {
		t.Fatalf("effective credential egress = %q found=%t err=%v", got, found, err)
	}
	if _, found, err := reg.EgressSpecForGroupCredential("group-1", "missing"); err != nil || found {
		t.Fatalf("missing credential must stay unresolved: found=%t err=%v", found, err)
	}

	reg.Merge(map[string]*ResolvedRoute{
		"seat-3": {OauthGroupID: "group-1", GroupRuntime: mat(map[string]GroupRuntimeAccount{
			"account-1": {CredentialID: "credential-1", EgressProxyURL: "socks5://different.example:1080"},
		})},
	})
	if _, found, err := reg.EgressSpecForGroupCredential("group-1", "credential-1"); err == nil || found {
		t.Fatalf("inconsistent runtime must fail closed: found=%t err=%v", found, err)
	}
}

func TestEgressSpecForGroupCredential_MalformedSelectedPoolFailsClosed(t *testing.T) {
	reg := NewRegistry()
	reg.Merge(map[string]*ResolvedRoute{
		"selected-malformed": {OauthGroupID: "group-1", GroupRuntime: "{"},
	})
	if _, found, err := reg.EgressSpecForGroupCredential("group-1", "credential-1"); err == nil || found {
		t.Fatalf("malformed selected pool must fail closed: found=%t err=%v", found, err)
	}
}
