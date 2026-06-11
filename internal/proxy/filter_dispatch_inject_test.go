package proxy

import (
	"encoding/json"
	"testing"
)

// TestInjectVirtualKey pins the per-seat attribution stamp (20260611 集中化网关归因
// 改造): the proxy stamps virtual_key_id onto the team event JSON; an empty vk
// (non-team route) and malformed JSON are left unchanged (fail-safe — a stamping
// glitch must never break the upload).
func TestInjectVirtualKey(t *testing.T) {
	const ev = `{"event_id":"e1","tenant_id":"org-1","action_taken":"mask"}`

	out := injectVirtualKey([]byte(ev), "aikey_team_abc123")
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["virtual_key_id"] != "aikey_team_abc123" {
		t.Errorf("virtual_key_id = %v, want aikey_team_abc123", m["virtual_key_id"])
	}
	if m["event_id"] != "e1" || m["tenant_id"] != "org-1" {
		t.Errorf("other fields mutated: %v", m)
	}

	if got := string(injectVirtualKey([]byte(ev), "")); got != ev {
		t.Errorf("empty vk mutated event: %s", got)
	}

	const bad = `{not json`
	if got := string(injectVirtualKey([]byte(bad), "vk")); got != bad {
		t.Errorf("malformed json mutated: %s", got)
	}
}

// TestInjectAttribution_Chained pins the call-site chain: both tenant_id (the
// authoritative org, overriding any client-claimed value) and virtual_key_id end
// up on the event — this is exactly what the team-event path stamps.
func TestInjectAttribution_Chained(t *testing.T) {
	const ev = `{"event_id":"e1","tenant_id":"client-claimed","action_taken":"mask"}`
	out := injectVirtualKey(injectTenant([]byte(ev), "org-real"), "vk-1")
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["tenant_id"] != "org-real" { // proxy overrides client-claimed tenant
		t.Errorf("tenant_id = %v, want org-real (authoritative)", m["tenant_id"])
	}
	if m["virtual_key_id"] != "vk-1" {
		t.Errorf("virtual_key_id = %v, want vk-1", m["virtual_key_id"])
	}
}
