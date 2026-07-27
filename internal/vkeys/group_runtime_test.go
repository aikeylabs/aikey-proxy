package vkeys

import "testing"

func TestMergeLiveGroupAccountRefs_RuntimeMembershipIsAuthoritative(t *testing.T) {
	snapshot := []GroupAccountRef{
		{AccountID: "account-1", Identity: "one@example.com", ProviderCode: "anthropic", Priority: 9, CredentialID: "cred-1"},
		{AccountID: "removed", Identity: "removed@example.com", ProviderCode: "anthropic", Priority: 1},
	}
	runtime := map[string]GroupRuntimeAccount{
		"account-1": {Identity: "live-one@example.com", ProviderCode: "anthropic", ProtocolType: "anthropic", Priority: 2, CredentialID: "cred-live-1"},
		"account-2": {Identity: "two@example.com", ProviderCode: "anthropic", ProtocolType: "anthropic", Priority: 3, CredentialID: "cred-2"},
	}

	got := MergeLiveGroupAccountRefs(snapshot, runtime)
	if len(got) != 2 || got[0].AccountID != "account-1" || got[1].AccountID != "account-2" {
		t.Fatalf("live membership not authoritative: %+v", got)
	}
	if got[0].Identity != "one@example.com" || got[0].Priority != 2 || got[0].CredentialID != "cred-1" {
		t.Fatalf("snapshot enrichment/live priority changed unexpectedly: %+v", got[0])
	}
	if got[1].Identity != "two@example.com" || got[1].ProtocolType != "anthropic" || got[1].CredentialID != "cred-2" {
		t.Fatalf("runtime-only account metadata missing: %+v", got[1])
	}
}

func TestMergeLiveGroupAccountRefs_EmptyRuntimeKeepsLegacySnapshot(t *testing.T) {
	snapshot := []GroupAccountRef{{AccountID: "account-1"}}
	got := MergeLiveGroupAccountRefs(snapshot, nil)
	if len(got) != 1 || got[0].AccountID != "account-1" {
		t.Fatalf("pre-poll compatibility fallback changed: %+v", got)
	}
}
