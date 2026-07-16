package vkeys

// FENCE (alpha.5 五跳合约, hop 3→4): on a CLUSTER worker node the
// group_runtime column is written by aikey-cli's cluster_apply_snapshot
// (build_group_runtime_material), NOT by this proxy's supervisor writer — and
// the hot-path reader (resolveGroupCredential) parses it with THESE structs.
// This test pins a VERBATIM sample of the cli writer's output so a key rename
// on either side red-lines here instead of silently decrypting nothing.
// The cli-side twin is vault_op.rs::group_runtime_material_projects_parent_token.

import (
	"encoding/json"
	"testing"
)

func TestGroupRuntime_ParsesCliClusterWriterSample(t *testing.T) {
	// Byte-shape as emitted by aikey-cli build_group_runtime_material.
	sample := `{
		"acc-1": {
			"credential_type": "oauth_account",
			"identity": "a@x.io",
			"provider_code": "anthropic",
			"priority": 1,
			"secret_nonce": "bm9uY2UxMjM0NTY=",
			"secret_ciphertext": "Y2lwaGVydGV4dA==",
			"expires_at": 4200,
			"external_id": "ext-1",
			"window_max_util_pct": 80,
			"window_status": "ok"
		},
		"acc-2": {
			"credential_type": "oauth_account",
			"priority": 2,
			"needs_login": true
		}
	}`
	var m map[string]GroupRuntimeAccount
	if err := json.Unmarshal([]byte(sample), &m); err != nil {
		t.Fatalf("cli cluster writer sample must parse with the hot-path structs: %v", err)
	}
	a1 := m["acc-1"]
	if a1.CredentialType != "oauth_account" || a1.SecretNonce == "" || a1.SecretCiphertext == "" {
		t.Fatalf("acc-1 = %+v — secret fields lost (key drift between cli writer and proxy reader?)", a1)
	}
	if a1.ExpiresAt != 4200 || a1.ExternalID != "ext-1" || a1.Priority != 1 {
		t.Fatalf("acc-1 meta = %+v — metadata keys drifted", a1)
	}
	if a1.WindowMaxUtilPct == nil || *a1.WindowMaxUtilPct != 80 {
		t.Fatalf("acc-1 window = %+v — window keys drifted", a1.WindowMaxUtilPct)
	}
	a2 := m["acc-2"]
	if !a2.NeedsLogin || a2.SecretCiphertext != "" {
		t.Fatalf("acc-2 = %+v — needs_login marker must parse with NO secret", a2)
	}
}
