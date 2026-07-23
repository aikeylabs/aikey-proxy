package supervisor

import (
	"database/sql"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// The active_key_providers config key predates Client Route as a separate
// concept. New CLI versions intentionally store "anthropic" there even when
// the selected upstream supplier is Mock Provider. The health surface must
// follow the exact active binding instead of interpreting that route name as a
// Provider, otherwise the real Mock credential silently disappears from
// /health/keys.
func TestGetKeyCheckTargetsUsesExactTeamBindingAxes(t *testing.T) {
	dbPath, reader := newOpenableVault(t, []map[string]string{{
		"vk": "vk-mock-anthropic", "seat": "seat-1", "group": "", "override": "",
	}})

	derived := vault.DeriveKeyWithParams(
		[]byte("pw"), []byte("0123456789abcdef"), 8, 1, 1,
	)
	nonce, ciphertext, err := vault.Encrypt(derived, []byte("mock-secret"))
	if err != nil {
		t.Fatalf("encrypt fixture key: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE user_profile_provider_bindings (
		profile_id TEXT NOT NULL,
		provider_code TEXT NOT NULL,
		binding_provider_code TEXT NOT NULL DEFAULT '',
		protocol_type TEXT NOT NULL DEFAULT '',
		key_source_type TEXT NOT NULL,
		key_source_ref TEXT NOT NULL,
		PRIMARY KEY (profile_id, provider_code)
	)`); err != nil {
		t.Fatalf("create bindings: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO user_profile_provider_bindings
		(profile_id, provider_code, binding_provider_code, protocol_type,
		 key_source_type, key_source_ref)
		VALUES ('default', 'anthropic', 'mock', 'anthropic', 'team',
		        'vk-mock-anthropic')`); err != nil {
		t.Fatalf("insert binding: %v", err)
	}
	if _, err := db.Exec(`UPDATE managed_virtual_keys_cache
		SET provider_code='mock', protocol_type='anthropic',
		    base_url='http://master/mock-provider/anthropic',
		    provider_key_nonce=?, provider_key_ciphertext=?
		WHERE virtual_key_id='vk-mock-anthropic'`, nonce, ciphertext); err != nil {
		t.Fatalf("update managed key: %v", err)
	}
	for key, value := range map[string]string{
		"active_key_type":      "team",
		"active_key_ref":       "vk-mock-anthropic",
		"active_key_providers": `["anthropic"]`,
	} {
		if _, err := db.Exec(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`, key, []byte(value)); err != nil {
			t.Fatalf("write config %s: %v", key, err)
		}
	}

	s := &Supervisor{}
	s.active.Store(&generation{vault: reader})
	targets, err := s.GetKeyCheckTargets()
	if err != nil {
		t.Fatalf("GetKeyCheckTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets=%+v, want one exact Mock target", targets)
	}
	got := targets[0]
	if got.Provider != "mock" || got.Protocol != "anthropic" {
		t.Fatalf("target axes=(%q,%q), want (mock,anthropic)", got.Provider, got.Protocol)
	}
	if got.BaseURL != "http://master/mock-provider/anthropic" || got.APIKey != "mock-secret" {
		t.Fatalf("target material=%+v", got)
	}
}
