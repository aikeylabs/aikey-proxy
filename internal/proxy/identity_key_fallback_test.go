package proxy

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// encIdentityKey puts a DELIVERED per-account identity key into the at-rest
// group_runtime shape, exactly as the two relays (cluster daemon / member-rail
// supervisor) write it: AES-GCM with the node vault key, nonce+ciphertext
// base64(std).
func encIdentityKey(t *testing.T, key []byte, m vkeys.GroupRuntimeAccount, identityKey []byte) vkeys.GroupRuntimeAccount {
	t.Helper()
	nonce, ct, err := vault.Encrypt(key, identityKey)
	if err != nil {
		t.Fatalf("encrypt identity key: %v", err)
	}
	m.IdentityKeyNonce = base64.StdEncoding.EncodeToString(nonce)
	m.IdentityKeyCiphertext = base64.StdEncoding.EncodeToString(ct)
	return m
}

// TestIdentityKey_MissingFallsBackToLocalDerivationAndCRIT is the reader half of
// the identity-key chain: material → resolver → the per-request route the Codex
// rewrite consumes, plus the degradation the spec requires when the control
// plane's key is absent.
//
// spec: R-codex-identity-rewrite-4.S2 密钥缺失 —— worker 收到的账号材料没有专属
// 密钥时，仍必须用「本机密钥 + 账号编号」派生出一把可用的密钥（所以改写永远有
// 种子、原值永远不透传），同节点上另一个账号必须得到不同的值，并且健康端点报
// CRIT（不只 WARN）。
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
//
// Counters are asserted as DELTAS around each leg (and the account ids are
// unique to this test) so the fence needs no global reset hook and cannot be
// perturbed by other tests in the package.
func TestIdentityKey_MissingFallsBackToLocalDerivationAndCRIT(t *testing.T) {
	key := grKey()
	seat := "seat-idk"
	delivered := bytes.Repeat([]byte{0x5c}, 32)

	refs := []vkeys.GroupAccountRef{{AccountID: "idk-acc-a", Identity: "a@x", ProviderCode: "openai"}}

	// ── Leg A: the delivered key reaches the resolved route, no fallback ──
	withKey := map[string]vkeys.GroupRuntimeAccount{
		"idk-acc-a": encIdentityKey(t, key,
			encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-a"),
			delivered),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp-idk",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, withKey)}

	base := IdentityKeyFallbackSnapshot()
	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve with a delivered identity key: %v", err)
	}
	if !bytes.Equal(res.IdentityKey, delivered) {
		t.Fatalf("the control plane's per-account key did not reach the resolved route: got %d bytes, want the delivered %d-byte key",
			len(res.IdentityKey), len(delivered))
	}
	afterA := IdentityKeyFallbackSnapshot()
	if afterA.MissingTotal != base.MissingTotal || afterA.MissingActive != base.MissingActive {
		t.Fatalf("a delivered key must not be counted as missing: total %d->%d active %d->%d",
			base.MissingTotal, afterA.MissingTotal, base.MissingActive, afterA.MissingActive)
	}

	// ── Leg B: material without the key → local derivation + CRIT ──
	withoutKey := map[string]vkeys.GroupRuntimeAccount{
		"idk-acc-a": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-a"),
	}
	route.GroupRuntime = mustJSON(t, withoutKey)
	res, err = resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve without a delivered identity key must still serve: %v", err)
	}
	if len(res.IdentityKey) != 32 {
		t.Fatalf("missing material key must degrade to a LOCAL 32-byte derivation, never to an empty key (an empty key would leave the rewrite with no seed and pass the original identifiers upstream): got %d bytes", len(res.IdentityKey))
	}
	if bytes.Equal(res.IdentityKey, delivered) {
		t.Fatal("fallback key equals the delivered key — the resolver is reading stale material, not deriving locally")
	}
	if bytes.Equal(res.IdentityKey, key) {
		t.Fatal("fallback key IS the node vault key — the vault key must be a derivation input, never handed out as the identity key")
	}
	fallbackA := append([]byte(nil), res.IdentityKey...)
	afterB := IdentityKeyFallbackSnapshot()
	if afterB.MissingTotal <= afterA.MissingTotal {
		t.Fatalf("missing-key fallback was not counted: total %d->%d", afterA.MissingTotal, afterB.MissingTotal)
	}
	if afterB.MissingActive != afterA.MissingActive+1 {
		t.Fatalf("health surface must report the account as CRIT (>0 active) while it serves on a locally derived key: active %d->%d",
			afterA.MissingActive, afterB.MissingActive)
	}

	// Same account, same node ⇒ the same key, or the rewritten identity would
	// churn on every request and defeat the upstream's session reuse.
	res, err = resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("second resolve on the fallback path: %v", err)
	}
	if !bytes.Equal(res.IdentityKey, fallbackA) {
		t.Fatal("fallback derivation is not stable for the same account on the same node")
	}

	// Another account on the SAME node must get a DIFFERENT key (spec S2).
	otherRefs := []vkeys.GroupAccountRef{{AccountID: "idk-acc-b", Identity: "b@x", ProviderCode: "openai"}}
	otherRoute := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp-idk",
		GroupAccounts: mustJSON(t, otherRefs),
		GroupRuntime: mustJSON(t, map[string]vkeys.GroupRuntimeAccount{
			"idk-acc-b": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-b"),
		})}
	otherRes, err := resolveGroupCredential(otherRoute, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve second account on the fallback path: %v", err)
	}
	if bytes.Equal(otherRes.IdentityKey, fallbackA) {
		t.Fatal("two accounts on the same node derived the SAME fallback key — the two accounts' devices would look identical upstream, which is exactly the linkage the rewrite exists to break")
	}

	// A different node (different vault key) must not reproduce this node's
	// fallback key either.
	foreignKey := make([]byte, 32)
	for i := range foreignKey {
		foreignKey[i] = byte(i*7 + 3)
	}
	foreignRoute := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp-idk",
		GroupAccounts: mustJSON(t, refs),
		GroupRuntime: mustJSON(t, map[string]vkeys.GroupRuntimeAccount{
			"idk-acc-a": encMat(t, foreignKey, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-a"),
		})}
	foreignRes, err := resolveGroupCredential(foreignRoute, foreignKey, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve on a second node: %v", err)
	}
	if bytes.Equal(foreignRes.IdentityKey, fallbackA) {
		t.Fatal("fallback key is node-independent — it must be derived from THIS node's vault key")
	}

	// ── Leg C: the CRIT self-heals once the material carries the key again ──
	// Two accounts are on the fallback by now (idk-acc-a via this route and the
	// foreign node, idk-acc-b via its own), so healing idk-acc-a must drop the
	// active count by EXACTLY one and leave the other account's CRIT standing —
	// a blanket reset would hide a still-degraded account.
	beforeHeal := IdentityKeyFallbackSnapshot()
	route.GroupRuntime = mustJSON(t, withKey)
	res, err = resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve after the key was re-delivered: %v", err)
	}
	if !bytes.Equal(res.IdentityKey, delivered) {
		t.Fatal("re-delivered key did not take over from the local fallback")
	}
	healed := IdentityKeyFallbackSnapshot()
	if healed.MissingActive != beforeHeal.MissingActive-1 {
		t.Fatalf("CRIT must clear itself for exactly the repaired account when the control plane's key arrives again, with no proxy restart: active %d -> %d, want %d",
			beforeHeal.MissingActive, healed.MissingActive, beforeHeal.MissingActive-1)
	}
	if healed.MissingTotal < afterB.MissingTotal {
		t.Fatalf("lifetime fallback count must not go backwards (it is the diagnosis trail): %d -> %d", afterB.MissingTotal, healed.MissingTotal)
	}
}

// TestIdentityKey_UndecryptableMaterialDegradesInsteadOfFailing pins the
// robustness half: corrupt identity-key material must NOT fail the request (the
// account still has a usable token) — it takes the same locally derived
// fallback and the same CRIT as absent material.
func TestIdentityKey_UndecryptableMaterialDegradesInsteadOfFailing(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "idk-acc-corrupt", Identity: "c@x", ProviderCode: "openai"}}
	mat := encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-c")
	mat.IdentityKeyNonce = "!!not-base64!!"
	mat.IdentityKeyCiphertext = "!!not-base64!!"
	route := &vkeys.ResolvedRoute{SeatID: "seat-idk", OauthGroupID: "grp-idk",
		GroupAccounts: mustJSON(t, refs),
		GroupRuntime:  mustJSON(t, map[string]vkeys.GroupRuntimeAccount{"idk-acc-corrupt": mat})}

	before := IdentityKeyFallbackSnapshot()
	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("corrupt identity-key material must not break routing: %v", err)
	}
	if len(res.IdentityKey) != 32 {
		t.Fatalf("corrupt material must degrade to the local derivation: got %d bytes", len(res.IdentityKey))
	}
	if after := IdentityKeyFallbackSnapshot(); after.MissingTotal <= before.MissingTotal {
		t.Fatalf("corrupt material must be counted like absent material: total %d->%d", before.MissingTotal, after.MissingTotal)
	}
}
