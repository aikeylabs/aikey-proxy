package supervisor

// identity_key_heartbeat_wiring_fence_test.go — the fence that the Codex
// identity-rewrite counter is actually PUT ON the cluster heartbeat.
//
// internal/proxy owns the counter and fences its behavior
// (identity_key_fallback_test.go: marking, clearing, self-healing). It cannot
// fence the wiring: those tests call the resolver directly, so they stay green
// even if the supervisor never puts the number on the heartbeat — and a counter
// nobody ships is a counter that does not exist. This is the other half, the
// same split cluster_node_wiring_fence_test.go makes for the cluster-node guard.
//
// # Why this matters enough to fence (需求包 codex-pool-anti-linkage, task 2.5)
//
// The chain is: worker counts → heartbeat `health.pool_routing` → aikey-hub's
// report → the control plane's codex_identity_rewrite.identity_key_missing CRIT
// (R-codex-identity-rewrite-4.S2). Every hop downstream is fenced in its own
// repo, and every one of those fences feeds itself a HAND-WRITTEN payload — so
// deleting the two lines below leaves the entire chain dead and all of them
// green. That is the "围栏按链路写，不按字段写" gap this file closes.
//
// # Why this is a SOURCE fence and not a runtime one
//
// The payload is built by a closure inside New() (poolRoutingFn), reachable only
// by constructing a whole Supervisor — vault, generations, a live Registrar —
// which nothing in this package does. And the two things a runtime assertion
// would need are both out of reach from here: markIdentityKeyMissing is
// unexported in package proxy (group_resolve.go exports exactly one symbol,
// IdentityKeyFallbackSnapshot), and the /status renderer that must agree with
// this payload lives in package app (app/app.go), which imports this package.
// So the drift check below compares the two exits' WIRE NAMES at source level;
// see the report for what would unlock the runtime version.
//
// spec: R-codex-identity-rewrite-4.S2 材料没有专属密钥 → 仍改写（本机兜底派生），
// 健康端点报 CRIT。
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// Both exits are read through the package's readSupervisorSource, which strips
// comments first — the comments in BOTH files discuss these field names in prose,
// and a fence that fires on its own rationale gets deleted.
//
// the two wire names, written once here and asserted in both exits below.
const (
	identityKeyMissingActiveWire = "identity_key_missing_active"
	identityKeyMissingTotalWire  = "identity_key_missing_total"
)

// TestIdentityKeyMissingIsWiredIntoTheHeartbeatPayload asserts the supervisor
// really puts both counters into the heartbeat's pool_routing section, reads
// them from the resolver that took the fallback, and ships them unconditionally.
func TestIdentityKeyMissingIsWiredIntoTheHeartbeatPayload(t *testing.T) {
	src := readSupervisorSource(t, "supervisor.go")

	// Vacuity guard: if the read is gone entirely this fence must say so rather
	// than pass over an absence.
	if !strings.Contains(src, "proxy.IdentityKeyFallbackSnapshot()") {
		t.Fatal("supervisor.go never calls proxy.IdentityKeyFallbackSnapshot(). The cluster " +
			"heartbeat then carries no identity-rewrite counter, aikey-hub relays nothing, and " +
			"codex_identity_rewrite.identity_key_missing can never fire — accounts served on a " +
			"node-local fallback key stay invisible while the control plane reports OK. " +
			"internal/proxy's fences cannot catch this: they call the resolver themselves.")
	}

	for _, wire := range []string{identityKeyMissingActiveWire, identityKeyMissingTotalWire} {
		tag := `json:"` + wire + `"`
		if !strings.Contains(src, tag) {
			t.Fatalf("supervisor.go's heartbeat pool_routing payload has no %s field. "+
				"aikey-hub decodes this exact key (nameservice/internal/health.PoolRoutingHealth) "+
				"and the control plane reads nodes[].pool_routing.%s — a field that is not on the "+
				"wire is not an error anywhere, it just reads as zero forever.", tag, wire)
		}
		// 🔴 A counter that disappears at zero makes "the material arrived and the
		// fallback stopped" and "this build never reported it" the same bytes
		// (design §4b.5 计数类恒在). The hub's side asserts the 0 shows up on the
		// wire; this is the producer's half of that convention.
		if strings.Contains(src, `json:"`+wire+`,omitempty"`) {
			t.Fatalf("supervisor.go tags %s with omitempty. A zero counter would then vanish "+
				"from the heartbeat and the control plane could not tell a repaired node from a "+
				"node that never wired the counter (design §4b.5).", wire)
		}
	}

	// Declared is not shipped: a field left at its zero value is the exact
	// hand-copied-relay defect this chain already suffered once at the hub.
	for _, read := range []string{".MissingActive", ".MissingTotal"} {
		if !strings.Contains(src, read) {
			t.Fatalf("supervisor.go declares the heartbeat counter fields but never reads %s off "+
				"the snapshot, so it would ship a hard-coded zero — which is exactly what the "+
				"control plane reads as «nothing is degraded».", read)
		}
	}
}

// TestIdentityKeyMissingWireNamesDoNotDriftBetweenTheTwoExits is the machine
// expression of "两份手写出口不许漂移".
//
// The same pair of numbers is rendered TWICE by hand: here for the cluster
// heartbeat, and in internal/admin's PoolRoutingHealth for GET /status. Both
// read the one snapshot, but each spells the wire names itself, so a rename in
// one exit silently gives operators two different field names for one fact —
// and whichever consumer reads the other one goes quiet. (Removing the second
// exit is a refactor, deliberately NOT done here: TODO-34.)
func TestIdentityKeyMissingWireNamesDoNotDriftBetweenTheTwoExits(t *testing.T) {
	heartbeat := readSupervisorSource(t, "supervisor.go")
	status := readSupervisorSource(t, "../admin/handlers.go")

	for _, wire := range []string{identityKeyMissingActiveWire, identityKeyMissingTotalWire} {
		tag := `json:"` + wire + `"`
		inHeartbeat := strings.Contains(heartbeat, tag)
		inStatus := strings.Contains(status, tag)
		if inHeartbeat != inStatus {
			t.Fatalf("%s is on the cluster heartbeat (%v) but on /status (%v) — the two exits "+
				"render the SAME snapshot and have drifted apart. One operator surface now names "+
				"this fact differently from the other, and the consumer of the renamed one reads "+
				"nothing. Rename BOTH, or collapse them into one projection (TODO-34).",
				tag, inHeartbeat, inStatus)
		}
	}
}

// TestIdentityKeyMissingSnapshotMarshalsToTheWireNames pins the one end that IS
// reachable at runtime: the shared source both exits read. If its tags are
// renamed, both exits ship the new name and the source fences above would still
// pass — this catches that.
func TestIdentityKeyMissingSnapshotMarshalsToTheWireNames(t *testing.T) {
	raw, err := json.Marshal(proxy.IdentityKeyFallbackSnapshot())
	if err != nil {
		t.Fatalf("marshal the identity-key health snapshot: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode the marshaled snapshot: %v", err)
	}
	for _, wire := range []string{identityKeyMissingActiveWire, identityKeyMissingTotalWire} {
		if _, ok := fields[wire]; !ok {
			t.Fatalf("proxy.IdentityKeyHealth no longer marshals %q (got %s). Both the heartbeat "+
				"and /status copy their numbers out of this type; renaming it here renames the "+
				"fact everywhere at once.", wire, raw)
		}
	}
}
