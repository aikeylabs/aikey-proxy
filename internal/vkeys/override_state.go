// override_state.go — why ONE named account cannot serve right now.
//
// The seat path asks "which account should this seat use?" and walks candidates
// until one works. A device-routing token asks a different question: the control
// plane already decided which pool account this device belongs to, so the worker
// must either use THAT account or say why it cannot. There is no walk, and the
// answer has to name a cause — the three causes have three different remedies
// and three different HTTP statuses.
//
// This file holds only the classification, deliberately as a pure function with
// no route parsing, no store access and no clock of its own: the hot path and a
// unit fence see exactly the same decision, and the precedence is pinned by a
// table test instead of by whichever branch happened to run first.
//
// spec: R-device-routing-token-dispatch-7.S4 材料未到或凭证失效不报成额度用完
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
package vkeys

// OverrideState is why (or whether) the ONE account named by the control plane
// can serve this request.
//
// The values are the client-facing `reason` strings verbatim (design §4b.2), not
// display labels: the 503 body carries them as-is. That is on purpose — an
// enum→string mapping table one layer up is the classic place for a rename to
// stop propagating, and then the operator reads a reason the code no longer
// produces.
type OverrideState string

const (
	// OverrideUsable: serve it. Nothing more to decide.
	OverrideUsable OverrideState = "usable"
	// OverrideMaterialNotReady: this worker has nothing to serve WITH — the
	// account is not in its candidate set, or its material has not arrived yet.
	// Nobody has to act; the material rail converges on its own. 503.
	OverrideMaterialNotReady OverrideState = "material_not_ready"
	// OverrideCredentialUnusable: the material is here but the account-level
	// credential is dead (needs a login, expired past refresh, or this worker
	// already saw the upstream reject this exact token). Waiting does not fix
	// it — the control plane rebinds the device. 503.
	OverrideCredentialUnusable OverrideState = "credential_unusable" //nolint:gosec // G101: an enum state name, not a credential value
	// OverrideQuotaExhausted: the credential is fine, the window is not —
	// cooldown, rate limit, or an exhausted 5h/7d window. This one recovers by
	// itself, and it is the ONLY state that may be reported as a 429.
	OverrideQuotaExhausted OverrideState = "quota_exhausted"
)

// ClassifyOverride reports the state of the single account `override` names.
//
//	refs        — the candidate set the picker will rank over. Callers on the hot
//	              path MUST pass the same merged view PickRoutedAccount gets
//	              (MergeLiveGroupAccountRefs), or this classification and the
//	              pick can disagree about who is even a candidate.
//	material    — the delivered per-account material (PLAINTEXT flags only are
//	              read; secrets are untouched). A nil/empty map means nothing has
//	              arrived → material_not_ready, never "blind mode": the strict
//	              branch must not guess.
//	override    — the account id from the internal header. "" is classified
//	              material_not_ready so that an empty decision can never reach
//	              the picker as "no override" (the caller answers a missing
//	              header with NO_DECISION long before this).
//	cooling     — accounts whose WINDOW is currently closed (timed + per-tier
//	              cooldowns).
//	authRevoked — accounts whose CURRENT token this worker already saw rejected.
//	nowUnix     — injected clock for the expiry / window-reset gates.
//
// Precedence (fixed, and the reason this is a table-tested pure function):
// missing material outranks everything (there is nothing to judge), a dead
// credential outranks a closed window (waiting cannot fix a rejected token), and
// only then is it a quota answer.
func ClassifyOverride(
	refs []GroupAccountRef,
	material map[string]GroupRuntimeAccount,
	override string,
	cooling map[string]bool,
	authRevoked map[string]bool,
	nowUnix int64,
) OverrideState {
	if override == "" {
		return OverrideMaterialNotReady
	}
	candidate := false
	for i := range refs {
		if refs[i].AccountID == override {
			candidate = true
			break
		}
	}
	mat, delivered := material[override]
	if !candidate || !delivered {
		return OverrideMaterialNotReady
	}
	// MaterialExpired is used rather than a bare ExpiresAt comparison so api_key
	// material (no expiry in its contract) is not read as expired.
	if authRevoked[override] || mat.NeedsLogin || MaterialExpired(mat, nowUnix) {
		return OverrideCredentialUnusable
	}
	// MaterialWindowBlockedAt, not MaterialWindowExhausted: past the
	// authoritative reset a stale exhausted value must not keep the account out
	// (bugfix 2026-08-27-oauth-pool-quota-state-convergence). The pinned account
	// is the only candidate here, so a false positive is a full outage for that
	// device rather than a fallback to a sibling.
	if cooling[override] || MaterialWindowBlockedAt(mat, nowUnix) {
		return OverrideQuotaExhausted
	}
	return OverrideUsable
}
