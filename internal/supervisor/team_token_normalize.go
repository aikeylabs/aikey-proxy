package supervisor

// Team token normalization shared helper.
//
// Used by supervisor.go's Registry loading to construct the runtime team
// bearer token from a server-issued vk_id stored in
// `managed_virtual_keys_cache.virtual_key_id`. Defensive against historical
// prefix residue (`aikey_vk_` / `aikey_team_`) and pathological double-prefix
// dirty data.
//
// The Rust-side equivalent lives at `aikey-cli/src/team_token_normalize.rs`
// and must produce identical output for every input — verified by the shared
// golden-cases fixture at `aikey-cli/tests/fixtures/team_token_normalize.json`.
//
// Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §3 / §4.

import (
	"errors"
	"strings"
)

// ErrEmptyVkID is returned when input is empty / whitespace-only / collapses
// to empty after prefix-stripping. `mk.VirtualKeyID` should never be empty;
// if it is, that's an upstream data bug. Caller skips the registration /
// surfaces the error rather than producing a degenerate `"aikey_team_"` token.
var ErrEmptyVkID = errors.New("empty vk_id")

// NormalizeTeamToken builds the runtime team token from a server-issued vk_id.
//
// Steps:
//  1. Trim leading/trailing whitespace.
//  2. Loop-strip any known historical prefix (`aikey_vk_`) or current prefix
//     (`aikey_team_`) plus any whitespace exposed after each strip. Loop
//     covers the pathological double-prefix case
//     (e.g. `aikey_vk_aikey_team_<bare>`) that a corrupted cache could
//     theoretically contain.
//  3. Reject empty input → ErrEmptyVkID.
//  4. Re-apply the canonical `aikey_team_` prefix.
//
// Why a shared helper: route / activate / supervisor must all emit the same
// token regardless of historical cache state, otherwise `aikey route`
// (CLI-side) and the proxy Registry could disagree for the same team key →
// third-party clients fail to route.
func NormalizeTeamToken(raw string) (string, error) {
	bare := strings.TrimSpace(raw)
	for {
		stripped, ok := stripKnownPrefix(bare)
		if !ok {
			break
		}
		bare = strings.TrimSpace(stripped)
	}
	if bare == "" {
		return "", ErrEmptyVkID
	}
	return "aikey_team_" + bare, nil
}

// stripKnownPrefix removes either `aikey_team_` or `aikey_vk_` from the front
// (one prefix per call). Returns the stripped string and true on match,
// or the original string and false if no known prefix matches.
func stripKnownPrefix(s string) (string, bool) {
	if r, ok := strings.CutPrefix(s, "aikey_team_"); ok {
		return r, true
	}
	if r, ok := strings.CutPrefix(s, "aikey_vk_"); ok {
		return r, true
	}
	return s, false
}

// isStrictPersonalRouteToken returns true iff the given token is exactly the
// post-2026-04-29 personal/OAuth bearer form: `aikey_personal_` + 64
// lowercase hex chars (length 79).
//
// Used by registry load (buildGeneration / syncManagedKeys) to filter out
// pre-migration legacy `aikey_vk_<64-hex>` residue and any other malformed
// shapes. Mirrors `dispatch.isTier1Personal` in the proxy package — kept as
// a separate copy here to avoid an import cycle (proxy already imports
// supervisor for NormalizeTeamToken).
//
// Why filter at registry load: per the "no double-prefix compatibility
// window" principle, legacy tokens MUST NOT be silently re-registered into
// the live registry. If a vault hasn't been CLI-migrated yet, the proxy
// would otherwise accept old `aikey_vk_<64-hex>` tokens — exactly the
// pitfall the namespace-authority refactor closed.
func isStrictPersonalRouteToken(token string) bool {
	return hasStrictHex64Suffix(token, "aikey_personal_")
}

// isStrictAppRouteToken returns true iff the given token is exactly the
// Phase 4 app bearer form: `aikey_app_<64 lowercase hex>` (length 74).
//
// Mirrors isStrictPersonalRouteToken's role: filters out any vault rows
// whose route_token shape doesn't match (writer-side bug or hand-crafted
// vault residue) so the registry's invariant is preserved — "after
// startup the registry only sees strict Tier1 forms" — and proxy's
// dispatch.isTier1App can do exact-key Resolve without surprises.
func isStrictAppRouteToken(token string) bool {
	return hasStrictHex64Suffix(token, "aikey_app_")
}

// hasStrictHex64Suffix is the shared form predicate behind the strict
// Tier1 bearer types (personal / app). DRY'd so future strict-form
// additions get the same charset + length guarantees without copy-paste
// drift (the same shape exists in dispatch.go and vault/route_token_form.go
// — each package keeps its own copy to avoid import cycles).
func hasStrictHex64Suffix(token, prefix string) bool {
	suffix, ok := strings.CutPrefix(token, prefix)
	if !ok {
		return false
	}
	if len(suffix) != 64 {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		c := suffix[i]
		isLowerHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isLowerHex {
			return false
		}
	}
	return true
}

// tokenPrefixForLog returns a short, non-secret-leaking representation of a
// token for log lines: just the prefix segment up to the first underscore
// after `aikey_`, or "<empty>" / "<no-aikey-prefix>" for edge cases.
//
// Examples:
//   "aikey_personal_0123abcd..."  → "aikey_personal_..."
//   "aikey_vk_acc-1234abc"        → "aikey_vk_..."
//   "aikey_unknown_xyz"           → "aikey_unknown_..."
//   ""                            → "<empty>"
//   "sk-real-secret"              → "<no-aikey-prefix>"
//
// Why not log the full token: even legacy bearers are local-proxy
// credentials; leaking them into stderr / log files broadens the blast
// radius of a compromised log host.
func tokenPrefixForLog(token string) string {
	if token == "" {
		return "<empty>"
	}
	rest, ok := strings.CutPrefix(token, "aikey_")
	if !ok {
		return "<no-aikey-prefix>"
	}
	if idx := strings.IndexByte(rest, '_'); idx >= 0 {
		return "aikey_" + rest[:idx] + "_..."
	}
	return "aikey_" + rest + "..."
}
