package proxy

// Token namespace dispatch — central authority for the `aikey_*` namespace.
//
// The 2026-04-29 prefix rename established the namespace-authority principle:
// any token starting with `aikey_` belongs to AiKey's routing namespace, and
// proxy is the AUTHORITATIVE decision point for what's legitimate. Native
// provider tokens (e.g. `sk-...`) are handled by a separate fallthrough path.
//
// Dispatch outcomes:
//   - Tier2Probe         → `aikey_probe_*` (test sentinel, tier 2 path)
//   - Tier1Team          → `aikey_team_*` (team static bearer; Registry lookup)
//   - Tier1Personal      → `aikey_personal_<64-hex>` (personal static bearer; Registry lookup)
//   - Tier1App           → `aikey_app_<64-hex>` (third-party app static bearer; App pipeline)
//   - Tier3ActiveSentinel→ `aikey_active_*` (follow-active sentinel; tier 3 fallthrough INTENTIONAL)
//   - TokenInvalid       → any other `aikey_*` (unknown subform / malformed / reserved `aikey_route_*`)
//   - Tier3Native        → token does not start with `aikey_` (native upstream credential)
//
// `aikey_active_*` is the SOLE exception within the aikey namespace allowed
// to fall through — sentinel design depends on tier-3 picking up the active
// binding via the URL path's canonical provider code. The suffix is purely
// informational; proxy never validates it.
//
// Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §3

import "strings"

// DispatchAction enumerates the routing decisions for a token after
// namespace-authority filtering. Returned by ClassifyToken.
type DispatchAction int

const (
	// Tier3Native — token is not in the aikey_ namespace; fall through to
	// the path-binding lookup using its raw value (or replaced). Used by
	// CLI tools that send their own native provider tokens.
	Tier3Native DispatchAction = iota

	// Tier3ActiveSentinel — token is `aikey_active_*`; intentionally falls
	// through to GetProviderBinding(canonical). Suffix is informational.
	Tier3ActiveSentinel

	// Tier2Probe — token is `aikey_probe_*`; targets the exact alias in the
	// suffix via the proxy's tier-2 probe path (server-side decryption).
	Tier2Probe

	// Tier1Team — token is `aikey_team_*`; resolve via Registry as a static
	// bearer for the named team key. Registry miss → TokenInvalid downstream.
	Tier1Team

	// Tier1Personal — token is `aikey_personal_<64-hex>` (strict form);
	// resolve via Registry as a static bearer for the named personal/OAuth
	// route. Registry miss → TokenInvalid downstream.
	Tier1Personal

	// Tier1App — token is `aikey_app_<64-hex>` (strict form); third-party
	// app static bearer routed via App pipeline (internal/proxy/apppipe).
	// Registry lookup uses the plaintext token as key (byToken map),
	// matching the personal/OAuth pattern. Registry miss → TokenInvalid.
	Tier1App

	// TokenInvalid — token is in the aikey_ namespace but does NOT match a
	// known legitimate form. Caller MUST return HTTP 401 with body.error.code
	// = "TOKEN_INVALID" and MUST NOT fall through. Includes:
	//   - aikey_route_*    (reserved namespace, not implemented this round)
	//   - aikey_unknown_*  (typo / unknown subform)
	//   - aikey_personal_* with non-64-hex suffix (legacy sentinel, malformed bearer)
	//   - aikey_app_*      with non-64-hex suffix
	//   - aikey_team_      (empty vk_id)
	TokenInvalid
)

// ClassifyToken applies the namespace-authority dispatch rules. Pure function,
// no I/O — call sites pass the token string and dispatch on the returned
// action.
//
// Order is significant: probe is checked BEFORE personal because both share
// the `aikey_p` prefix; checking probe first guarantees `aikey_probe_*` is
// never misclassified as a malformed personal bearer. Active is checked
// last among aikey_* because its suffix is unconstrained, so any earlier
// checks would shadow it inadvertently.
func ClassifyToken(token string) DispatchAction {
	if !strings.HasPrefix(token, "aikey_") {
		return Tier3Native
	}

	switch {
	case strings.HasPrefix(token, "aikey_probe_"):
		// Tier 2 — probe sentinel. Suffix is the alias to test; non-empty
		// is enforced at the probe handler (returning a clear error if so).
		return Tier2Probe

	case strings.HasPrefix(token, "aikey_team_"):
		// Tier 1 — team static bearer. Empty vk_id (just `aikey_team_`)
		// is invalid; the helper team_token_normalize on the writer side
		// ensures this never happens, but defend at the dispatch boundary
		// in case stale/legacy tokens leak through.
		if token == "aikey_team_" {
			return TokenInvalid
		}
		return Tier1Team

	case strings.HasPrefix(token, "aikey_personal_"):
		// Tier 1 — personal static bearer. Strict form: `aikey_personal_`
		// + exactly 64 lowercase hex chars (length 79). isTier1Personal
		// rejects everything else (legacy `aikey_personal_<alias>` form,
		// uppercase hex, short/long suffix, non-hex chars).
		if isTier1Personal(token) {
			return Tier1Personal
		}
		return TokenInvalid

	case strings.HasPrefix(token, "aikey_app_"):
		// Tier 1 — third-party app static bearer. Strict form: `aikey_app_`
		// + exactly 64 lowercase hex chars (length 74). Mirrors the
		// personal bearer form-check for the same reasons (precise rejection
		// of malformed shapes before they reach Registry lookup).
		//
		// MUST be checked BEFORE `aikey_active_` — `aikey_app_` is not a
		// prefix of `aikey_active_` so no shadowing today, but keep this
		// ordering strict to defend against future namespace additions.
		if isTier1App(token) {
			return Tier1App
		}
		return TokenInvalid

	case strings.HasPrefix(token, "aikey_active_"):
		// Tier 3 fallthrough — sentinel by design. Suffix is the canonical
		// provider code; not validated here because the proxy resolves the
		// route via the URL path's provider, not the sentinel suffix.
		return Tier3ActiveSentinel

	default:
		// Any other aikey_* subform: aikey_route_* (reserved, not yet
		// implemented), aikey_unknown_*, aikey_vk_* (legacy, fully removed
		// post-migration), etc. → TOKEN_INVALID per namespace authority.
		return TokenInvalid
	}
}

// isTier1Personal returns true iff `token` is exactly `aikey_personal_`
// followed by 64 lowercase hex chars. This is the strict, narrow form for
// the personal static bearer (output of CLI's storage::generate_route_token).
//
// Why strict:
//   - Legacy `aikey_personal_<alias>` (the pre-2026-04-29 sentinel form)
//     would otherwise be silently routed via Registry lookup, only to
//     produce a "not found" registry miss. The user sees no signal that
//     their token shape itself is wrong.
//   - Uppercase hex would 401 anyway because lookups are case-sensitive,
//     but the error message would be opaque. Rejecting at form-check
//     surface produces a precise error.
//   - Length variations (63 hex / 65 hex / 128 hex) are obviously corrupt
//     and should never reach Registry.
func isTier1Personal(token string) bool {
	return hasStrictHex64Suffix(token, "aikey_personal_")
}

// isTier1App returns true iff `token` is one of:
//   - exact strict form `aikey_app_<64 lowercase hex>` (third-party app
//     bearer issued by `aikey app register` / aikey-cli authorize_atomic);
//   - a well-known first-party app Bearer from
//     :data:`firstPartyAppBearerWhitelist` (zero-config, see SPEC §1.3).
//
// The whitelist exception was added 2026-05-22 so trust-local (the
// degrade-detector first-party app) can ship a human-readable, install-
// invariant Bearer instead of paying the env-injection ceremony to
// persist a random 64-hex one across launchd restarts.
func isTier1App(token string) bool {
	return hasStrictHex64Suffix(token, "aikey_app_") || isFirstPartyAppBearer(token)
}

// firstPartyAppBearerWhitelist is the well-known set of first-party app
// Bearers exempted from the strict `aikey_app_<64 hex>` form. Same value
// on every install (zero-config trust-local). Not secrets — see SPEC
// `workflow/CI/requirements/2026-05-22-l3-rhythm-signal-design-rules.md`
// §1.3.
//
// **Drift 防退化**: this map must equal the matching constants in:
//   - degrade-detector/server_local/services/check_orchestrator.py
//     ::FIRST_PARTY_APP_KEY
//   - aikey-cli/src/migrations.rs::DEGRADE_DETECTOR_FIRST_PARTY_BEARER
//
// Duplicated in 3 packages here (proxy/dispatch.go, vault/route_token_form.go,
// supervisor/team_token_normalize.go) due to import-cycle constraints —
// same lockstep convention as :func:`hasStrictHex64Suffix`.
var firstPartyAppBearerWhitelist = map[string]struct{}{
	"aikey_app_internal_degrade_detector_v1": {},
}

// isFirstPartyAppBearer reports whether token is a baked-in first-party
// Bearer that should be accepted alongside strict-form tokens. See
// :data:`firstPartyAppBearerWhitelist` doc for the security model.
func isFirstPartyAppBearer(token string) bool {
	_, ok := firstPartyAppBearerWhitelist[token]
	return ok
}

// hasStrictHex64Suffix returns true iff `token` is exactly `prefix` followed
// by 64 lowercase hex chars. Shared form-check for Tier1 strict bearers
// (personal / app) — DRY the predicate so future strict-form additions get
// the same charset + length guarantees without copy-paste drift.
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
