package vault

import "strings"

// Helpers for the registry-load form filter (third-party review #4 [低],
// 2026-04-29). These mirror the supervisor package's
// `isStrictPersonalRouteToken` / `tokenPrefixForLog` (see
// internal/supervisor/team_token_normalize.go) but live in the vault
// package so vault loaders can reject non-strict route_tokens at SELECT
// time without introducing a vault → supervisor import (which would be
// a layering violation; supervisor depends on vault, not the reverse).
//
// Why duplicate the few lines instead of factoring up: both copies are
// trivial pure functions with the same form contract pinned by golden
// tests in their respective packages; centralizing them would invite a
// bigger refactor of the package layout for marginal benefit. The pair
// is small enough to maintain in lockstep when the form changes.

// isStrictPersonalBearerForm reports whether token matches exactly
// `aikey_personal_<64 lowercase hex>` — the post-2026-04-29 personal /
// OAuth bearer form. Used by registry loaders to skip pre-migration
// rows whose route_token is still `aikey_vk_*` or another legacy shape.
func isStrictPersonalBearerForm(token string) bool {
	const prefix = "aikey_personal_"
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

// routeTokenPrefixForLog returns a short, log-safe representation of a
// route token. It strips the secret suffix so the log line surfaces what
// went wrong without leaking material that may turn out to be a real
// (just unexpected-form) credential.
func routeTokenPrefixForLog(token string) string {
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
