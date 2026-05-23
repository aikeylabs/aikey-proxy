// Package probepipe implements the Probe pipeline — the request path for
// explicit per-alias upstream checks routed via /probe/<alias>/v1/...
// URLs.
//
// This is "mode C" in the credential-mode architecture; see
// `workflow/CI/requirements/2026-05-23-credential-mode-architecture.md`
// §1.3 for the contract.
//
// Pipeline layout:
//
//	router.go    — URL parsing (this file)
//	authn.go     — first-party constant Bearer check
//	resolve.go   — vault alias lookup + status mapping
//
// The handler that orchestrates these stages lives in proxy/proxy.go
// (handleProbePipeline), mirroring the apppipe convention.
//
// Why a separate package: probe is semantically distinct from the App
// pipeline — there is no app_records / profile_id / follow_user_active /
// provider-binding indirection. URL alias is the single routing signal
// and is the SAME field for both personal and OAuth credentials. Sharing
// the apppipe package would force conditional branches in resolve / authn
// that obscure the simpler probe contract.
package probepipe

import (
	"net/url"
	"strings"
)

// ProbeContext is the parsed shape of a /probe/<alias>/v1/... URL.
//
// AliasName has already been URL-decoded and validated against the
// `[A-Za-z0-9._@-]+` charset (sufficient for personal entries + OAuth
// email/local_alias forms per SPEC §1.3).
type ProbeContext struct {
	// AliasName is the URL-decoded alias name between /probe/ and /v1/.
	AliasName string
	// StrippedPath is what comes after /probe/<alias>/v1; always starts
	// with "/". Typical values: "/messages" (Anthropic SDK),
	// "/chat/completions" (OpenAI SDK).
	StrippedPath string
}

// ExtractProbePath parses an HTTP request path and returns a ProbeContext
// iff the path matches /probe/<alias>/v1[/<rest>]. Otherwise returns nil
// — caller falls through to /apps/ or legacy pipelines.
//
// Edge cases:
//   - /probe/X/v1                  → {AliasName:"X", StrippedPath:"/"}
//   - /probe/X/v1/messages         → {AliasName:"X", StrippedPath:"/messages"}
//   - /probe/X@y.com/v1/messages   → AliasName URL-decodes "@" naturally
//   - /probe                       → nil
//   - /probe/X                     → nil (missing v1)
//   - /probe/X/v2/foo              → nil (v1 only — bump explicitly when /v2 lands)
//   - /probe/X/foo                 → nil (foo != v1)
//   - /apps/X/v1                   → nil (apps pipeline)
//
// CRITICAL: caller MUST invoke this BEFORE the apppipe.ExtractAppPath
// check in proxy.Handle so URL prefix collision (e.g. a slug literally
// named "probe") never silently routes through the App pipeline. The
// ordering invariant is enforced by a regression test in proxy_test.go.
func ExtractProbePath(path string) *ProbeContext {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 4)
	if len(parts) < 3 || parts[0] != "probe" {
		return nil
	}
	if parts[2] != "v1" {
		return nil
	}

	alias, err := url.PathUnescape(parts[1])
	if err != nil || !isValidAliasName(alias) {
		return nil
	}

	rest := "/"
	if len(parts) == 4 && parts[3] != "" {
		rest = "/" + parts[3]
	}
	return &ProbeContext{
		AliasName:    alias,
		StrippedPath: rest,
	}
}

// isValidAliasName enforces the SPEC §1.3 charset [A-Za-z0-9._@-]+.
//
// Why a tight charset: probe alias is a single URL segment with no
// per-character escape handling beyond percent-decoding; permitting
// /, ?, # or whitespace would create routing ambiguity or expose the
// alias to URL-parser quirks across HTTP clients. The current set
// covers all in-the-wild forms: personal entries (kebab/snake/dot
// case), OAuth emails (user@host.tld), and renamed local_alias labels.
func isValidAliasName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		ok := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '@' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}
