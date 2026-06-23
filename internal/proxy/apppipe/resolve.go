package apppipe

// resolve.go — App pipeline stage that validates the resolved bearer
// against vault metadata (app_records) + decides profile scope.
//
// 2026-05-21 Phase 2 Day 7 redesign:
//
// This stage NO LONGER does the binding lookup. Reason: the binding key
// is the UPSTREAM provider (anthropic / openai / ...), which is inferred
// from body.model at request time — and the body hasn't been sanitized
// yet when resolve runs. The pipeline now reads the model field AFTER
// sanitize and calls ResolveUpstreamBinding(...) with the inferred
// upstream code (see handleAppPipeline / translate.go).
//
// What resolve still does:
//
//   1. Decide the profile_id scope:
//        - first-party + FollowUserActive=true  → "default"
//          (App shares the user's `aikey use` binding; whitelisted slugs
//           only — R2 mitigation re-check below.)
//        - otherwise                            → "app:<slug>"
//          (isolated mode.)
//
//   2. Load app_records to surface the declared upstreams[] list.
//      Subsequent stages use it for the upstream-whitelist check.
//
//   3. R2 mitigation: re-validate first-party for follow-active even
//      though the CLI write-side already enforced — defends against
//      direct vault tampering.

import (
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// VaultReader is the minimal vault surface the App pipeline depends on.
// Decoupled from proxy.ActiveKeyReader so tests can supply a focused
// stub without satisfying ActiveKeyReader's full method set.
// *vault.Reader satisfies this via AKL-102.
//
// GetAliasCredential was added 2026-05-23 for B mode (credential-mode
// architecture SPEC §1.1.B / §3.3): when an app row carries a non-empty
// bound_alias, ResolveUpstreamBinding short-circuits the provider-binding
// lookup and resolves the credential via this method instead.
type VaultReader interface {
	GetProviderBindingWithScope(profileID, providerCode string) (*vault.ProviderBinding, error)
	GetAppRecord(slug string) (*vault.AppRecord, error)
	GetAliasCredential(name string) (*vault.AliasCredential, error)
}

// ResolveError represents a request that passed authn but cannot proceed
// due to a vault / scope / R2 issue.
type ResolveError struct {
	ErrorCode  string // body.error.code
	Message    string // body.error.message (English per CLAUDE.md)
	StatusCode int    // HTTP status
}

func (e *ResolveError) Error() string { return e.ErrorCode + ": " + e.Message }

// ResolvedAppContext is what resolve hands to the next stage. Carries
// metadata only; binding lookup happens AFTER body sanitize + upstream
// inference (see ResolveUpstreamBinding below).
type ResolvedAppContext struct {
	// AppRecord holds the metadata side (name, upstreams, app_kind).
	AppRecord *vault.AppRecord
	// AppRoute is the *vkeys.ResolvedRoute returned by authn, carrying
	// AppSlug / AppKind / AppKeyID / FollowUserActive. Pipeline reads
	// AppKeyID for usage_event's app_key_id column.
	AppRoute *vkeys.ResolvedRoute
	// ProfileID is "app:<slug>" (isolated) or "default" (follow-active).
	ProfileID string
}

// Resolve performs profile scope decision + app_records read + R2 check.
// Binding lookup is deferred to ResolveUpstreamBinding below, called
// after the body is sanitized and the upstream is inferred from body.model.
func Resolve(reader VaultReader, route *vkeys.ResolvedRoute, appCtx *AppContext) (*ResolvedAppContext, *ResolveError) {
	if reader == nil {
		return nil, &ResolveError{
			StatusCode: http.StatusServiceUnavailable,
			ErrorCode:  "APP_VAULT_NOT_AVAILABLE",
			Message:    "Server is not ready (vault reader not wired for App pipeline). Restart proxy or retry shortly.",
		}
	}

	// ── R2 mitigation: double-check first-party for follow-active ────────
	//
	// The CLI's register validator (validate_first_party_invariants)
	// rejects follow_user_active=true for non-first-party slugs at write
	// time; we re-check the AppKind here so direct vault tampering can't
	// escalate a third-party slug to follow-active. Loud reject per
	// CLAUDE.md "失败要显眼".
	if route.FollowUserActive && route.AppKind != "first-party" {
		return nil, &ResolveError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "FOLLOW_ACTIVE_NOT_ALLOWED",
			Message:    "Follow-active mode requires app_kind=first-party, but this app is " + route.AppKind + ". The vault may be tampered — re-register via `aikey app register`.",
		}
	}

	// Profile-id scope decision (主方案 §3.3).
	var profileID string
	if route.AppKind == "first-party" && route.FollowUserActive {
		profileID = "default"
	} else {
		profileID = "app:" + appCtx.Slug
	}

	// Load app_records. The upstreams[] list is used later by the
	// upstream-whitelist check in ResolveUpstreamBinding.
	appRecord, err := reader.GetAppRecord(appCtx.Slug)
	if err != nil {
		return nil, &ResolveError{
			StatusCode: http.StatusInternalServerError,
			ErrorCode:  "APP_RECORD_READ_FAILED",
			Message:    "Failed to read app metadata for slug \"" + appCtx.Slug + "\": " + err.Error(),
		}
	}
	if appRecord == nil {
		// app row missing — rare race (uninstall after Registry snapshot
		// but before proxy restart picks up the change). Defensive: don't
		// crash, just reject.
		return nil, &ResolveError{
			StatusCode: http.StatusNotFound,
			ErrorCode:  "APP_NOT_FOUND",
			Message:    "App record for slug \"" + appCtx.Slug + "\" not found in vault. The app may have been uninstalled; restart the Agent's process after re-registering.",
		}
	}

	return &ResolvedAppContext{
		ProfileID: profileID,
		AppRecord: appRecord,
		AppRoute:  route,
	}, nil
}

// ResolveUpstreamBinding performs the upstream-side resolve step that
// requires the request body to be known: validates the inferred upstream
// against the app's declared `upstreams[]` list, then looks up the
// binding for (profile_id, upstream).
//
// Called by handleAppPipeline after sanitize succeeds. Splitting it out
// of Resolve() avoids holding the binding lock across the body-read
// phase — and keeps the upstream-inference signal (body.model) on a
// natural sequence boundary (sanitize → infer → bind → translate).
//
// Errors:
//   - "" inferred upstream → UPSTREAM_UNINFERRABLE (400)
//   - upstream not in app.Upstreams → UPSTREAM_NOT_DECLARED (403)
//   - binding missing → BINDING_NOT_FOUND (404)
//   - vault read error → BINDING_READ_FAILED (500)
func ResolveUpstreamBinding(
	reader VaultReader,
	resolved *ResolvedAppContext,
	inferredUpstream string,
) (*vault.ProviderBinding, *ResolveError) {
	if inferredUpstream == "" {
		return nil, &ResolveError{
			StatusCode: http.StatusBadRequest,
			ErrorCode:  "UPSTREAM_UNINFERRABLE",
			Message: "Could not infer upstream provider from body.model. " +
				"Expected a recognized model id (claude-*, gpt-*, gemini-*, kimi-*, ...) " +
				"so AiKey can pick the matching binding.",
		}
	}

	// Upstream-whitelist check (was the protocol-set check pre-Day-7).
	// Catches vendor mid-flight scope expansion — an app registered with
	// --upstreams openai can't silently use anthropic without re-consent.
	if !containsString(resolved.AppRecord.Upstreams, inferredUpstream) {
		return nil, &ResolveError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "UPSTREAM_NOT_DECLARED",
			Message: "App \"" + resolved.AppRoute.AppSlug + "\" did not declare upstream \"" + inferredUpstream +
				"\" in its manifest. Declared upstreams: " + joinStrings(resolved.AppRecord.Upstreams, ", ") +
				". Re-register via `aikey app register --slug " + resolved.AppRoute.AppSlug +
				" --upstreams ...` (requires user re-consent) to expand.",
		}
	}

	// ── B mode short-circuit (2026-05-23, SPEC §1.1.B + §3.3) ──────────
	//
	// If the row carries a non-empty bound_alias, resolve the credential
	// from that alias snapshot instead of looking up a user-profile
	// provider binding. The synthesized binding is shape-compatible with
	// what GetProviderBindingWithScope would return, so all downstream
	// stages (ResolveBindingCredential, provider adapter, OAuth inject)
	// see one uniform binding contract.
	//
	// Canonical-alias mismatch (binding.ProviderCode brand alias vs
	// inferredUpstream canonical, e.g. "claude" vs "anthropic") is
	// handled at the proxy.handleAppPipeline call-site where
	// providerCanonicalCode lives — same split as handleProbePipeline.
	if resolved.AppRecord.BoundAlias != "" {
		return resolveBoundAliasBinding(reader, resolved)
	}

	// Binding lookup. Key is (profile_id, upstream_provider).
	binding, err := reader.GetProviderBindingWithScope(resolved.ProfileID, inferredUpstream)
	if err != nil {
		return nil, &ResolveError{
			StatusCode: http.StatusInternalServerError,
			ErrorCode:  "BINDING_READ_FAILED",
			Message: "Failed to read provider binding (profile=\"" + resolved.ProfileID +
				"\", upstream=\"" + inferredUpstream + "\"): " + err.Error(),
		}
	}
	if binding == nil {
		var hint string
		if resolved.ProfileID == "default" {
			hint = "Run `aikey use` to set the default binding for upstream \"" + inferredUpstream + "\"."
		} else {
			hint = "Run `aikey app route " + resolved.AppRoute.AppSlug +
				"` (interactive) — pick a key for upstream \"" + inferredUpstream + "\"."
		}
		return nil, &ResolveError{
			StatusCode: http.StatusNotFound,
			ErrorCode:  "BINDING_NOT_FOUND",
			Message: "No provider binding for app \"" + resolved.AppRoute.AppSlug +
				"\" (profile=\"" + resolved.ProfileID + "\", upstream=\"" + inferredUpstream + "\"). " + hint,
		}
	}
	return binding, nil
}

// resolveBoundAliasBinding is the B-mode credential lookup: dereference
// AppRecord.BoundAlias via the same GetAliasCredential helper the Probe
// pipeline uses, and return its synthesized binding.
//
// Errors map to App-pipeline-shape codes so callers don't need a separate
// branch for B-mode failure handling:
//   - alias lookup vault failure  → 500 BOUND_ALIAS_READ_FAILED
//   - alias row missing            → 404 BOUND_ALIAS_NOT_FOUND
//   - alias status != "active"     → 403 BOUND_ALIAS_REVOKED (revoked)
//     / BOUND_ALIAS_PAUSED (paused)
//     / BOUND_ALIAS_INACTIVE (other)
func resolveBoundAliasBinding(reader VaultReader, resolved *ResolvedAppContext) (*vault.ProviderBinding, *ResolveError) {
	alias := resolved.AppRecord.BoundAlias
	cred, err := reader.GetAliasCredential(alias)
	if err != nil {
		return nil, &ResolveError{
			StatusCode: http.StatusInternalServerError,
			ErrorCode:  "BOUND_ALIAS_READ_FAILED",
			Message: "Failed to look up bound_alias \"" + alias + "\" for app \"" +
				resolved.AppRoute.AppSlug + "\": " + err.Error(),
		}
	}
	if cred == nil {
		return nil, &ResolveError{
			StatusCode: http.StatusNotFound,
			ErrorCode:  "BOUND_ALIAS_NOT_FOUND",
			Message: "App \"" + resolved.AppRoute.AppSlug + "\" is configured in B mode " +
				"with bound_alias=\"" + alias + "\", but that alias is missing from the vault. " +
				"Re-bind via `aikey app update " + resolved.AppRoute.AppSlug + " --bound-alias <name>` " +
				"after running `aikey list` to see available aliases.",
		}
	}
	switch cred.Status {
	case "active":
		return cred.Binding, nil
	case "revoked":
		return nil, &ResolveError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "BOUND_ALIAS_REVOKED",
			Message: "App \"" + resolved.AppRoute.AppSlug + "\" bound_alias \"" + alias +
				"\" is revoked. Re-authorize the credential or re-bind to a different alias.",
		}
	case "paused":
		return nil, &ResolveError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "BOUND_ALIAS_PAUSED",
			Message: "App \"" + resolved.AppRoute.AppSlug + "\" bound_alias \"" + alias +
				"\" is paused. Re-enable it before this app can forward.",
		}
	default:
		return nil, &ResolveError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "BOUND_ALIAS_INACTIVE",
			Message: "App \"" + resolved.AppRoute.AppSlug + "\" bound_alias \"" + alias +
				"\" has status \"" + cred.Status + "\" which is not usable.",
		}
	}
}

// containsString and joinStrings — tiny helpers kept here instead of
// importing strings.Contains/strings.Join to keep the import list flat.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}
