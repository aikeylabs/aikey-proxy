package apppipe

// credtypes.go — types + interface for credential resolution from a
// provider binding.
//
// Both the legacy `/v1/<provider>/...` pipeline (proxy.handlePathPrefixRoute)
// AND the App pipeline (apppipe.Pipeline.forward — TBD) need to convert
// a `vault.ProviderBinding` into a concrete upstream credential:
//   - personal_oauth_account → broker.EnsureFresh + ResolveCredential
//   - team → vault.GetTeamKeyByID
//   - default (personal) → vault.GetPersonalKeyByAlias
//
// Without a shared contract, the two pipelines would inline-copy the same
// ~80 lines of branching logic. That's a source-of-truth split (CLAUDE.md
// "Source-of-truth 不要分裂") — when the OAuth flow changes (e.g., new
// Codex BaseURL endpoint or new error code), one branch would inevitably
// drift before the other.
//
// Types live in apppipe rather than proxy for cycle reasons: proxy
// already imports apppipe (for ExtractAppPath / Authenticate / Resolve),
// so apppipe must be a "leaf" in the package graph here. Defining the
// types in apppipe + having proxy.Proxy implement the BindingResolver
// interface keeps the existing import direction. If a future refactor
// promotes credtypes to a third package (e.g., proxy/credresolve), the
// move is mechanical.

import (
	"log/slog"
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// BindingCredential is the resolved upstream credential for a provider
// binding. See BindingResolver.ResolveBindingCredential's docstring for
// per-KeySourceType semantics.
type BindingCredential struct {
	// RealKey is the plaintext upstream secret. Empty for the OAuth
	// path (KeyAlias = "__oauth__" sentinel signals oauthInject already
	// mutated request headers); non-empty for team / personal paths
	// where the caller injects RealKey into the outbound request.
	RealKey string
	// VirtualKeyID is the route's stable identifier, used by reportable.go's
	// deriveKeyLabel: "oauth:<account_id>" / "personal:<alias>" / team's vk_id.
	VirtualKeyID string
	// KeyAlias is the user-facing label for personal / team routes.
	// Empty for OAuth (which uses OAuthIdentity in deriveKeyLabel).
	KeyAlias string
	// BaseURL is the upstream the caller will reverse-proxy to. Includes
	// the Codex override (chatgpt.com/backend-api/codex) for OAuth +
	// openai canonicalCode.
	BaseURL string
	// OAuthIdentity is the user-visible identity (email / display name)
	// for OAuth credentials. Used by deriveKeyLabel and audit events.
	OAuthIdentity string
	// OAuthAccountID is the broker account identifier for OAuth credentials.
	OAuthAccountID string
	// ManagedKey carries team-key metadata (OrgID / SeatID / CredentialID /
	// VirtualKeyRevision) that flows into usage events for team-key paths.
	// nil for OAuth and personal paths.
	ManagedKey *vault.ManagedKey
}

// BindingResolveError represents an OAuth resolution failure that the
// caller MUST surface as a JSON error response. Returned only for the
// OAuth path; team / personal paths fail soft (empty BindingCredential
// fields → caller falls back to legacy resolution).
type BindingResolveError struct {
	StatusCode int    // HTTP status code (503 / 401)
	ErrorType  string // body.error.type (server_error / auth_error)
	ErrorCode  string // body.error.code
	Message    string // body.error.message
}

func (e *BindingResolveError) Error() string { return e.ErrorCode + ": " + e.Message }

// BindingResolver is the contract callers (legacy proxy + App pipeline)
// use to convert a ProviderBinding into a concrete credential. The
// production implementation is proxy.Proxy itself — its method
// ResolveBindingCredential satisfies this interface.
//
// The interface is here (not in proxy) to avoid an import cycle: proxy
// already imports apppipe, so apppipe owns the contract and proxy
// fulfillls it.
type BindingResolver interface {
	ResolveBindingCredential(
		r *http.Request,
		binding *vault.ProviderBinding,
		providerCode, canonicalCode string,
		logger *slog.Logger,
	) (*BindingCredential, *BindingResolveError)
}
