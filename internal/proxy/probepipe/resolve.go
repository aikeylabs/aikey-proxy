package probepipe

// resolve.go — Probe pipeline alias resolution stage.
//
// Looks up the URL alias in the vault (via vault.Reader.GetAliasCredential)
// and maps the result into a synthetic ProviderBinding plus structured
// status. The downstream handler reuses the same ResolveBindingCredential
// machinery that the App / legacy pipelines use, so OAuth WAF fingerprint
// injection / personal-key decrypt / managed-key fetch logic is shared.

import (
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// VaultReader is the minimal vault surface probepipe depends on.
// *vault.Reader satisfies it; tests can supply a focused stub.
type VaultReader interface {
	GetAliasCredential(name string) (*vault.AliasCredential, error)
}

// ResolveError represents an alias lookup that cannot proceed: row missing,
// status non-active, or vault read failure. Carries HTTP status + error
// code + message so the handler can render JSON without further mapping.
type ResolveError struct {
	StatusCode int
	ErrorCode  string
	Message    string
}

func (e *ResolveError) Error() string { return e.ErrorCode + ": " + e.Message }

// Resolve looks up ctx.AliasName in the vault and returns the resolved
// credential (with a synthetic ProviderBinding) when status is "active".
//
// Error mappings per SPEC §1.3:
//   - vault reader missing       → 503 PROBE_VAULT_NOT_AVAILABLE
//   - vault read failed          → 500 VAULT_READ_FAILED
//   - alias not found            → 404 ALIAS_NOT_FOUND
//   - alias status="revoked"     → 403 ALIAS_REVOKED
//   - alias status="paused"      → 403 ALIAS_PAUSED
//   - alias other non-active     → 403 ALIAS_INACTIVE
func Resolve(reader VaultReader, ctx *ProbeContext) (*vault.AliasCredential, *ResolveError) {
	if reader == nil {
		return nil, &ResolveError{
			StatusCode: http.StatusServiceUnavailable,
			ErrorCode:  "PROBE_VAULT_NOT_AVAILABLE",
			Message: "Server is not ready (vault reader not wired for Probe pipeline). " +
				"Restart proxy or retry shortly.",
		}
	}

	cred, err := reader.GetAliasCredential(ctx.AliasName)
	if err != nil {
		return nil, &ResolveError{
			StatusCode: http.StatusInternalServerError,
			ErrorCode:  "VAULT_READ_FAILED",
			Message:    "Failed to look up alias \"" + ctx.AliasName + "\" in vault: " + err.Error(),
		}
	}
	if cred == nil {
		return nil, &ResolveError{
			StatusCode: http.StatusNotFound,
			ErrorCode:  "ALIAS_NOT_FOUND",
			Message: "Alias \"" + ctx.AliasName + "\" not found in vault. Run " +
				"`aikey list` to see available aliases — personal keys appear " +
				"by `entries.alias`, OAuth accounts by `local_alias` or " +
				"`display_identity` (typically email).",
		}
	}

	switch cred.Status {
	case "active":
		return cred, nil
	case "revoked":
		return nil, &ResolveError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "ALIAS_REVOKED",
			Message: "Alias \"" + ctx.AliasName + "\" is revoked and cannot be " +
				"used. Re-authorize via the provider's login flow " +
				"(`aikey claude login` / `aikey codex login` / etc.) before probing.",
		}
	case "paused":
		return nil, &ResolveError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "ALIAS_PAUSED",
			Message: "Alias \"" + ctx.AliasName + "\" is paused. Re-enable it " +
				"before probing.",
		}
	default:
		return nil, &ResolveError{
			StatusCode: http.StatusForbidden,
			ErrorCode:  "ALIAS_INACTIVE",
			Message: "Alias \"" + ctx.AliasName + "\" has status \"" + cred.Status +
				"\" which is not usable.",
		}
	}
}
