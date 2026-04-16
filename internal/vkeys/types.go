package vkeys

// ResolvedRoute contains everything needed to forward a request after
// virtual key resolution.
type ResolvedRoute struct {
	VirtualKeyID  string
	Provider      string   // "openai", "anthropic"
	BaseURL       string   // upstream base URL
	KeyAlias      string   // vault entry alias for real key (static config keys)
	AllowedModels []string // nil means allow all
	// PlaintextKey is set for team-managed virtual keys loaded from
	// managed_virtual_keys_cache.  When non-empty it is used directly,
	// bypassing the per-request vault alias lookup.
	PlaintextKey string

	// Anchor fields for usage reporting.
	// For team-managed keys: populated from ManagedKey metadata.
	// For OAuth accounts: OAuthIdentity is the email/display name (for audit only).
	OrgID              string
	AccountID          string
	SeatID             string
	OAuthIdentity      string // Email or display name (OAuth only, for audit/usage reporting)
	BindingID          string // empty if not available in local cache (schema gap)
	ProviderID         string // empty if not available in local cache (schema gap)
	ProviderCode       string
	ProtocolType       string
	CredentialID       string
	CredentialRevision string
	VirtualKeyRevision string
}

// IsModelAllowed checks if the given model is permitted by this route.
// Returns true if AllowedModels is nil/empty (all models allowed).
func (r *ResolvedRoute) IsModelAllowed(model string) bool {
	if len(r.AllowedModels) == 0 {
		return true
	}
	for _, m := range r.AllowedModels {
		if m == model {
			return true
		}
	}
	return false
}
