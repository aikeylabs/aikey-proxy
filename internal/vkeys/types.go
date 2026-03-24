package vkeys

// ResolvedRoute contains everything needed to forward a request after
// virtual key resolution.
type ResolvedRoute struct {
	VirtualKeyID  string
	Provider      string   // "openai", "anthropic"
	BaseURL       string   // upstream base URL
	KeyAlias      string   // vault entry alias for real key
	AllowedModels []string // nil means allow all
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
