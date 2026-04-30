package provider

import "github.com/AiKeyLabs/pkg/providerroutes"

// Routes returns the process-wide provider routing table — a thin
// re-export of pkg/providerroutes.Default() so callers in this package
// don't need to import the leaf package directly.
func Routes() *providerroutes.Table {
	return providerroutes.Default()
}
