package provider

import (
	_ "embed"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// v4.3 (2026-05-01) · provider routes config table.
//
// Source of truth: aikey-cli/data/provider_fingerprint.yaml `provider_routes`.
// `make sync-fingerprint` (transitive dep of `make build`) copies that file
// into aikey-proxy/data/ so go:embed can pick it up at compile time.
//
// Why embed at compile time (vs runtime read):
//   - No deployment file dependency (zero install-path drift)
//   - One source of truth at HEAD; the cli + proxy + web fallback all
//     reference the same yaml content
//   - Build fails loud if the sync step is skipped → discoverable
//
// Lookup is keyed by host (exact, case-insensitive). Multi-host providers
// (kimi family covers both api.kimi.com and api.moonshot.cn) appear as
// multiple rows sharing the same `provider` field but different `base_url`.

//go:embed data/provider_fingerprint.yaml
var fingerprintYAML []byte

// ProviderRoute mirrors the yaml row schema. Keep field names aligned with
// aikey-cli (Rust struct ProviderRoute) so the wire/embed payloads stay
// interchangeable for tests and rules export.
type ProviderRoute struct {
	Host     string `yaml:"host"`
	Protocol string `yaml:"protocol"`
	Provider string `yaml:"provider"`
	BaseURL  string `yaml:"base_url"`
	Version  string `yaml:"version"`
}

// providerFingerprint matches the subset of the yaml we consume in proxy.
// The full yaml has many more fields used only by the cli — we ignore them
// silently (yaml.v3 Decode does not require exhaustive keys).
type providerFingerprint struct {
	ProviderRoutes []ProviderRoute `yaml:"provider_routes"`
}

var (
	routesOnce sync.Once
	routesByHost map[string]ProviderRoute
)

func loadRoutes() {
	var fp providerFingerprint
	if err := yaml.Unmarshal(fingerprintYAML, &fp); err != nil {
		// Embedded yaml is a build-time asset; a parse failure here means
		// the embedded file is malformed, which would have failed cli
		// tests too. Panic is acceptable — we want the binary to refuse
		// to start rather than silently route requests with no table.
		panic("aikey-proxy: malformed embedded provider_fingerprint.yaml: " + err.Error())
	}
	routesByHost = make(map[string]ProviderRoute, len(fp.ProviderRoutes))
	for _, r := range fp.ProviderRoutes {
		routesByHost[strings.ToLower(r.Host)] = r
	}
}

// providerRouteByHost looks up the route declaration for an exact host
// (case-insensitive). Returns ok=false when the host isn't in the table —
// caller decides the fallback (typically: degraded literal-prepend until
// the host is added to yaml provider_routes).
func providerRouteByHost(host string) (ProviderRoute, bool) {
	routesOnce.Do(loadRoutes)
	r, ok := routesByHost[strings.ToLower(host)]
	return r, ok
}

// AllProviderRoutes returns every loaded route. Used by tests and any
// admin/diagnostic endpoint that wants to surface the full table.
func AllProviderRoutes() []ProviderRoute {
	routesOnce.Do(loadRoutes)
	out := make([]ProviderRoute, 0, len(routesByHost))
	for _, r := range routesByHost {
		out = append(out, r)
	}
	return out
}
