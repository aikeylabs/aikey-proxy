package provider

import (
	"strings"
	"sync/atomic"

	"github.com/AiKeyLabs/pkg/providerregistry"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// routesOverride is nil in every production build. See OverrideRoutesForTest.
var routesOverride atomic.Pointer[providerroutes.Table]

// Routes returns the process-wide provider routing table — a thin
// re-export of pkg/providerroutes.Default() so callers in this package
// don't need to import the leaf package directly.
func Routes() *providerroutes.Table {
	if t := routesOverride.Load(); t != nil {
		return t
	}
	return providerroutes.Default()
}

// OverrideRoutesForTest swaps the routing table and returns a restore func.
//
// # 🔴 Why production code carries a test seam
//
// The table is keyed by HOST, and the embedded yaml only knows real vendor
// hosts. So anything that depends on a request being MAPPED — model mapping and
// the response-side model restoration it implies — simply does not engage
// against an `httptest` server on 127.0.0.1, and every test of that behavior
// silently exercises the passthrough path instead.
//
// That is not hypothetical. The response-truncation defect
// (response_content_length_test.go) lives entirely inside the mapped path, and
// the first attempt to fence it with a plain httptest upstream PASSED WITHOUT
// THE FIX — green because no mapping occurred, i.e. green for the wrong reason.
// A seam that lets a test name its own host is what makes the difference between
// a fence and a decoration.
//
// 🚫 Not for production wiring. Nothing outside _test.go may call this: the
// table is a build-time asset whose digest is the provenance stamp the
// diagnostics endpoint reports, and a runtime override would make that stamp a
// lie about what is actually routing traffic.
func OverrideRoutesForTest(t *providerroutes.Table) (restore func()) {
	prev := routesOverride.Load()
	routesOverride.Store(t)
	return func() { routesOverride.Store(prev) }
}

// CanonicalCode normalizes the provider aliases accepted at client-facing
// boundaries to the canonical provider code used by the route table.
//
// The alias table is READ FROM aikey-cli/data/provider_registry.yaml via
// pkg/providerregistry. It used to be a switch here, duplicating the same 15
// mappings the Rust CLI and the web bundles already derive from that yaml —
// which requirement spec
// workflow/CI/requirements/2026-07-18-provider-protocol-compatibility-and-baseurl.md
// §10 prohibits ("不得维护硬编码 switch 作为第二套静默真相源"). Adding a provider
// is now a one-line yaml edit; the package's SHA gate fails the build if the
// embedded copy drifts from the canonical source.
//
// Unknown input is returned lowercased and trimmed rather than rejected,
// matching Rust's provider_registry::canonical() exactly — see the note on
// Registry.Canonical for why that passthrough must not be "fixed".
func CanonicalCode(providerCode string) string {
	return providerregistry.Default().Canonical(providerCode)
}

// CanonicalProtocol normalizes legacy protocol spellings to the route-table
// vocabulary. Provider is an independent axis: this function never derives a
// protocol from a provider.
//
// NOTE: unlike CanonicalCode this stays a switch, because PROTOCOL aliases have
// no source of truth yet — provider_registry.yaml describes providers, and
// provider_fingerprint.yaml's rows carry a protocol value but no alias table for
// it. Left as-is deliberately rather than folded into the registry, which would
// put protocol vocabulary in a file whose declared scope is provider identity.
func CanonicalProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "openai":
		return "openai_compatible"
	case "google":
		return "gemini"
	case "claude":
		return "anthropic"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

// ProtocolFamily resolves the upstream wire protocol from the independent
// provider + protocol axes. Multi-protocol providers deliberately fail closed
// when protocolHint is missing or invalid; silently choosing their first YAML
// row would make routing depend on row order.
//
// The single-protocol fallback keeps legacy credentials (whose protocol_type
// predates the two-axis model and may therefore be empty) working.
func ProtocolFamily(providerCode, protocolHint string) (string, bool) {
	providerCode = CanonicalCode(providerCode)
	protocolHint = CanonicalProtocol(protocolHint)
	if route, ok := Routes().ByProviderProtocol(providerCode, protocolHint); ok {
		return route.Protocol, true
	}
	protocols := Routes().ProtocolsForProvider(providerCode)
	if len(protocols) == 1 {
		return protocols[0], true
	}
	// 2026-08-02 (provider-credential-cascade): a provider having exactly one
	// protocol used to be the ONLY way a protocol-less credential could resolve.
	// Giving deepseek / moonshot / qwen / doubao / minimax their anthropic faces
	// falsified that premise for five providers at once, so every legacy
	// credential on them would have begun answering
	// `502 Unknown provider protocol: `. (zhipu had been multi-protocol since
	// 2026-05 and was already failing exactly this way — unnoticed, because
	// nothing compared the two eras.)
	//
	// LegacyProtocolForProvider answers the narrower, still-truthful question:
	// which face did this provider serve on its BARE HOST, i.e. the one a
	// credential predating the protocol axis must have been created against.
	// It is not row order — a second face always arrives with an explicit
	// path_prefix, so it cannot move this answer.
	//
	// Still fail-closed when even that is ambiguous (mock has no bare-host row):
	// a provider with no protocol-less era should surface the bug rather than
	// have one guessed for it.
	return Routes().LegacyProtocolForProvider(providerCode)
}

// ProtocolFamilyForCredential answers a DIFFERENT question from ProtocolFamily,
// which is why it is a second function and not a flag on the first one.
//
//	ProtocolFamily              — "what protocol does the routing table say this
//	                               provider speaks?"
//	ProtocolFamilyForCredential — "this credential DECLARES a protocol; may that
//	                               declaration stand as the answer?"
//
// # Why this exists (2026-08-25)
//
// The console's third-party mode lets an administrator register a custom
// provider code with a hand-typed base_url (that dialog's own help text
// recommends it for Ollama / LM Studio / vLLM), and master deliberately waves
// such a provider through — see aikey-control-master
// internal/provider/service.go validateProviderProtocol, whose test asserts
// "custom provider absent from matrix — allowed". The Rust CLI agrees:
// client_route_for_binding falls back to the protocol's client surface for an
// unknown provider. The proxy was the only one of the three that failed closed,
// so every such credential could be created, displayed as a working channel,
// and then answered 502 on the first request.
//
// The requirement spec never said which of the two behaviours was right —
// see 「自定义第三方供应商」 in
// workflow/CI/requirements/2026-07-18-provider-protocol-compatibility-and-baseurl.md,
// added with this change. The rule it now states: a provider ABSENT from the
// routing table has no table row to contradict it, so its credential's own
// protocol_type is the truth.
//
// bugfix: workflow/CI/bugfix/20260825-custom-thirdparty-provider-axes-rejected.md (regression: make -C aikey-proxy test-bugfix-custom-provider-axes)
//
// # Why widening here is not a hole in the compatibility matrix
//
// Three conditions must all hold, and each one closes a distinct escape:
//
//  1. the provider must be ABSENT from the table — a provider that HAS rows is
//     still judged by them, so zhipu+gemini stays rejected;
//  2. the declaration must be non-empty — an empty protocol_type carries no
//     information, so it keeps failing closed exactly as before;
//  3. the declared protocol must be one the table's rows actually use, so a
//     typo or an invented protocol is refused here rather than deeper in.
//
// ⚠️ Condition 3 is a VOCABULARY check, not an "an adapter exists" check — the
// two are not the same. `gemini` is in the vocabulary (google has rows) while
// the proxy ships no gemini adapter, so a custom provider declaring `gemini` is
// admitted here and then refused by Registry.Get with
// `unknown provider protocol "gemini"`. That is deliberate: it is EXACTLY what
// `google` + `gemini` does today, and making custom providers stricter than the
// vendor whose protocol they borrow would be its own inconsistency. See the
// gemini note in provider_registry.yaml for why the row outlives the adapter.
//
// 🚫 Do NOT use this for the client-route half of an axes check. That question
// is "can this client surface carry this protocol", and answering it with the
// caller's own declaration makes it self-satisfying — see the note at the
// second ProtocolFamily call in proxy/binding_axes.go.
func ProtocolFamilyForCredential(providerCode, declaredProtocol string) (string, bool) {
	if fam, ok := ProtocolFamily(providerCode, declaredProtocol); ok {
		// Known provider: byte-identical to the strict path, including its
		// legacy/single-protocol fallbacks.
		return fam, true
	}
	protocol := CanonicalProtocol(declaredProtocol)
	if protocol == "" {
		return "", false // condition 2
	}
	if len(Routes().ProtocolsForProvider(CanonicalCode(providerCode))) > 0 {
		return "", false // condition 1: the table has rows for it, so the table decides
	}
	if len(Routes().ProvidersForProtocol(protocol)) == 0 {
		return "", false // condition 3: no row anywhere speaks it, so no adapter does either
	}
	return protocol, true
}

// FamilyOf exposes the registry's provider family (e.g. kimi_code and
// moonshot both belong to the `kimi` family). Used by the active-key matcher
// to accept a legacy route-shaped entry without hard-coding which suppliers
// a route may use — provider_registry.yaml owns that.
func FamilyOf(providerOrAlias string) (string, bool) {
	return providerregistry.Default().Family(providerOrAlias)
}
