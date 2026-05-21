package translator

import (
	"context"
	"sync"
)

// Registry maps (from, to, endpoint) tuples to transform functions.
// Pair implementations register themselves via `Register()` (typically
// from a side-effect `func init()` in their package), and the App
// pipeline calls `TranslateRequest` / `TranslateNonStream` at request
// time to perform the actual conversion.
//
// Concurrency: thread-safe. Multiple goroutines may call Translate*
// methods concurrently on the same Registry. Mutation via Register is
// permitted but typically happens only at process startup; runtime
// Register calls are technically supported (e.g. plugin loading) but
// not exercised at MVP.
//
// Why this is a struct (with public NewRegistry + DefaultRegistry)
// instead of just a package-global map: testability. NewRegistry()
// returns an isolated instance so unit tests can register / inspect
// pairs without polluting the package-global. Production code uses
// DefaultRegistry() which is what pair `init()` functions register
// against.
type Registry struct {
	mu sync.RWMutex
	// Internal storage is three-tuple (from, to, endpoint) keyed —
	// MVP only uses EndpointDefault but the storage shape is fixed
	// for forward compatibility. Public API hides the endpoint
	// dimension; see TranslateRequest etc.
	pairs map[pairKey]*pair
}

// pairKey is the internal map key. Defined as a struct (not a string)
// so unrelated changes to Format / Endpoint string formatting don't
// affect Registry's hashing.
type pairKey struct {
	From     Format
	To       Format
	Endpoint Endpoint
}

// pair bundles the transforms for one (from, to, endpoint) tuple.
// `request` is the only transform required at MVP; non-stream response
// is optional (some pairs may want to do request-side conversion only
// and forward the raw upstream response). At阶段 1 we also enforce a
// stream transform pair-by-pair.
type pair struct {
	request  RequestTransform
	response ResponseTransforms
}

// NewRegistry constructs an empty, isolated Registry. Test code uses
// this to avoid colliding with the package-global. Production code
// uses DefaultRegistry().
func NewRegistry() *Registry {
	return &Registry{
		pairs: make(map[pairKey]*pair),
	}
}

// defaultRegistry is the package-global Registry that pair `init()`
// functions register into. Hidden behind DefaultRegistry() so tests
// can verify "is the global initialized" with a single accessor.
var defaultRegistry = NewRegistry()

// DefaultRegistry returns the package-global Registry. Pair packages
// register against this in their `init()` functions; production proxy
// code reads from this Registry at request time. Tests SHOULD use
// `NewRegistry()` instead to avoid global state.
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Register stores transform functions for the (from, to) pair under
// EndpointDefault. This is the dominant MVP API; pair packages call
// it from `init()`. The Endpoint dimension is internal at MVP, so
// there's no `RegisterEndpoint(from, to, endpoint, ...)` exposed
// publicly — 阶段 3 promotes the three-tuple API if Endpoint awareness
// becomes a public concern.
//
// Idempotency contract: re-registering the same (from, to) pair
// OVERWRITES the existing transforms. This makes test setup easier
// (`Register` is the only mutator) and matches CLIProxyAPI's behavior.
// In production this only matters if a plugin re-registers after
// startup, which we don't currently support.
func (r *Registry) Register(from, to Format, req RequestTransform, resp ResponseTransforms) {
	r.registerEndpoint(from, to, EndpointDefault, req, resp)
}

// registerEndpoint is the three-tuple internal version. Kept private
// at MVP so callers can't depend on the Endpoint dimension before
// it's vetted. 阶段 3 promotes this to public (renamed to
// RegisterEndpoint) when Endpoint-aware pairs land.
func (r *Registry) registerEndpoint(from, to Format, ep Endpoint, req RequestTransform, resp ResponseTransforms) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pairs[pairKey{From: from, To: to, Endpoint: ep}] = &pair{
		request:  req,
		response: resp,
	}
}

// HasPair reports whether the (from, to) pair has been registered. The
// App pipeline calls this when deciding "is this inbound→upstream
// combination supported": if !HasPair → caller can fail-fast with a
// precise error instead of silently passing the raw request through
// (which would 400 from the upstream with a confusing message).
//
// EndpointDefault only; the (from, to, endpoint=other) probe is via
// internal hasPairEndpoint.
func (r *Registry) HasPair(from, to Format) bool {
	return r.hasPairEndpoint(from, to, EndpointDefault)
}

func (r *Registry) hasPairEndpoint(from, to Format, ep Endpoint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.pairs[pairKey{From: from, To: to, Endpoint: ep}]
	return ok
}

// TranslateRequest converts an inbound request body from `from` Format
// to `to` Format. Returns the translated bytes on success, or
// *TranslateError on failure (which the caller surfaces via
// e.ToOpenAIShape() + e.HTTPStatus).
//
// When `from == to` (e.g. openai → openai passthrough), the registered
// pair's RequestTransform IS still invoked — pairs may want to do
// per-pair normalization (e.g. model name canonicalization) even on
// "passthrough". Pairs that truly want byte-equal passthrough register
// a transform that returns `body, nil`.
//
// When no (from, to) pair is registered, TranslateRequest returns a
// AIKEY_TRANSLATION_FAILED error (NOT silent passthrough). Callers
// MUST check HasPair before calling, or be prepared to handle this
// error — the explicit error makes "I forgot to register a pair"
// loud at request time rather than producing mysterious upstream 400s.
func (r *Registry) TranslateRequest(
	ctx context.Context,
	from, to Format,
	model string,
	body []byte,
	stream bool,
) ([]byte, *TranslateError) {
	return r.translateRequestEndpoint(ctx, from, to, EndpointDefault, model, body, stream)
}

func (r *Registry) translateRequestEndpoint(
	ctx context.Context,
	from, to Format,
	ep Endpoint,
	model string,
	body []byte,
	stream bool,
) ([]byte, *TranslateError) {
	r.mu.RLock()
	p, ok := r.pairs[pairKey{From: from, To: to, Endpoint: ep}]
	r.mu.RUnlock()
	if !ok || p == nil || p.request == nil {
		return nil, &TranslateError{
			Code:       CodeTranslationFailed,
			HTTPStatus: 500,
			Message: "No translator pair registered for " + string(from) + " → " + string(to) +
				". This is a server-side configuration bug; check that the relevant pair's init() ran.",
		}
	}
	return p.request(ctx, model, body, stream)
}

// TranslateNonStream converts a non-streaming upstream response body
// from `to` Format back to `from` Format (note the swap — a request
// from openai going to anthropic generates an anthropic response which
// must be translated FROM anthropic TO openai). The pair author
// registered this transform under the same (from, to) tuple as the
// request, so the Registry handles the directional swap internally
// by re-using the same key.
//
// 阶段 0 MVP: this is the only response API. 阶段 1 adds
// TranslateStreamChunk for SSE responses.
//
// Like TranslateRequest, when no pair is registered returns a
// AIKEY_TRANSLATION_FAILED error (no silent passthrough).
func (r *Registry) TranslateNonStream(
	ctx context.Context,
	from, to Format,
	body []byte,
) ([]byte, *TranslateError) {
	return r.translateNonStreamEndpoint(ctx, from, to, EndpointDefault, body)
}

func (r *Registry) translateNonStreamEndpoint(
	ctx context.Context,
	from, to Format,
	ep Endpoint,
	body []byte,
) ([]byte, *TranslateError) {
	r.mu.RLock()
	p, ok := r.pairs[pairKey{From: from, To: to, Endpoint: ep}]
	r.mu.RUnlock()
	if !ok || p == nil || p.response.NonStream == nil {
		return nil, &TranslateError{
			Code:       CodeTranslationFailed,
			HTTPStatus: 500,
			Message: "No non-stream response translator for " + string(from) + " → " + string(to) +
				". The pair may exist for requests but not responses; check the pair's init() registers both.",
		}
	}
	return p.response.NonStream(ctx, body)
}
