package mcp

// auth.go — bearer → (org, seat), by reusing the virtual keys the customer
// already has (decision D-2, requirement R-D-2).
//
// # 🔴 The one design statement in this file
//
// There is no second credential system. The MCP plane resolves the SAME
// virtual key the developer's LLM traffic already uses, through the SAME
// registry (internal/vkeys). Handing a customer a second kind of token to
// issue, rotate and revoke would double the credential surface for zero
// security benefit — and would guarantee that one of the two revocation paths
// eventually gets forgotten.
//
// It also means MCP inherits VK revocation for free: the supervisor drops a
// revoked token from the registry, and the very next MCP request fails to
// resolve. Nothing MCP-specific has to know that revocation happened.
//
// # Why RFC 9728 metadata exists here at all
//
// 🚫 It is NOT "OAuth support", and sales may not describe it as such (tasks
// 1.8b). It exists so a spec-compliant MCP client DEGRADES GRACEFULLY. Without
// the document, such a client tries dynamic client registration, gets nothing,
// and hangs. With it — and specifically with `authorization_servers` present
// as an EXPLICIT EMPTY ARRAY — the client reads "bearer accepted, no
// authorization server offered" and tells its user to paste a token, which is
// the outcome we actually want.
//
// 🔴 Omitting the field would NOT mean the same thing: an absent field means
// "no statement made", and clients treat that as "go discover". The empty array
// is a statement. This distinction is task 1.8a and it is the entire difference
// between a client that prompts and a client that hangs.

import (
	"net/http"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// Identity is who a request is from, after bearer resolution.
type Identity struct {
	OrgID  string
	SeatID string
	// Token is retained for downstream accounting (the call record is attributed
	// to the key, not just the seat). 🔴 It never leaves the process and never
	// enters a log line or an API response — R7.
	Token string
}

// AuthError carries the three coupled values an HTTP layer needs.
//
// Same shape as apppipe.AuthError for the LLM plane, kept local rather than
// imported because apppipe's failure modes are about /apps/<slug> URLs and
// mixing the two vocabularies would produce messages that mention the wrong
// product surface.
type AuthError struct {
	Code       mcpwire.ErrorCode
	Message    string
	StatusCode int
}

// TokenResolver is the slice of vkeys.Registry this package needs.
//
// An interface rather than the concrete *vkeys.Registry so tests can drive the
// real handler with a two-line stub instead of standing up a vault. The
// production wiring passes the real registry.
type TokenResolver interface {
	Resolve(token string) *vkeys.ResolvedRoute
}

// extractBearer reads the bearer from an MCP request.
//
// 🔴 Authorization: Bearer ONLY — deliberately narrower than the LLM plane,
// which also accepts `x-api-key` for Anthropic-style SDKs. MCP clients are
// specified to use Authorization; accepting a second header here would invent a
// non-standard extension that third-party clients would then start depending
// on, and we would own it forever.
func extractBearer(h http.Header) string {
	auth := h.Get("Authorization")
	if auth == "" {
		return ""
	}
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		// Some clients send "bearer" lower-case. RFC 7235 says the scheme is
		// case-insensitive, so rejecting it would be us being wrong, not them.
		if token, ok = strings.CutPrefix(auth, "bearer "); !ok {
			return ""
		}
	}
	return strings.TrimSpace(token)
}

// Authenticate resolves the request's bearer to an identity.
//
// 🔴 Every failure is 401 with the same message shape. We do NOT distinguish
// "no token" from "unknown token" from "revoked token" in the response, because
// the caller's next action is identical in all three cases and the differences
// would let an unauthenticated prober enumerate which tokens once existed. The
// distinction IS available to the operator in logs.
func Authenticate(h http.Header, reg TokenResolver) (Identity, *AuthError) {
	if reg == nil {
		// A wiring fault, not a request fault. 503 rather than 401: telling the
		// user "your credentials are wrong" when the server never loaded its
		// registry sends them to debug the one thing that is fine.
		return Identity{}, &AuthError{
			Code:       mcpwire.ErrCredentialMissing,
			StatusCode: http.StatusServiceUnavailable,
			Message: "The MCP gateway is not ready: its key registry has not loaded. " +
				"Retry shortly; if it persists, restart aikey-proxy.",
		}
	}

	token := extractBearer(h)
	if token == "" {
		return Identity{}, unauthenticated()
	}
	route := reg.Resolve(token)
	if route == nil {
		return Identity{}, unauthenticated()
	}
	return Identity{OrgID: route.OrgID, SeatID: route.SeatID, Token: token}, nil
}

func unauthenticated() *AuthError {
	return &AuthError{
		// 🔴 MCP_TOOL_FORBIDDEN would be wrong here: that code means "this seat
		// exists and is not granted this tool", which is a different problem
		// with a different fix. Authentication failure has no frozen MCP_ code
		// because the transport answers it with a 401 + WWW-Authenticate, which
		// is what the spec tells clients to look for.
		Code:       "",
		StatusCode: http.StatusUnauthorized,
		Message: "Missing or unrecognised bearer token. Set the Authorization header to " +
			"`Bearer <your AiKey virtual key>`; run `aikey list` to see yours.",
	}
}

// WWWAuthenticate is the value of the WWW-Authenticate header on a 401.
//
// 🔴 The resource_metadata parameter is what makes the 401 USEFUL rather than
// merely correct: RFC 9728 clients follow it to the metadata document, read
// that no authorization server is offered, and prompt the user for a token —
// instead of hanging in a discovery loop. Fence 1.F4 asserts the header shape.
func WWWAuthenticate(externalBaseURL string) string {
	return `Bearer realm="AiKey MCP Gateway", ` +
		`resource_metadata="` + strings.TrimSuffix(externalBaseURL, "/") +
		`/.well-known/oauth-protected-resource"`
}

// ProtectedResourceMetadata is the RFC 9728 document served at
// GET /.well-known/oauth-protected-resource.
type ProtectedResourceMetadata struct {
	// Resource is the canonical identifier of this protected resource.
	Resource string `json:"resource"`
	// AuthorizationServers is 🔴 ALWAYS emitted, even when empty.
	//
	// 🚫 Never add `omitempty` to this field. An empty array says "bearer
	// accepted, no authorization server offered" and makes a compliant client
	// prompt for a token. An ABSENT field says "no statement made" and makes
	// the same client go looking, then hang. That is task 1.8a, and the two
	// differ by one struct tag.
	AuthorizationServers []string `json:"authorization_servers"`
	// BearerMethodsSupported tells clients where to put the token.
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	// ResourceDocumentation points a stuck human at the instructions.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// NewProtectedResourceMetadata builds the document for this deployment.
func NewProtectedResourceMetadata(externalBaseURL string) ProtectedResourceMetadata {
	base := strings.TrimSuffix(externalBaseURL, "/")
	return ProtectedResourceMetadata{
		Resource:               base + "/mcp",
		AuthorizationServers:   []string{},
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  "https://docs.aikeylabs.com/mcp",
	}
}
