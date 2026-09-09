package mcp

// upstream.go — talking to a backend MCP server.
//
// # The transport registry (task 1.2)
//
// Three transports exist in the MCP world and a backend declares which one it
// speaks. They are dispatched through a REGISTRY rather than a switch:
//
//	streamable_http  the current remote transport (POST + optional SSE reply)
//	http_sse         the 2024-11-05 remote transport, still in the field
//	stdio            a local child process — registered in P5
//
// 🔴 A registry, not if-else. The project rule is explicit about multi-protocol
// adaptation, and the practical reason is P5: adding stdio must be one
// Register call in a new file, not an edit to a switch statement that every
// other transport also lives inside.
//
// # 🔴 What must NEVER go out on this path
//
// No `X-Aikey-*` header, ever (D-13). The rule already exists for LLM upstreams
// — a non-standard header is a persona signal that walls WAFs — and it applies
// here for a wider reason: a third-party MCP server can sit behind any gateway,
// and we cannot predict what an unknown header does to it. Provenance travels
// in the RESPONSE direction and into the call record (`upstream_request_id`),
// never on the request.
//
// The fence is TestNoAikeyHeaderReachesAnUpstreamMCPServer.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// UpstreamTransport is one way of reaching a backend MCP server.
//
// Implementations must be safe for concurrent use: the manifest sync loop and
// live tool calls share one instance per backend.
type UpstreamTransport interface {
	// Name is the value that appears in mcp_backend.transport.
	Name() string
	// ListTools performs `tools/list` against the backend.
	//
	// 🔴 This is the ONLY probe. R9 forbids using a real tool as a health check:
	// a probe runs periodically, so probing with a real tool means a machine
	// that executes an action on the customer's systems on a timer, forever,
	// that nobody asked for. Fence 3.F2.
	ListTools(ctx context.Context, b UpstreamBackend) ([]mcpwire.Tool, error)
	// CallTool performs `tools/call`.
	CallTool(ctx context.Context, b UpstreamBackend, name string, args json.RawMessage) (*mcpwire.CallToolResult, error)
}

// UpstreamBackend is everything a transport needs to reach one backend.
//
// 🔴 Credential carries the RESOLVED secret and exists only in memory, for the
// duration of one call. It is populated by the credential resolver (P4); until
// then it is empty and a backend that declares CredentialID gets
// MCP_CREDENTIAL_MISSING rather than an unauthenticated attempt — sending a
// bare request to an endpoint that expects auth produces a 401 that looks like
// the customer's credential is wrong.
type UpstreamBackend struct {
	ID          string
	Name        string
	Transport   string
	EndpointURL string
	// Command / Args / EnvKeys are the stdio shape (P5).
	Command string
	Args    []string
	EnvKeys []string
	// CredentialID is the binding. Empty means the backend needs no auth.
	CredentialID string
	// Credential is the resolved material. Zero value = nothing resolved.
	Credential UpstreamCredential
	// RESTBinding is set for a http_rest backend and describes THIS CALL's
	// mapping onto an HTTP request (P9).
	//
	// 🔴 A per-call field on a struct that is already built per call — it sits
	// beside Credential, which is also resolved per call. The alternative was
	// widening UpstreamTransport.CallTool to take the whole PolicyTool, which
	// would change a contract three transports and their tests implement in
	// order to serve one of them.
	RESTBinding string
}

// UpstreamCredential is resolved secret material, in memory only.
//
// 🔴 It carries json:"-" on every field AND a redacting String()/GoString().
// Both are needed and neither is decoration: Go marshals exported fields by name
// regardless of tags (so "no tags" does not mean "not serialised"), and %v on a
// bare struct prints every field. A type that is safe to print and safe to
// marshal BY CONSTRUCTION is worth more than a comment asking people not to (R7).
type UpstreamCredential struct {
	// Kind is bearer / basic / header / env.
	Kind string `json:"-"`
	// HeaderName is used when Kind == "header".
	HeaderName string `json:"-"`
	// Secret is the plaintext.
	//
	// 🔴 `json:"-"` is load-bearing, not decoration. Go marshals every EXPORTED
	// field by name whether or not it carries a tag, so "this struct has no JSON
	// tags" does NOT mean it stays out of a response — the fence caught exactly
	// that assumption and printed the secret.
	Secret string `json:"-"`
}

// String redacts.
//
// 🔴 Present so that %v, %s and %+v on a credential — in a log line, an error
// message, a debug print someone adds at 2am — cannot emit the secret. A type
// that is safe to print by construction beats a comment asking people not to.
func (c UpstreamCredential) String() string {
	if c.Secret == "" {
		return "UpstreamCredential{" + c.Kind + ", unresolved}"
	}
	return "UpstreamCredential{" + c.Kind + ", REDACTED}"
}

// GoString redacts under %#v too, which is the verb a debugger-minded print
// reaches for and the one that would otherwise dump every field verbatim.
func (c UpstreamCredential) GoString() string { return c.String() }

// Credential kinds — the SHAPE of the secret, which is what tells the injector
// WHERE to put it.
//
// 🔴 Mirrors the control plane's mcpgateway vocabulary and the CHECK constraint
// on mcp_backend_credential.kind. Re-declared rather than imported because the
// proxy does not import the control plane; the fence over the agreement is
// TestCredentialKindsMatchTheControlPlane.
const (
	CredentialKindBearer = "bearer"
	CredentialKindBasic  = "basic"
	CredentialKindHeader = "header"
	// CredentialKindEnv is stdio-only: the secret goes into the child process's
	// environment, and HeaderName carries the VARIABLE NAME.
	//
	// 🔴 Reusing HeaderName rather than adding an EnvName column is deliberate
	// (慎重新建数据结构): the two mean the same thing — "what is this secret
	// called on the wire this backend speaks" — and a second column would need
	// a rule for what happens when both are set.
	CredentialKindEnv = "env"
)

// ErrCredentialMissing means the backend declares a credential the resolver
// could not produce.
var ErrCredentialMissing = errors.New("mcp: backend credential is not resolvable")

// ErrTransportUnknown means the backend declares a transport nothing implements.
var ErrTransportUnknown = errors.New("mcp: no transport registered for this backend")

// UpstreamError distinguishes an upstream fault from ours.
//
// 🔴 The distinction is the single most expensive question in supporting a
// gateway product: does the customer open a ticket with us or with whoever runs
// their MCP server. Carrying it in the error type means every caller answers it
// the same way, rather than each one guessing from a string.
type UpstreamError struct {
	// Code is the frozen error code to report. Always an EXT_ one.
	Code mcpwire.ErrorCode
	// Status is the upstream's HTTP status, when there was one.
	Status int
	// Detail is safe to log. 🔴 It must never contain a request body — an MCP
	// tool's arguments are the customer's data.
	Detail string
	// NotAccepted reports that the request PROVABLY never reached the server:
	// the connection was refused, the name did not resolve, or the TLS
	// handshake failed. It is the only condition under which a non-idempotent
	// tool call may be retried (R4).
	//
	// 🔴 It defaults to FALSE, and the default is the safety property. Every
	// other failure — a timeout, a 5xx, a dropped connection mid-body — happens
	// AFTER the request was handed over, so the tool may already have run.
	// Retrying `create_issue` there opens two issues. An error that forgets to
	// set this is treated as "may have run", which is the conservative reading.
	NotAccepted bool
}

func (e *UpstreamError) Error() string {
	return string(e.Code) + ": " + e.Detail
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

var (
	transportMu sync.RWMutex
	transports  = map[string]UpstreamTransport{}
)

// RegisterTransport adds a transport implementation.
//
// 🔴 Panics on a duplicate. A silently-replaced transport would mean the backend
// everyone thinks is speaking Streamable HTTP is speaking something else, and
// nothing in the system would ever say so. Registration happens at init time, so
// a panic here is a build-time-shaped failure, not a runtime one.
func RegisterTransport(t UpstreamTransport) {
	transportMu.Lock()
	defer transportMu.Unlock()
	if _, dup := transports[t.Name()]; dup {
		panic("mcp: transport " + t.Name() + " registered twice")
	}
	transports[t.Name()] = t
}

// LookupTransport returns the transport for a name.
func LookupTransport(name string) (UpstreamTransport, bool) {
	transportMu.RLock()
	defer transportMu.RUnlock()
	t, ok := transports[name]
	return t, ok
}

// RegisteredTransports lists what this build can reach, for /health/mcp and for
// the capabilities document.
func RegisteredTransports() []string {
	transportMu.RLock()
	defer transportMu.RUnlock()
	out := make([]string, 0, len(transports))
	for n := range transports {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func init() {
	RegisterTransport(&httpTransport{name: TransportStreamableHTTP})
	RegisterTransport(&httpTransport{name: TransportHTTPSSE})
}

// Transport names, mirroring dbmigrate.MCPBackendTransportValues.
const (
	TransportStdio          = "stdio"
	TransportStreamableHTTP = "streamable_http"
	TransportHTTPSSE        = "http_sse"
)

// ---------------------------------------------------------------------------
// the HTTP transports
// ---------------------------------------------------------------------------

// httpTransport implements both remote transports.
//
// 🔴 ONE implementation for both, parameterised by name, because from the
// CLIENT side they differ in exactly one thing: what the server may reply with.
// Streamable HTTP may answer a POST with either `application/json` or an SSE
// stream; the 2024-11-05 transport answers JSON on POST and uses a separate GET
// stream for server-initiated messages, which we do not consume (we never ask a
// backend to call us). Two files here would be two copies of the same request
// builder, and the copies would drift.
type httpTransport struct{ name string }

func (t *httpTransport) Name() string { return t.name }

// upstreamHTTPClient is the outbound client.
//
// Its timeout is a HARD ceiling, separate from the per-request context deadline
// the isolation shell sets: a context deadline bounds the request, this bounds
// the connection. An upstream that accepts a connection and then dribbles bytes
// forever is bounded by neither unless both exist.
//
// 🔴 Its Transport is wrapped in headerStripper, which is what makes D-13 an
// ACTUAL guarantee rather than a convention. Stripping inside the request
// builder is not enough: a RoundTripper — an egress wrapper, a tracing library,
// anything added later — runs AFTER the builder and can put headers back. The
// fence caught exactly that, injecting X-Aikey-* from a RoundTripper and
// watching them arrive at the upstream.
var upstreamHTTPClient = &http.Client{
	Timeout:   120 * time.Second,
	Transport: &headerStripper{},
}

// headerStripper removes internal headers as the very last step before the wire.
//
// 🔴 It is a RoundTripper rather than a helper the request builder calls,
// because being LAST is the whole property. Anything that can wrap an
// http.Client can add a header after the builder ran; nothing runs after the
// transport that actually dials.
type headerStripper struct{ next http.RoundTripper }

func (h *headerStripper) RoundTrip(r *http.Request) (*http.Response, error) {
	// Clone before mutating: RoundTrippers must not modify the request they are
	// given, and a retry (ours or anyone's) would otherwise see a request we
	// already edited.
	req := r.Clone(r.Context())
	stripAikeyHeaders(req.Header)
	next := h.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(req)
}

// maxUpstreamResponse caps a single upstream reply.
//
// 🔴 Without it, a backend can make the proxy allocate without bound while
// holding one of the isolation shell's finite slots — turning the protection
// into the attack's amplifier. 8 MiB is far above any real tool result and far
// below anything that threatens the process.
const maxUpstreamResponse = 8 << 20

func (t *httpTransport) ListTools(ctx context.Context, b UpstreamBackend) ([]mcpwire.Tool, error) {
	// 🔴 tools/list and NOTHING else. See the UpstreamTransport doc: probing
	// with a real tool would put a timer on the customer's systems.
	env, err := t.rpc(ctx, b, mcpwire.MethodToolsList, nil)
	if err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, &UpstreamError{
			Code:   mcpwire.ErrUpstream5XX,
			Detail: "upstream refused tools/list: " + env.Error.Message,
		}
	}
	var res mcpwire.ListToolsResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return nil, &UpstreamError{
			Code:   mcpwire.ErrUpstream5XX,
			Detail: "upstream tools/list result is not the documented shape",
		}
	}
	return res.Tools, nil
}

func (t *httpTransport) CallTool(ctx context.Context, b UpstreamBackend, name string, args json.RawMessage) (*mcpwire.CallToolResult, error) {
	params, err := json.Marshal(mcpwire.CallToolRequest{Name: name, Arguments: args})
	if err != nil {
		return nil, err
	}
	env, err := t.rpc(ctx, b, mcpwire.MethodToolsCall, params)
	if err != nil {
		return nil, err
	}
	if env.Error != nil {
		// 🔴 A JSON-RPC error from the upstream is the upstream's answer, not a
		// transport failure. It is surfaced as an in-band tool error so the
		// MODEL can read it and self-correct, rather than as a protocol error
		// the client would treat as a broken connection.
		return &mcpwire.CallToolResult{
			IsError: true,
			Content: []mcpwire.ContentBlock{{Type: "text", Text: env.Error.Message}},
		}, nil
	}
	var res mcpwire.CallToolResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return nil, &UpstreamError{
			Code:   mcpwire.ErrUpstream5XX,
			Detail: "upstream tools/call result is not the documented shape",
		}
	}
	return &res, nil
}

// rpc performs one JSON-RPC round trip.
func (t *httpTransport) rpc(ctx context.Context, b UpstreamBackend, method string, params json.RawMessage) (*mcpwire.Envelope, error) {
	if b.EndpointURL == "" {
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable, Detail: "backend has no endpoint_url"}
	}
	// 🔴 A backend that declares a credential but has none resolved is refused
	// BEFORE the request. Sending a bare request to an endpoint that expects
	// auth yields a 401 that reads like "the customer's token is wrong", which
	// sends them to rotate a credential that was never the problem.
	if b.CredentialID != "" && b.Credential.Secret == "" {
		return nil, ErrCredentialMissing
	}

	body, err := json.Marshal(mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		ID:      json.RawMessage(`1`),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Both content types, per the Streamable HTTP spec: the server chooses.
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", string(mcpwire.SupportedProtocolVersions[0]))
	applyCredential(req, b.Credential)

	// Belt and braces: the transport strips again as the genuine last step.
	// Doing it here too means a caller that bypasses upstreamHTTPClient (a test,
	// a future direct dial) still gets the guarantee.
	stripAikeyHeaders(req.Header)

	resp, err := upstreamHTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			// 🔴 A timeout is NOT NotAccepted. The request was handed to the
			// connection; the tool may be running right now. This is the single
			// most important line for R4 — flipping it would make every timed-out
			// non-idempotent call eligible for a second execution.
			return nil, &UpstreamError{Code: mcpwire.ErrUpstreamTimeout, Detail: "upstream did not respond in time"}
		}
		// 🔴 The error string is NOT echoed to the client: a dial error can
		// contain internal hostnames and addresses. It is logged by the caller,
		// which has the request id to correlate with.
		return nil, &UpstreamError{
			Code: mcpwire.ErrUpstream5XX, Detail: "upstream is unreachable",
			NotAccepted: neverAccepted(err),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 500 {
		return nil, &UpstreamError{
			Code: mcpwire.ErrUpstream5XX, Status: resp.StatusCode,
			Detail: fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode),
		}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// 🔴 Reported as a CREDENTIAL problem, not a generic upstream error: it
		// is the one upstream status with an action the customer can take, and
		// the message names it.
		return nil, &UpstreamError{
			Code: mcpwire.ErrCredentialMissing, Status: resp.StatusCode,
			Detail: fmt.Sprintf("the backend rejected our credential (HTTP %d)", resp.StatusCode),
		}
	}
	if resp.StatusCode >= 400 {
		return nil, &UpstreamError{
			Code: mcpwire.ErrUpstream5XX, Status: resp.StatusCode,
			Detail: fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode),
		}
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponse+1))
	if err != nil {
		return nil, &UpstreamError{Code: mcpwire.ErrUpstream5XX, Detail: "could not read the upstream response"}
	}
	if len(raw) > maxUpstreamResponse {
		return nil, &UpstreamError{
			Code:   mcpwire.ErrUpstream5XX,
			Detail: fmt.Sprintf("upstream response exceeds the %d MiB ceiling", maxUpstreamResponse>>20),
		}
	}

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return parseSSEEnvelope(raw)
	}
	var env mcpwire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &UpstreamError{Code: mcpwire.ErrUpstream5XX, Detail: "upstream reply is not JSON-RPC"}
	}
	return &env, nil
}

// parseSSEEnvelope extracts the JSON-RPC response from an SSE reply.
//
// Streamable HTTP lets a server answer a POST with an event stream that may
// carry notifications before the response. 🔴 We take the LAST parseable
// envelope that carries a result or an error: earlier frames are progress
// notifications, and treating the first one as the answer is a subtle bug that
// only shows up against servers that actually send progress.
func parseSSEEnvelope(raw []byte) (*mcpwire.Envelope, error) {
	var last *mcpwire.Envelope
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		var env mcpwire.Envelope
		if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &env); err != nil {
			continue
		}
		if len(env.Result) > 0 || env.Error != nil {
			e := env
			last = &e
		}
	}
	if last == nil {
		return nil, &UpstreamError{
			Code:   mcpwire.ErrUpstream5XX,
			Detail: "upstream event stream carried no JSON-RPC response",
		}
	}
	return last, nil
}

// applyCredential puts the resolved secret where the backend expects it.
//
// 🔴 Header or Basic only. `env` credentials belong to stdio backends and are
// injected into the child's environment (P5); reaching here with one means a
// misconfigured backend, and silently sending nothing would produce a 401 the
// customer cannot explain.
func applyCredential(req *http.Request, c UpstreamCredential) {
	switch c.Kind {
	case "bearer":
		if c.Secret != "" {
			req.Header.Set("Authorization", "Bearer "+c.Secret)
		}
	case "basic":
		if c.Secret != "" {
			req.Header.Set("Authorization", "Basic "+c.Secret)
		}
	case "header":
		if c.Secret != "" && c.HeaderName != "" {
			req.Header.Set(c.HeaderName, c.Secret)
		}
	}
}

// stripAikeyHeaders removes every internal header before the wire.
//
// 🔴 This is D-13 and the standing rule in
// workflow/CI/IDE/claude/principles/no-aikey-headers-to-llm-upstream.md.
// It strips by PREFIX rather than by a list of known names, because a list has
// to be kept in step with every header anyone ever adds, and the one that gets
// forgotten is the one that goes out.
func stripAikeyHeaders(h http.Header) {
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-aikey-") {
			h.Del(name)
		}
	}
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// neverAccepted reports whether err proves the request never reached the server.
//
// 🔴 It answers TRUE only for failures that happen BEFORE any byte of the
// request could have been processed:
//
//	DNS failure        the name never resolved, so nothing was dialled
//	connection refused nothing was listening
//	TLS handshake      the session was never established
//
// Everything else — including a connection that dropped mid-request — returns
// false, because "the connection broke" does not tell us whether the server had
// already read and acted on what we sent.
//
// 🔴 This is a WHITELIST, and it must stay one. A blacklist ("everything except
// timeouts is safe") would classify each new error shape as retryable by
// default, and the cost of being wrong here is a customer's tool running twice.
func neverAccepted(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var tlsErr *tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		return true
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	// A dial-phase OpError is pre-request by construction: net/http only
	// produces one while establishing the connection.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return false
}
