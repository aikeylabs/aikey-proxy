package mcp

// httprest.go — calling a plain REST API as if it were an MCP tool (阶段8 P9).
//
// # 🔴 This backend is NOT an MCP server, and three things follow
//
//  1. There is no `tools/list` to probe. The manifest was authored by the
//     control plane from an OpenAPI document a human reviewed, so the upstream
//     has no opinion to compare against — ListTools returns nothing and the
//     sync loop skips these backends entirely (see manifestsync.go).
//  2. There is therefore no DRIFT. A REST API can change under us and we will
//     not notice; the honest place to say that is the console, not a fake
//     fingerprint computed from a response body.
//  3. Health cannot be probed either. 🔴 We deliberately do NOT call a real
//     endpoint to check liveness: a probe runs on a TIMER, so probing with a
//     real operation installs a machine that performs an action on the
//     customer's systems every N minutes, forever, that nobody asked for and no
//     audit trail attributes to a person. That is R9's rule, and it applies
//     with more force here — every one of these endpoints is a real business
//     operation, not a protocol handshake.
//
// # 🔴 The request is built from the BINDING, not from the arguments
//
// Everything about the outgoing request — method, path, where each value goes —
// comes from a binding a human approved at import time. Arguments the binding
// does not name are dropped, not appended. See pkg/mcpwire.RESTBinding: an
// importer that let a caller reach unreviewed parameters would be a request
// forger with an approval workflow attached.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// TransportHTTPREST is the value in mcp_backend.transport.
//
// 🔴 Named for what the backend IS (a REST API over HTTP), not for how we
// learned about it (OpenAPI): task 9.6 registers these by hand with no spec
// involved, and a transport called `openapi` would make that read as a
// different kind of thing.
const TransportHTTPREST = "http_rest"

// restResponseCap bounds what we read back.
//
// 🔴 The MCP response cap already exists one layer up, but this one is separate
// and smaller-scoped on purpose: a REST endpoint can stream a report of any
// size, and the bytes have to be held here to become a tool result. Sharing the
// outer cap would mean discovering the problem after allocating.
const restResponseCap = 4 << 20

type httpRESTTransport struct{}

func (t *httpRESTTransport) Name() string { return TransportHTTPREST }

// ListTools returns nothing, and that is the correct answer.
//
// 🔴 NOT an error. The sync loop treats an error as a failed probe and opens a
// circuit; a REST backend has no probe to fail. Returning an empty list with no
// error says "there is nothing to discover here", which is the truth — the
// manifest came from the import, and the console is where it lives.
func (t *httpRESTTransport) ListTools(context.Context, UpstreamBackend) ([]mcpwire.Tool, error) {
	return nil, nil
}

// CallTool turns one tools/call into one HTTP request.
func (t *httpRESTTransport) CallTool(
	ctx context.Context, b UpstreamBackend, name string, args json.RawMessage,
) (*mcpwire.CallToolResult, error) {
	binding, present, err := mcpwire.ParseRESTBinding(b.RESTBinding)
	if err != nil {
		// 🔴 OUR data is unreadable, so no EXT_ code: blaming the upstream would
		// send the customer to debug an API that is working.
		return nil, &UpstreamError{
			Code:   mcpwire.ErrBackendUnavailable,
			Detail: "the stored call mapping for this tool could not be read: " + err.Error(),
		}
	}
	if !present {
		// A tool on a REST backend with no binding cannot be called at all. This
		// is a configuration fault, and 🔴 refusing is the only honest answer —
		// guessing a path from the tool's name would call an endpoint nobody
		// approved.
		return nil, &UpstreamError{
			Code: mcpwire.ErrBackendUnavailable,
			Detail: fmt.Sprintf("tool %q is served by a REST backend but carries no call mapping; "+
				"re-import it or register its method and path", name),
		}
	}
	built, err := binding.Build(args)
	if err != nil {
		return nil, &UpstreamError{
			Code:   mcpwire.ErrBackendUnavailable,
			Detail: "the call could not be built from its mapping: " + err.Error(),
		}
	}

	endpoint := strings.TrimRight(b.EndpointURL, "/") + built.Path
	var body io.Reader
	if built.Body != nil {
		body = bytes.NewReader(built.Body)
	}
	req, err := http.NewRequestWithContext(ctx, built.Method, endpoint, body)
	if err != nil {
		return nil, &UpstreamError{
			Code:   mcpwire.ErrBackendUnavailable,
			Detail: "the resulting address is not a valid URL: " + err.Error(),
		}
	}
	if built.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
	for k, v := range built.Header {
		req.Header.Set(k, v)
	}
	// 🔴 The credential goes on LAST, after the binding's own headers. A binding
	// cannot then overwrite the Authorization header with a value a model chose —
	// which would otherwise let a tool argument replace the customer's credential
	// with one the caller supplied.
	applyCredential(req, b.Credential)

	// 🔴 The same header-stripping rule as every other upstream: no X-Aikey-*
	// ever leaves for a third party (D-13). Nothing here adds one, and this call
	// states that rather than relying on it having stayed true.
	stripAikeyHeaders(req.Header)

	// 🔴 The SAME client the MCP upstreams use — one timeout, one transport, one
	// place the header-stripping RoundTripper lives. A second client here would
	// be a second set of those, and the one nobody remembered to configure is
	// the one that leaks.
	resp, err := upstreamHTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			// 🔴 A timeout is NOT NotAccepted. The request was handed over; the
			// REST endpoint may be executing right now, and for a write endpoint
			// that is exactly the case where a retry places the order twice.
			return nil, &UpstreamError{
				Code:   mcpwire.ErrUpstreamTimeout,
				Detail: "the API did not respond in time",
			}
		}
		// 🚫 The error string is not echoed: a dial error carries internal
		// hostnames, and this backend is by definition inside the customer's
		// network.
		return nil, &UpstreamError{
			Code: mcpwire.ErrUpstream5XX, Detail: "the API is unreachable",
			// Whether the request provably never left is what decides if a retry
			// is safe at all (R4). Same whitelist as every other transport.
			NotAccepted: neverAccepted(err),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, restResponseCap+1))
	if readErr != nil {
		return nil, &UpstreamError{
			Code: mcpwire.ErrUpstream5XX, Status: resp.StatusCode,
			Detail: "the response body could not be read: " + readErr.Error(),
		}
	}
	truncated := len(raw) > restResponseCap
	if truncated {
		raw = raw[:restResponseCap]
	}

	// 🔴 A 4xx/5xx is an UPSTREAM error carrying the EXT_ prefix — it is the
	// customer's API refusing, not the gateway. The status is reported so the
	// developer can tell a 404 from a 403 without opening a ticket with us.
	if resp.StatusCode >= 400 {
		return nil, &UpstreamError{
			Code:   restErrorCode(resp.StatusCode),
			Status: resp.StatusCode,
			// 🚫 The body is NOT echoed into the error. An API's error body
			// routinely contains the record that was refused, and an error string
			// travels further than we can follow.
			Detail: fmt.Sprintf("%s %s answered HTTP %d", built.Method, built.Path, resp.StatusCode),
		}
	}

	text := string(raw)
	if truncated {
		// 🔴 Said out loud, in the result the model reads. A silently truncated
		// response is one the model will reason about as if it were complete.
		text += "\n\n[truncated: the response exceeded the gateway's size limit]"
	}
	return &mcpwire.CallToolResult{
		Content: []mcpwire.ContentBlock{{Type: "text", Text: text}},
	}, nil
}

// restErrorCode maps an HTTP status onto the frozen vocabulary.
//
// 🔴 Both 4xx and 5xx are EXT_MCP_UPSTREAM_5XX today, because the frozen
// catalogue has one upstream-failure code and inventing a second here would be
// a contract change made in passing. The STATUS carries the distinction, which
// is what a developer actually reads.
func restErrorCode(status int) mcpwire.ErrorCode {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		// A credential the gateway presented was refused. Distinct because the
		// fix is ours (re-bind the credential), not the caller's.
		return mcpwire.ErrCredentialMissing
	}
	return mcpwire.ErrUpstream5XX
}

func init() {
	RegisterTransport(&httpRESTTransport{})
}
