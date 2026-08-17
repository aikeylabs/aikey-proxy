// group_failover.go — N9: in-request account failover for oauth-group routes.
//
// Before this, a pool account's upstream failure was only handled REACTIVELY
// (N8c): the failing response went straight to the client, the account was
// cooled down, and the NEXT request routed around it — every account failure
// necessarily burned one visible user error. N9 closes that: the group serve
// path retries the SAME client request on the next candidate account, and the
// client only ever sees the final outcome.
//
// Blueprint follows the sub2api gateway loop (research/2026-07-19-sub2api-池生命
// 周期与429分类-对照研读.md 问题1), with three load-bearing rules:
//
//  1. FIRST-BYTE GATE: failover is allowed only while NOT A SINGLE BYTE has
//     reached the client. The capture writer below defers the upstream response
//     at WriteHeader time; anything already streamed (SSE mid-flight) makes the
//     response tamper-proof — switching then would splice two streams.
//  2. BODY REPLAY: every attempt forwards a fresh clone of the ORIGINAL request
//     (headers + body); per-attempt mutations (oauthInject persona headers,
//     upstream URL rewrite, context stashes) never leak into the next attempt.
//  3. FAILED-ACCOUNT/PATH EXCLUSION: account-attributed HTTP failures join the
//     per-request account set, while no-response transport failures join the
//     path set — never redial the same failed path through a different account.
//     (401/evidence-429 also mark the shared cooldown store via ModifyResponse,
//     which future requests see; 529/5xx cross-REQUEST cooldown is the separate
//     P0-B work — within THIS request the failed set alone is sufficient.)
//
// Where we deliberately EXCEED sub2api: their transport-level failures (no HTTP
// response at all) are written to the client as a dead-end 502 with no failover
// (their gateway_service.go:5048-5072 gap). Here httputil.ReverseProxy's
// ErrorHandler synthesizes a non-quota 503 through the SAME capture writer. The
// outer loop retries only a candidate with a different Provider path; another
// account on the same dead path is skipped without dialing.
//
// Scope (stage 1): oauth-group routes only — the only routes with alternate
// accounts to fail over TO. Direct-bind/single-credential routes keep the
// existing single-shot behavior.
package proxy

import (
	"bytes"
	"net/http"
	"sync"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

const (
	// groupFailoverMaxSwitches caps how many ALTERNATE accounts one client
	// request may try after the first pick fails (total upstream attempts =
	// switches + 1). ponytail: structural default balancing tail latency (each
	// switch is a full sequential upstream round-trip) against 防封 exposure
	// (every switch touches one more account's persona with the same payload);
	// sub2api ships 10, ours starts conservative. Tune with burn-in data.
	groupFailoverMaxSwitches = 3

	// groupFailoverBodyCap bounds the buffered (deferred) upstream ERROR body.
	// Upstream error envelopes are tiny JSON; the cap only guards a pathological
	// giant error body from ballooning memory. A truncated buffer is still a
	// valid client response because Content-Length is recomputed on flush.
	groupFailoverBodyCap = 128 << 10
)

// failoverEligibleResponse reports whether an upstream response may be retried
// on another account. The set mirrors cooldownDecision's account-fault taxonomy:
//   - 401: credential broken/revoked on THIS account;
//   - 429 WITH rate-limit evidence (hasRateLimitSignal — value-based per the B1
//     fix): this account's window/quota, another account may serve. An
//     evidence-LESS 429 (suspected WAF/business rejection) is about the REQUEST,
//     not the account — switching cannot help and only burns more personas, so
//     it passes through;
//   - >=500 (incl. 529 overload and the ReverseProxy-synthesized 503 for
//     transport errors): upstream/account- or path-side failure worth one try
//     elsewhere; the caller separates account exclusion from path exclusion.
func failoverEligibleResponse(status int, h http.Header) bool {
	// ACCOUNT egress construction failure is deliberately eligible: the broken
	// spec belongs to one account/path, and keeping the engine's preferred choice
	// is less important than preserving the pool's user-facing availability.
	// The outer loop still flushes this exact typed 503 when no healthy alternate
	// exists, so failover never hides the root cause.
	// Same reasoning one layer out: the NODE's egress could not be built, so no
	// upstream request happened on ANY candidate and none can. Retrying would walk
	// the whole chain to collect identical local failures, and — worse — would put
	// every binding in the administrator's chain into cooldown for a fault that is
	// this node's, not theirs. The next request would then find a chain that looks
	// unhealthy end to end because one node has a bad spec.
	if h.Get(HeaderAikeyErrorSource) == observability.ErrCodeNodeEgressEngine {
		return false
	}
	switch {
	case status == http.StatusUnauthorized:
		return true
	case status == http.StatusTooManyRequests:
		return hasRateLimitSignal(h)
	case status >= 500:
		return true
	}
	return false
}

// groupFailoverWriter is the first-byte gate. It fronts the real ResponseWriter
// for one forward attempt:
//
//   - When the response turns out failover-eligible (and capture is allowed),
//     NOTHING is written to the client — status/headers/body are buffered so the
//     caller can either retry on another account or flush this response as the
//     final answer.
//   - Any other response (success, non-eligible error, or the last permitted
//     attempt) passes through unchanged, including SSE flushes.
//
// The eligibility decision happens exactly once, at WriteHeader time — after
// that the mode is fixed for the attempt, so a 200-streaming response can never
// be half-buffered.
type groupFailoverWriter struct {
	dst          http.ResponseWriter
	header       http.Header
	allowCapture bool
	// eligible decides whether a response may be deferred. nil = the account
	// axis's `failoverEligibleResponse`, unchanged.
	//
	// 🔴 The binding axis (upstream fallback) needs ONE extra reason to defer —
	// a hop whose model map rejects the requested model must be skipped rather
	// than answered (task 2.30). That reason is supplied here instead of being
	// added to `failoverEligibleResponse`, because task 2.5 forbids widening the
	// shared predicate: it also governs the account axis, and changing it would
	// alter released behavior for oauth-group routing that has nothing to do
	// with this change.
	eligible func(int, http.Header) bool

	decided   bool
	capturing bool
	status    int
	buf       bytes.Buffer
	// failedPathKey is private metadata from ReverseProxy.ErrorHandler. It never
	// becomes an upstream or client header; the outer group loop uses it to avoid
	// dialing the same failed network path through another account.
	failedPathKey string
	// onCommit releases the replay body at the first client-visible response.
	// Captured failures deliberately do not commit because the next account needs
	// the same body. sync.Once protects WriteHeader/flush races and double calls.
	onCommit   func()
	commitOnce sync.Once
}

func newGroupFailoverWriter(dst http.ResponseWriter, allowCapture bool) *groupFailoverWriter {
	return &groupFailoverWriter{dst: dst, header: make(http.Header), allowCapture: allowCapture}
}

func (fw *groupFailoverWriter) Header() http.Header { return fw.header }

func (fw *groupFailoverWriter) WriteHeader(status int) {
	if fw.decided {
		return
	}
	fw.decided = true
	fw.status = status
	eligible := fw.eligible
	if eligible == nil {
		eligible = failoverEligibleResponse
	}
	if fw.allowCapture && eligible(status, fw.header) {
		fw.capturing = true
		return // defer — the caller decides retry vs flush
	}
	dh := fw.dst.Header()
	for k, v := range fw.header {
		dh[k] = v
	}
	fw.dst.WriteHeader(status)
	fw.commit()
}

func (fw *groupFailoverWriter) Write(b []byte) (int, error) {
	if !fw.decided {
		fw.WriteHeader(http.StatusOK)
	}
	if fw.capturing {
		if room := groupFailoverBodyCap - fw.buf.Len(); room > 0 {
			if len(b) > room {
				fw.buf.Write(b[:room])
			} else {
				fw.buf.Write(b)
			}
		}
		return len(b), nil // report full write — the upstream copy must not error
	}
	return fw.dst.Write(b)
}

// Flush satisfies http.Flusher for the streaming (SSE) passthrough path; while
// capturing (a deferred error) there is nothing client-side to flush.
func (fw *groupFailoverWriter) Flush() {
	if fw.capturing || !fw.decided {
		return
	}
	if f, ok := fw.dst.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.NewResponseController reach the real writer's extensions
// (only ever needed on the passthrough path; capture mode swallows control ops).
func (fw *groupFailoverWriter) Unwrap() http.ResponseWriter { return fw.dst }

// captured reports whether this attempt's response was deferred for a retry
// decision.
func (fw *groupFailoverWriter) capturedResponse() bool { return fw.capturing }

func (fw *groupFailoverWriter) markProviderPathFailure(pathKey string) {
	fw.failedPathKey = pathKey
}

func (fw *groupFailoverWriter) commit() {
	if fw.onCommit != nil {
		fw.commitOnce.Do(fw.onCommit)
	}
}

// flushCaptured writes the deferred response to the client verbatim — used when
// the failover budget or the candidate set is exhausted and the last upstream
// error IS the final answer. Content-Length reflects the (possibly truncated)
// buffered body.
func (fw *groupFailoverWriter) flushCaptured() {
	if !fw.capturing {
		return
	}
	dh := fw.dst.Header()
	for k, v := range fw.header {
		dh[k] = v
	}
	dh.Del("Content-Length") // recomputed by net/http from the buffered body
	fw.dst.WriteHeader(fw.status)
	fw.commit()
	_, _ = fw.dst.Write(fw.buf.Bytes())
}
