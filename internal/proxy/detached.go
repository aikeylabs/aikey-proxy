package proxy

import (
	"context"
	"io"
	"net/http"
	"time"
)

// defaultUpstreamTimeout caps how long a detached upstream call may run.
// It bounds requests that the client has abandoned but the upstream is still
// processing (e.g. a very long generation). Adjust via Proxy.UpstreamTimeout.
const defaultUpstreamTimeout = 10 * time.Minute

// detachedTransport wraps an http.RoundTripper and replaces the per-request
// context with one derived from the proxy lifecycle context. This ensures
// in-flight upstream calls are NOT canceled when the client disconnects;
// they run until completion (or the upstream timeout / proxy shutdown).
type detachedTransport struct {
	inner      http.RoundTripper
	proxyCtx   context.Context
	maxTimeout time.Duration
}

func (t *detachedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Detach from the CLIENT's cancellation (a client disconnect must not abort the
	// upstream call) but PRESERVE the request's context VALUES. Bug (2026-07-01, found
	// by TestGroupServe_WindowUtilHeaderPreCutsSwitchesAndUplinks): the old
	// `context.WithTimeout(t.proxyCtx, …)` derived a FRESH context from the proxy
	// lifecycle, dropping every stashed value on req.Context() — including the N10
	// window-cap stash that ModifyResponse reads off resp.Request. So the pre-cut
	// (防封: cool a pool account before it hits 100%) silently never fired for
	// NON-streaming pool requests. WithoutCancel keeps the values while dropping the
	// client's Done; AfterFunc re-ties cancellation to proxy shutdown (unchanged
	// lifetime: proxy shutdown OR maxTimeout OR body close).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), t.maxTimeout)
	stopOnShutdown := context.AfterFunc(t.proxyCtx, cancel)
	cancelAll := func() { stopOnShutdown(); cancel() }
	req = req.WithContext(ctx)

	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		cancelAll()
		return nil, err
	}

	// Wrap the body so the per-request context is canceled when it is closed,
	// preventing context leaks for long-lived connections (also stops the
	// shutdown AfterFunc so it doesn't linger past the request).
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancelAll}
	return resp, nil
}

// cancelOnClose cancels the associated context when the response body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	c.cancel()
	return c.ReadCloser.Close()
}
