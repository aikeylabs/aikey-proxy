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
// in-flight upstream calls are NOT cancelled when the client disconnects;
// they run until completion (or the upstream timeout / proxy shutdown).
type detachedTransport struct {
	inner      http.RoundTripper
	proxyCtx   context.Context
	maxTimeout time.Duration
}

func (t *detachedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(t.proxyCtx, t.maxTimeout)
	req = req.WithContext(ctx)

	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		cancel()
		return nil, err
	}

	// Wrap the body so the per-request context is cancelled when it is closed,
	// preventing context leaks for long-lived connections.
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
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
