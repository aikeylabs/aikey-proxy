package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- detachedTransport tests ------------------------------------------------

// TestDetachedTransport_CompletesAfterClientContextCanceled is the core
// correctness test: the upstream call must finish even if the original client
// context is canceled mid-flight.
func TestDetachedTransport_CompletesAfterClientContextCanceled(t *testing.T) {
	upstreamReady := make(chan struct{})
	upstreamProceed := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(upstreamReady)
		select {
		case <-upstreamProceed:
		case <-r.Context().Done():
			// upstream's own context (derived from proxyCtx) should NOT be canceled
			// when the client context is canceled.
		}
		w.WriteHeader(200)
		w.Write([]byte("upstream_done"))
	}))
	defer upstream.Close()

	clientCtx, cancelClient := context.WithCancel(context.Background())
	dt := &detachedTransport{
		inner:      http.DefaultTransport,
		proxyCtx:   context.Background(), // proxy lifecycle context
		maxTimeout: 10 * time.Second,
	}

	req, _ := http.NewRequestWithContext(clientCtx, "GET", upstream.URL, nil)

	type result struct {
		resp *http.Response
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		resp, err := dt.RoundTrip(req) //nolint:bodyclose // resp.Body is read and closed by the result-channel consumer below
		resultCh <- result{resp, err}
	}()

	// Wait for upstream to receive the request, then cancel the client context.
	select {
	case <-upstreamReady:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never received request")
	}
	cancelClient()         // simulate client disconnect
	close(upstreamProceed) // allow upstream to respond

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("unexpected error: %v — upstream call should survive client disconnect", res.err)
		}
		body, _ := io.ReadAll(res.resp.Body)
		res.resp.Body.Close()
		if string(body) != "upstream_done" {
			t.Fatalf("body = %q, want %q", string(body), "upstream_done")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out: upstream call was canceled despite using detachedTransport")
	}
}

// TestDetachedTransport_AbortedByProxyContext verifies that canceling the
// proxy lifecycle context does abort the upstream call.
func TestDetachedTransport_AbortedByProxyContext(t *testing.T) {
	// Upstream that blocks until its own context is canceled.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		w.WriteHeader(503)
	}))
	defer upstream.Close()

	proxyCtx, cancelProxy := context.WithCancel(context.Background())
	dt := &detachedTransport{
		inner:      http.DefaultTransport,
		proxyCtx:   proxyCtx,
		maxTimeout: 30 * time.Second,
	}

	req, _ := http.NewRequestWithContext(context.Background(), "GET", upstream.URL, nil)

	done := make(chan error, 1)
	go func() {
		resp, err := dt.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancelProxy()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after proxy context canceled, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for abort after proxyCtx cancel")
	}
}

// TestDetachedTransport_MaxTimeoutBounds verifies that the per-request
// timeout derived from UpstreamTimeout bounds runaway upstream calls.
func TestDetachedTransport_MaxTimeoutBounds(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // blocks until timeout
		w.WriteHeader(503)
	}))
	defer upstream.Close()

	dt := &detachedTransport{
		inner:      http.DefaultTransport,
		proxyCtx:   context.Background(),
		maxTimeout: 150 * time.Millisecond, // very short for testing
	}

	req, _ := http.NewRequestWithContext(context.Background(), "GET", upstream.URL, nil)
	start := time.Now()
	resp, err := dt.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout took %v, expected ≤ 500ms", elapsed)
	}
}

// TestDetachedTransport_BodyWrappedAsCancelOnClose verifies that the transport
// wraps the response body as *cancelOnClose (so the context is canceled on close).
func TestDetachedTransport_BodyWrappedAsCancelOnClose(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	// Use a context we can observe.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dt := &detachedTransport{
		inner:      http.DefaultTransport,
		proxyCtx:   ctx,
		maxTimeout: 5 * time.Second,
	}

	req, _ := http.NewRequestWithContext(context.Background(), "GET", upstream.URL, nil)
	resp, err := dt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := resp.Body.(*cancelOnClose); !ok {
		t.Fatalf("expected *cancelOnClose, got %T", resp.Body)
	}

	// Reading and closing should not panic or error.
	io.ReadAll(resp.Body)
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

// TestDetachedTransport_NormalResponse verifies basic non-streaming response
// passthrough (no regressions from wrapping).
func TestDetachedTransport_NormalResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	dt := &detachedTransport{
		inner:      http.DefaultTransport,
		proxyCtx:   context.Background(),
		maxTimeout: 5 * time.Second,
	}

	req, _ := http.NewRequestWithContext(context.Background(), "GET", upstream.URL, nil)
	resp, err := dt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("body = %q, want JSON with ok", body)
	}
}
