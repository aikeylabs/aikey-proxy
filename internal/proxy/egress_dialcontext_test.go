package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// BuildEgressDialContext exists so the OAuth broker can ride the SAME egress as AI
// forwarding. Before it, a multi-protocol node upstream had no URL form to hand the
// broker's uTLS client, so token exchange silently used the system/env proxy — one
// node, two exits, and an opaque login failure when the system proxy was stale.
//
// These fences pin the two properties that make "same egress" true: the dial really
// goes through the configured hop, and internal destinations still bypass it exactly
// like the transport path.

// TestBuildEgressDialContext_DialsThroughTheConfiguredHop proves traffic actually
// traverses the spec rather than going direct. A local listener stands in for the
// egress hop: if the dialer went direct, it would never be touched.
func TestBuildEgressDialContext_DialsThroughTheConfiguredHop(t *testing.T) {
	var accepted int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			atomic.AddInt32(&accepted, 1)
			c.Close() // a socks5 handshake never completes — reaching us is the assertion
		}
	}()

	dial, closer, err := BuildEgressDialContext("socks5://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("BuildEgressDialContext: %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}

	// Target a PUBLIC-shaped address so the loopback bypass does not apply.
	conn, derr := dial(context.Background(), "tcp", "example.com:443")
	if conn != nil {
		conn.Close()
	}
	if derr == nil {
		t.Fatal("expected the half-open hop to fail the handshake; a success means something else answered")
	}
	if n := atomic.LoadInt32(&accepted); n == 0 {
		t.Fatal("the egress hop was never contacted — the dialer went direct, so OAuth would leave from a different exit than forwarding")
	}
	// Failures must be tagged so callers can tell "egress broken" from "upstream broken".
	if !strings.Contains(derr.Error(), "egress connect fail") {
		t.Errorf("dial error should be wrapped as an egress failure, got %v", derr)
	}
}

// TestBuildEgressDialContext_InternalDestinationsBypass mirrors the transport path's
// NO_PROXY/loopback rule. A self-hosted OAuth provider on localhost must NOT be
// forced out through the public egress — that turns a working local endpoint into a
// misleading proxy error.
func TestBuildEgressDialContext_InternalDestinationsBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// An egress pointing at a closed port: anything routed THROUGH it fails.
	dial, closer, err := BuildEgressDialContext("socks5://127.0.0.1:1")
	if err != nil {
		t.Fatalf("BuildEgressDialContext: %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}

	host := strings.TrimPrefix(srv.URL, "http://")
	conn, derr := dial(context.Background(), "tcp", host)
	if derr != nil {
		t.Fatalf("loopback target must bypass the egress and dial direct, got %v", derr)
	}
	conn.Close()
}

// TestBuildEgressDialContext_RejectsUnusableSpec keeps the build error visible
// instead of handing back a dialer that silently goes direct.
func TestBuildEgressDialContext_RejectsUnusableSpec(t *testing.T) {
	dial, closer, err := BuildEgressDialContext("proxies:\n  - name: x, type: ss, port: 1,\n")
	if closer != nil {
		closer.Close()
	}
	if err == nil {
		t.Fatalf("expected a build error for a malformed spec (dial=%v)", dial != nil)
	}
	if dial != nil {
		t.Error("a failed build must not return a dialer — the caller could use it and leak traffic direct")
	}
}
