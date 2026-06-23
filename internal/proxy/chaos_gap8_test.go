//go:build chaos

// Chaos experiment — 缺口8: aikey-proxy's http.Server has no max-concurrent-
// connection cap. This replicates the proxy's ACTUAL server timeouts
// (server.go: ReadHeaderTimeout=30s, IdleTimeout=120s) and floods it with idle
// keep-alive connections to quantify the real limit. On this box fd ulimit is
// ~1M, so the practical ceiling is MEMORY / goroutines per connection, not fds.
// Hypothesis H8/H8b: per-conn cost is a small constant; the server keeps serving
// a probe request under flood (no hard starvation), and the classic fd-pinning
// attacks are already blunted by the two timeouts.
//
// Run: go test -tags chaos -run TestChaosGap8 -v ./internal/proxy/

package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"
)

// startFloodServer starts an http.Server with the SAME timeout config as
// internal/server/server.go (the gap8 surface) on an ephemeral port.
func startFloodServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,  // mirrors server.go — kills slowloris
		IdleTimeout:       120 * time.Second, // mirrors server.go — reaps idle keep-alives
	}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close(); ln.Close() }
}

// openIdleKeepAlive dials, completes one HTTP/1.1 request, reads the full
// response, and returns the still-open connection (now an idle keep-alive that
// the server holds a goroutine for until IdleTimeout). Caller keeps it alive.
func openIdleKeepAlive(addr string) (net.Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	req, _ := http.NewRequest("GET", "/", nil)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	// Drain body so the connection returns to idle keep-alive state.
	buf := make([]byte, 8)
	io_ReadFull(br, buf[:2])
	_ = resp
	return c, nil
}

func io_ReadFull(br *bufio.Reader, p []byte) {
	for n := 0; n < len(p); {
		m, err := br.Read(p[n:])
		n += m
		if err != nil {
			return
		}
	}
}

// probeOnce opens a fresh connection and asserts the server still answers 200 —
// i.e. the flood of idle keep-alives has NOT starved legitimate traffic.
func probeOnce(addr string, timeout time.Duration) (ok bool, latency time.Duration) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, time.Since(start)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	br := bufio.NewReader(c)
	req, _ := http.NewRequest("GET", "/", nil)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return false, time.Since(start)
	}
	return resp.StatusCode == http.StatusOK, time.Since(start)
}

func goroutinesAndHeapMB() (int, float64) {
	g := runtime.NumGoroutine()
	return g, float64(heapInuseBytes()) / (1024 * 1024)
}

func TestChaosGap8_ConnFlood(t *testing.T) {
	addr, stop := startFloodServer(t)
	defer stop()

	// Warm up + baseline (one request settles the accept loop).
	if ok, _ := probeOnce(addr, 2*time.Second); !ok {
		t.Fatal("server not answering before flood")
	}
	time.Sleep(100 * time.Millisecond)
	baseG, baseHeap := goroutinesAndHeapMB()

	t.Logf("=== 缺口8 idle keep-alive connection flood (proxy server timeouts) ===")
	t.Logf("Go=%s ulimit-relevant: fd is NOT the limit on this box (1M)", runtime.Version())
	t.Logf("baseline: goroutines=%d heap=%.1fMB", baseG, baseHeap)
	t.Logf("%-8s %-12s %-12s %-14s %-14s", "conns", "goroutines", "heapMB", "probe200", "probeLatency")

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	targets := []int{500, 2000, 8000}
	var lastG int
	var lastHeap float64
	prev := 0
	for _, target := range targets {
		for i := prev; i < target; i++ {
			c, err := openIdleKeepAlive(addr)
			if err != nil {
				t.Logf("  open conn #%d failed: %v (stopping flood here)", i, err)
				target = len(conns)
				break
			}
			conns = append(conns, c)
		}
		prev = len(conns)
		time.Sleep(200 * time.Millisecond) // let server-side conn goroutines settle

		g, heapMB := goroutinesAndHeapMB()
		ok, lat := probeOnce(addr, 3*time.Second)
		lastG, lastHeap = g, heapMB
		t.Logf("%-8d %-12d %-12.1f %-14v %-14s", len(conns), g, heapMB, ok, lat.Round(time.Millisecond))
		if !ok {
			t.Errorf("PROBE FAILED at %d idle conns — legitimate traffic starved", len(conns))
		}
	}

	// Per-conn cost from the largest sample.
	if len(conns) > 0 {
		perConnGoroutine := float64(lastG-baseG) / float64(len(conns))
		perConnHeapKB := (lastHeap - baseHeap) * 1024 / float64(len(conns))
		t.Logf("\n--- per-connection cost (@%d conns) ---", len(conns))
		t.Logf("goroutines/conn ≈ %.2f   heap/conn ≈ %.1f KB", perConnGoroutine, perConnHeapKB)

		// Extrapolate memory ceiling (fd is 1M, so memory is the real wall).
		for _, n := range []int{50000, 200000} {
			projMB := perConnHeapKB * float64(n) / 1024
			t.Logf("extrapolate %d idle conns → ~%.0f MB heap (+ ~%d goroutines)",
				n, projMB, int(perConnGoroutine*float64(n)))
		}
	}
	t.Logf("\nNote: ReadHeaderTimeout=30s blunts slowloris; IdleTimeout=120s reaps these idle conns.")
}
