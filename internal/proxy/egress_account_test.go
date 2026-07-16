package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/pkg/egress"
)

// --- minimal socks5 CONNECT server (test helper) -------------------------------
//
// Implements just enough of RFC 1928 (no-auth + username/password, CONNECT) to
// prove the per-account egress dialer chain REALLY traverses each hop. Each
// server records the target address it was asked to CONNECT to, so a 2-hop test
// can assert order: node → front(→account) → account(→upstream) → upstream.

type socks5TestServer struct {
	ln         net.Listener
	addr       string
	mu         sync.Mutex
	connects   int
	lastTarget string
	wantUser   string // "" = no-auth
	wantPass   string
}

func newSocks5TestServer(t *testing.T, user, pass string) *socks5TestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &socks5TestServer{ln: ln, addr: ln.Addr().String(), wantUser: user, wantPass: pass}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *socks5TestServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *socks5TestServer) handle(c net.Conn) {
	defer c.Close()
	br := make([]byte, 2)
	if _, err := io.ReadFull(c, br); err != nil || br[0] != 0x05 {
		return
	}
	nMethods := int(br[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// Method selection.
	if s.wantUser != "" {
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil { // username/password
			return
		}
		if !s.authUserPass(c) {
			return
		}
	} else {
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no-auth
			return
		}
	}
	// CONNECT request: VER CMD RSV ATYP ...
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[1] != 0x01 { // CMD=CONNECT
		return
	}
	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	s.mu.Lock()
	s.connects++
	s.lastTarget = target
	s.mu.Unlock()

	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	// Success reply (bind addr ignored by clients here).
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	// Pipe both directions.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func (s *socks5TestServer) authUserPass(c net.Conn) bool {
	// VER=1 ULEN user PLEN pass
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 0x01 {
		return false
	}
	user := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(c, pl); err != nil {
		return false
	}
	pass := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	ok := string(user) == s.wantUser && string(pass) == s.wantPass
	if ok {
		_, _ = c.Write([]byte{0x01, 0x00})
	} else {
		_, _ = c.Write([]byte{0x01, 0x01})
	}
	return ok
}

func (s *socks5TestServer) stats() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects, s.lastTarget
}

// --- tests ---------------------------------------------------------------------

// The built-in engine claims socks5-only chains and declines anything with a
// non-socks5 hop or a config-fragment shape (those fall to the mihomo engine,
// present only in the offline enterprise build).
func TestBuiltinEngine_Claims(t *testing.T) {
	e := builtinEgressEngine{}
	claims := map[string]bool{
		"socks5://a:1080":                   true,
		"socks5://a:1080,socks5://b:1080":   true,
		" socks5://a:1080 , socks5://b:1080": true,
		"ss://rc4-md5:pw@h:8002":            false,
		"socks5://a:1080,ss://b:8002":       false, // mixed → mihomo
		`{"proxies":[]}`:                    false,
		"":                                  false,
	}
	for spec, want := range claims {
		if got := e.Claims(spec); got != want {
			t.Errorf("Claims(%q) = %v, want %v", spec, got, want)
		}
	}
}

// A spec no engine claims (e.g. a multi-protocol spec in the open-source build
// without the mihomo engine) fails LOUDLY with an actionable message — never
// silently, never out the wrong IP.
func TestEgressRegistry_UnclaimedSpecErrors(t *testing.T) {
	_, err := egress.BuildDialer("ss://rc4-md5:pw@8.8.8.8:8002")
	if err == nil {
		t.Fatal("a multi-protocol spec must error when no engine claims it")
	}
	if !strings.Contains(err.Error(), "offline enterprise package") {
		t.Fatalf("error must point the operator at the offline package, got: %v", err)
	}
}

func TestParseSocks5URL(t *testing.T) {
	if _, _, err := parseSocks5URL("http://1.2.3.4:8080"); err == nil {
		t.Fatal("http scheme must be rejected (socks5 only this phase)")
	}
	if _, _, err := parseSocks5URL("socks5h://1.2.3.4:1080"); err == nil {
		t.Fatal("socks5h must be rejected this phase (carry-over)")
	}
	addr, auth, err := parseSocks5URL("socks5://user:pass@1.2.3.4:1080")
	if err != nil {
		t.Fatalf("valid socks5 url: %v", err)
	}
	if addr != "1.2.3.4:1080" {
		t.Fatalf("addr = %q", addr)
	}
	if auth == nil || auth.User != "user" || auth.Password != "pass" {
		t.Fatalf("auth = %+v", auth)
	}
	if _, noAuth, _ := parseSocks5URL("socks5://1.2.3.4:1080"); noAuth != nil {
		t.Fatalf("no userinfo must yield nil auth, got %+v", noAuth)
	}
}

// Non-socks5 hop anywhere in the chain → build error (narrow scope, surfaced
// not silent). Single hop.
func TestBuildAccountEgressTransport_RejectsNonSocks5Account(t *testing.T) {
	if _, err := buildAccountEgressTransport("http://1.2.3.4:8080"); err == nil {
		t.Fatal("non-socks5 egress hop must error")
	}
}

// A non-socks5 hop in a MULTI-hop chain also errors (every hop must be socks5).
func TestBuildAccountEgressTransport_RejectsNonSocks5HopInChain(t *testing.T) {
	if _, err := buildAccountEgressTransport("socks5://1.2.3.4:1080,http://5.6.7.8:8080"); err == nil {
		t.Fatal("a non-socks5 hop in the chain must error, not silently downgrade")
	}
	if _, err := buildAccountEgressTransport("  "); err == nil {
		t.Fatal("an all-empty chain spec must error")
	}
}

// Single-hop: one socks5 hop → node → account → upstream.
func TestBuildAccountEgressTransport_SingleHop(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	acct := newSocks5TestServer(t, "", "")
	tr, err := buildAccountEgressTransport("socks5://" + acct.addr)
	if err != nil {
		t.Fatalf("build single-hop: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("GET via single-hop egress: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if n, last := acct.stats(); n == 0 || last != hostPort(t, target.URL) {
		t.Fatalf("account proxy not traversed correctly: connects=%d last=%q want target=%q", n, last, hostPort(t, target.URL))
	}
}

// Two-hop chain expressed in ONE field: "socks5://F,socks5://A" → node → F → A →
// upstream. Asserts ORDER from the self-contained spec: the FIRST hop (F) is
// asked to reach the SECOND hop (A), and A is asked to reach the UPSTREAM — so
// the exit IP is the last hop's (A). No node upstream_proxy involved.
func TestBuildAccountEgressTransport_TwoHopChainOrder(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	front := newSocks5TestServer(t, "", "")
	acct := newSocks5TestServer(t, "fuser", "fpass")

	// Whole chain in the single egress_proxy_url field: first hop, then exit hop.
	spec := "socks5://" + front.addr + ",socks5://fuser:fpass@" + acct.addr
	tr, err := buildAccountEgressTransport(spec)
	if err != nil {
		t.Fatalf("build two-hop: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("GET via two-hop egress: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	fN, fLast := front.stats()
	aN, aLast := acct.stats()
	if fN == 0 || fLast != acct.addr {
		t.Fatalf("first hop wrong: connects=%d last=%q want second-hop=%q", fN, fLast, acct.addr)
	}
	if aN == 0 || aLast != hostPort(t, target.URL) {
		t.Fatalf("exit hop wrong: connects=%d last=%q want target=%q", aN, aLast, hostPort(t, target.URL))
	}
}

// The per-account transport is cached per chain spec (the whole egress_proxy_url
// string). Same spec → cached instance; a different spec → a distinct transport.
// The account chain is self-contained (no node upstream_proxy), so the spec is
// the whole cache key.
func TestAccountEgressTransport_CachedBySpec(t *testing.T) {
	p := &Proxy{}
	acct := newSocks5TestServer(t, "", "")
	front := newSocks5TestServer(t, "", "")
	single := "socks5://" + acct.addr
	chained := "socks5://" + front.addr + ",socks5://" + acct.addr

	t1, err := p.accountEgressTransport(single)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	t2, err := p.accountEgressTransport(single)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if t1 != t2 {
		t.Fatal("same spec must return the CACHED transport, not rebuild")
	}

	t3, err := p.accountEgressTransport(chained)
	if err != nil {
		t.Fatalf("build chained: %v", err)
	}
	if t3 == t1 {
		t.Fatal("a different chain spec must build a distinct transport")
	}
}

func hostPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := parseTestURL(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u
}

// parseTestURL returns host:port for an http URL (httptest gives 127.0.0.1:port).
func parseTestURL(rawURL string) (string, error) {
	const p = "http://"
	if len(rawURL) < len(p) || rawURL[:len(p)] != p {
		return "", fmt.Errorf("not http url: %s", rawURL)
	}
	return rawURL[len(p):], nil
}
