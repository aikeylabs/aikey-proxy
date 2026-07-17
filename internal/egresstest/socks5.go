// Package egresstest provides shared test rigs for the per-account egress path
// (§11.7). It lives in a non-_test.go file so BOTH the proxy package (read side:
// resolve → account transport → dial) and the supervisor package (write side:
// member-rail HTTP pull → vault projection) can drive the SAME real socks5
// recorder in-process. Imported only from _test.go files, so it is never linked
// into the production binary.
package egresstest

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Socks5Server is a minimal RFC 1928 CONNECT server (no-auth + username/password)
// that records every CONNECT target, so a chained-egress test can assert the exit
// hop was really traversed (and, for multi-hop, in order). It is a real listener
// doing real dials — not a stub — so "egress took effect" means bytes actually
// went through it.
type Socks5Server struct {
	ln         net.Listener
	addr       string
	lastTarget string
	wantUser   string // "" = no-auth
	wantPass   string
	mu         sync.Mutex
	connects   int
}

// NewSocks5Server starts a socks5 recorder on 127.0.0.1:0. Pass user/pass to
// require username/password auth ("" = no-auth). Closed automatically via t.Cleanup.
func NewSocks5Server(t *testing.T, user, pass string) *Socks5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &Socks5Server{ln: ln, addr: ln.Addr().String(), wantUser: user, wantPass: pass}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// Addr is the server's dial address (host:port).
func (s *Socks5Server) Addr() string { return s.addr }

// Stats returns how many CONNECTs were served and the last CONNECT target.
func (s *Socks5Server) Stats() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects, s.lastTarget
}

func (s *Socks5Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *Socks5Server) handle(c net.Conn) {
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

func (s *Socks5Server) authUserPass(c net.Conn) bool {
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
