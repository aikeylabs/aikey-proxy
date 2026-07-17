package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/egress"
)

// The real socks5 CONNECT recorder used by these tests lives in
// internal/egresstest (shared with the supervisor package's member-rail egress
// E2E), so the write side (HTTP pull → vault) and the read side (resolve → dial)
// exercise the SAME rig.

// --- tests ---------------------------------------------------------------------

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

// The per-account transport is cached per chain spec (the whole egress_proxy_url
// string). Same spec → cached instance; a different spec → a distinct transport.
// The account chain is self-contained (no node upstream_proxy), so the spec is
// the whole cache key.
func TestAccountEgressTransport_CachedBySpec(t *testing.T) {
	p := &Proxy{}
	acct := egresstest.NewSocks5Server(t, "", "")
	front := egresstest.NewSocks5Server(t, "", "")
	single := "socks5://" + acct.Addr()
	chained := "socks5://" + front.Addr() + ",socks5://" + acct.Addr()

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

// TestEgressDelivery_DeliveredMaterialEgressesThroughAccountProxy is the
// client-side integration of the egress delivery chain (§11.7): it proves that a
// per-account egress_proxy_url DELIVERED in the group_runtime material actually
// makes the proxy egress THROUGH that account's proxy at request time — stitching
// the real resolver + real transport builder + a REAL socks5 dial in one test.
//
// It picks up where the CLI projection fence (aikey-cli vault_op.rs) leaves off:
// that fence proves the CLI writes egress_proxy_url into the node vault material;
// this proves the proxy READS it back, resolves the account, and dials out
// through it. Together with the master org-rail fence (groupruntime org_test) and
// the daemon relay fence (aikey-hub), every hop of "server sets egress → local
// proxy egresses through it" has a real test.
//
// 能红: if the resolver drops EgressProxyURL, or serveRoute stops honoring it, the
// account socks5 is never traversed → the exit assertion fails.
func TestEgressDelivery_DeliveredMaterialEgressesThroughAccountProxy(t *testing.T) {
	noEgressBypass(t) // hermetic: dial loopback stand-in THROUGH the egress
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	// The account's delivered egress proxy (what an admin set on master and the
	// CLI projected into the node vault material).
	exit := egresstest.NewSocks5Server(t, "", "")

	key := grKey()
	seat := "seat-1"
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	// group_runtime material EXACTLY as the CLI projects it: encrypted token +
	// the plaintext per-account egress_proxy_url.
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ExpiresAt:      9_000_000_000,
			EgressProxyURL: "socks5://" + exit.Addr(), // delivered per-account egress
		}, "tok-abc"),
	}
	route := &vkeys.ResolvedRoute{
		SeatID:        seat,
		OauthGroupID:  "grp",
		GroupAccounts: mustJSON(t, refs),
		GroupRuntime:  mustJSON(t, mat),
	}

	// 1) REAL resolution carries the delivered egress onto the resolution.
	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.EgressProxyURL != "socks5://"+exit.Addr() {
		t.Fatalf("delivered egress not carried onto resolution: %q", res.EgressProxyURL)
	}

	// 2) serveRoute sets rc.EgressProxyURL from the resolution; here we drive the
	//    same per-account transport path with a REAL dial.
	p := &Proxy{}
	tr, err := p.accountEgressTransport(res.EgressProxyURL)
	if err != nil {
		t.Fatalf("build account egress transport: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through delivered egress: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	// 3) The account's delivered socks5 MUST have been traversed to the target —
	//    proving the remotely-configured egress truly took effect in the proxy.
	if n, last := exit.Stats(); n == 0 || last != hostPort(t, target.URL) {
		t.Fatalf("delivered egress not used: account socks5 connects=%d last=%q want target=%q", n, last, hostPort(t, target.URL))
	}
}

// TestEgressDelivery_PerAccountIsolation_EachAccountEgressesThroughItsOwnExit is
// the decisive proof of the "每个账号单独一个出口并且生效" claim: TWO pool accounts,
// each delivered with a DIFFERENT egress_proxy_url, must each egress through THEIR
// OWN socks5 exit — and never cross. It drives the REAL resolver (pinning each
// account via overrideAccountID, the same knob group_serve uses) + the REAL
// transport builder + REAL socks5 dials, then asserts each exit served ONLY its own
// account's target and NOT the other's. This is what TestEgressDelivery (one
// account) and TestAccountEgressTransport_CachedBySpec (distinct spec → distinct
// transport, no dial) each covered only half of.
//
// 能红: if the resolver dropped the per-account egress, or the spec-keyed transport
// cache collapsed the two accounts onto one exit, or serveRoute reused the wrong
// account's transport, one exit would serve BOTH targets (or the wrong one) → the
// cross-talk assertions fire.
func TestEgressDelivery_PerAccountIsolation_EachAccountEgressesThroughItsOwnExit(t *testing.T) {
	noEgressBypass(t) // hermetic: dial loopback stand-ins THROUGH the egress

	targetA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "A") }))
	defer targetA.Close()
	targetB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "B") }))
	defer targetB.Close()

	// Two DISTINCT per-account exits — account A pinned to exitA, account B to exitB.
	exitA := egresstest.NewSocks5Server(t, "", "")
	exitB := egresstest.NewSocks5Server(t, "", "")

	key := grKey()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-A", ProviderCode: "anthropic"},
		{AccountID: "acc-B", ProviderCode: "anthropic"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-A": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000,
			EgressProxyURL: "socks5://" + exitA.Addr(),
		}, "tok-A"),
		"acc-B": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000,
			EgressProxyURL: "socks5://" + exitB.Addr(),
		}, "tok-B"),
	}
	route := &vkeys.ResolvedRoute{
		SeatID: "seat-1", OauthGroupID: "grp",
		GroupAccounts: mustJSON(t, refs),
		GroupRuntime:  mustJSON(t, mat),
	}

	// Drive each account through the REAL resolver + transport + a REAL dial.
	p := &Proxy{}
	egressTo := func(t *testing.T, accountID, wantExitAddr, targetURL string) {
		t.Helper()
		res, err := resolveGroupCredential(route, key, 1_000_000, nil, accountID)
		if err != nil {
			t.Fatalf("resolve %s: %v", accountID, err)
		}
		if res.EgressProxyURL != "socks5://"+wantExitAddr {
			t.Fatalf("%s resolved egress=%q want socks5://%s", accountID, res.EgressProxyURL, wantExitAddr)
		}
		tr, err := p.accountEgressTransport(res.EgressProxyURL)
		if err != nil {
			t.Fatalf("%s transport: %v", accountID, err)
		}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, targetURL, nil)
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("%s GET through egress: %v", accountID, err)
		}
		_ = resp.Body.Close()
	}
	egressTo(t, "acc-A", exitA.Addr(), targetA.URL)
	egressTo(t, "acc-B", exitB.Addr(), targetB.URL)

	// Each exit served ONLY its own account's target — this is per-account isolation.
	if n, last := exitA.Stats(); n == 0 || last != hostPort(t, targetA.URL) {
		t.Fatalf("exitA did not serve acc-A's target: connects=%d last=%q want %q", n, last, hostPort(t, targetA.URL))
	}
	if n, last := exitB.Stats(); n == 0 || last != hostPort(t, targetB.URL) {
		t.Fatalf("exitB did not serve acc-B's target: connects=%d last=%q want %q", n, last, hostPort(t, targetB.URL))
	}
	// No cross-talk: exitA must never have seen B's target, exitB never A's.
	if _, lastA := exitA.Stats(); lastA == hostPort(t, targetB.URL) {
		t.Fatalf("CROSS-TALK: acc-B's traffic egressed through acc-A's exit")
	}
	if _, lastB := exitB.Stats(); lastB == hostPort(t, targetA.URL) {
		t.Fatalf("CROSS-TALK: acc-A's traffic egressed through acc-B's exit")
	}
}

// Non-socks5 hop anywhere in the chain → build error (surfaced, not silent),
// via the real request-path method. Single hop and multi-hop.
func TestAccountEgressTransport_RejectsNonSocks5(t *testing.T) {
	p := &Proxy{}
	if _, err := p.accountEgressTransport("http://1.2.3.4:8080"); err == nil {
		t.Fatal("non-socks5 egress hop must error")
	}
	if _, err := p.accountEgressTransport("socks5://1.2.3.4:1080,http://5.6.7.8:8080"); err == nil {
		t.Fatal("a non-socks5 hop in the chain must error, not silently downgrade")
	}
	if _, err := p.accountEgressTransport("  "); err == nil {
		t.Fatal("an all-empty chain spec must error")
	}
}

// Single-hop: one socks5 hop → node → account → upstream, through the real
// per-account transport path.
func TestAccountEgressTransport_SingleHop(t *testing.T) {
	noEgressBypass(t) // hermetic: dial loopback stand-in THROUGH the egress
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	acct := egresstest.NewSocks5Server(t, "", "")
	tr, err := (&Proxy{}).accountEgressTransport("socks5://" + acct.Addr())
	if err != nil {
		t.Fatalf("build single-hop: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET via single-hop egress: %v", err)
	}
	_ = resp.Body.Close()
	if n, last := acct.Stats(); n == 0 || last != hostPort(t, target.URL) {
		t.Fatalf("account proxy not traversed: connects=%d last=%q want=%q", n, last, hostPort(t, target.URL))
	}
}

// Two-hop chain in ONE field: "socks5://F,socks5://A" → node → F → A → upstream.
// Asserts hop ORDER: F is asked to reach A, A is asked to reach the upstream, so
// the exit IP is the last hop's.
func TestAccountEgressTransport_TwoHopChainOrder(t *testing.T) {
	noEgressBypass(t) // hermetic: dial loopback stand-in THROUGH the egress
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	front := egresstest.NewSocks5Server(t, "", "")
	acct := egresstest.NewSocks5Server(t, "fuser", "fpass")
	spec := "socks5://" + front.Addr() + ",socks5://fuser:fpass@" + acct.Addr()
	tr, err := (&Proxy{}).accountEgressTransport(spec)
	if err != nil {
		t.Fatalf("build two-hop: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET via two-hop egress: %v", err)
	}
	_ = resp.Body.Close()

	fN, fLast := front.Stats()
	aN, aLast := acct.Stats()
	if fN == 0 || fLast != acct.Addr() {
		t.Fatalf("first hop wrong: connects=%d last=%q want second-hop=%q", fN, fLast, acct.Addr())
	}
	if aN == 0 || aLast != hostPort(t, target.URL) {
		t.Fatalf("exit hop wrong: connects=%d last=%q want target=%q", aN, aLast, hostPort(t, target.URL))
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
