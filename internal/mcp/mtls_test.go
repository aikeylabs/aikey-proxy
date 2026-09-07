package mcp

// mtls_test.go — fences 4.F6 / 4.F7 plus the one this feature nearly broke.
//
// # 🔴 The fence this feature nearly broke, and why it is here
//
// 15.F3 asserts that nothing of ours leaves for a third-party backend, and it
// asserted it about `upstreamHTTPClient` — the only outbound client that existed
// when it was written. mTLS adds a SECOND client per certificate alias. A second
// client is exactly how a guarantee like that gets lost: the fence stays green,
// because it is still looking at the first one.
//
// So the guarantee is restated here as a property of the SET of clients, and
// `outboundClients()` exists so the set can be enumerated. That function has no
// production caller, and that is a legitimate reason for it to exist: a set
// nobody enumerates is a set that grows one forgetful commit at a time.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// makeCertPEM mints a self-signed certificate + key as one PEM bundle, the shape
// an operator pastes into the console.
func makeCertPEM(t *testing.T, cn string) (bundle string, leaf *x509.Certificate) {
	t.Helper()
	return makeCertPEMValidUntil(t, cn, time.Now().Add(24*time.Hour))
}

// makeCertPEMValidUntil is makeCertPEM with the expiry as a parameter, so the
// 4.8c fences can mint a certificate that is already dead or nearly so. Kept as
// the single minting path: two copies would drift, and the copy the expiry
// fences use is the one nobody looks at.
func makeCertPEMValidUntil(t *testing.T, cn string, notAfter time.Time) (bundle string, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		// 🔴 Anchored behind notAfter, not at "an hour ago": an already-expired
		// certificate must still be internally consistent (NotBefore < NotAfter)
		// or x509 refuses to create it and the fence fails for the wrong reason.
		NotBefore:   notAfter.Add(-48 * time.Hour),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		// 🔴 An IP has to go in IPAddresses; Go verifies a dialled IP against
		// this field and ignores DNSNames for it. httptest serves on 127.0.0.1,
		// so without this the CLIENT rejects the server and the test fails in a
		// way that looks like the client certificate was wrong.
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	_ = pem.Encode(&sb, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&sb, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return sb.String(), parsed
}

// TestMTLSNeverSkipsServerVerification — fence 4.F6 / I25.
//
// 🔴 Mutual TLS authenticates BOTH ends. A deployment that presents a client
// certificate while accepting any server that asks has bought the inversion of
// what it paid for: it proves who IT is to whoever answers the address. The
// tempting way to reach this state is a support ticket that says "our backend
// uses a private CA" — the honest answer to which is RootCAs, not skipping
// verification.
func TestMTLSNeverSkipsServerVerification(t *testing.T) {
	bundle, _ := makeCertPEM(t, "client-a")
	mtlsClients.Delete("alias-verify")
	client, err := mtlsClientFor("alias-verify", UpstreamCredential{Kind: "mtls", Secret: bundle})
	if err != nil {
		t.Fatalf("building the client failed: %v", err)
	}

	tr, ok := client.Transport.(*headerStripper)
	if !ok {
		t.Fatalf("the mTLS client's transport is %T, not a headerStripper — see the other fence "+
			"in this file", client.Transport)
	}
	inner, ok := tr.next.(*http.Transport)
	if !ok {
		t.Fatalf("the stripper wraps %T, not an *http.Transport", tr.next)
	}
	if inner.TLSClientConfig == nil {
		t.Fatal("the mTLS client has no TLS config at all; it would present no certificate and " +
			"the backend's refusal would read as an outage")
	}
	if inner.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is set on the mTLS client.\n" +
			"🔴 Mutual TLS authenticates BOTH ends. Skipping server verification leaves a " +
			"deployment that believes it has mutual authentication while proving its own " +
			"identity to anything that answers the address — the exact inversion of what the " +
			"customer bought. A private CA belongs in RootCAs.")
	}
	if len(inner.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("the client carries %d certificates, want exactly the one for this alias",
			len(inner.TLSClientConfig.Certificates))
	}
	if inner.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion is %x; the one TLS config an operator's certificate rides on must "+
			"state its floor rather than inherit a default nobody checks", inner.TLSClientConfig.MinVersion)
	}
}

// TestMTLSWrongClientCertificateCannotConnect — fence 4.F7, the negative
// acceptance.
//
// 🔴 A REAL mutual-TLS server, not a mock. The property is about a handshake,
// and a mock would prove only that our code returns what we told it to. The
// server here requires and verifies a client certificate against a pool
// containing exactly one CA, so presenting a certificate from a different pair
// must fail at the handshake — which is what "the wrong certificate cannot
// connect" means.
func TestMTLSWrongClientCertificateCannotConnect(t *testing.T) {
	rightBundle, rightLeaf := makeCertPEM(t, "the-right-client")
	wrongBundle, _ := makeCertPEM(t, "some-other-client")

	pool := x509.NewCertPool()
	pool.AddCert(rightLeaf)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	srvBundle, srvLeaf := makeCertPEM(t, "127.0.0.1")
	srvPair, err := tls.X509KeyPair([]byte(srvBundle), []byte(srvBundle))
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	// Our clients verify the server, so the test has to trust the test server's
	// CA — 🔴 by extending the ROOT pool, never by turning verification off. A
	// test that reached for InsecureSkipVerify here would be exercising a
	// configuration the product must never ship.
	roots := x509.NewCertPool()
	roots.AddCert(srvLeaf)

	dial := func(alias, bundle string) error {
		mtlsClients.Delete(alias)
		c, cErr := mtlsClientFor(alias, UpstreamCredential{Kind: "mtls", Secret: bundle})
		if cErr != nil {
			return cErr
		}
		tr := c.Transport.(*headerStripper).next.(*http.Transport)
		tr.TLSClientConfig.RootCAs = roots
		b := UpstreamBackend{
			ID: "b", Name: "mtls-backend", Transport: TransportStreamableHTTP,
			EndpointURL: srv.URL, MTLSCertAlias: alias,
			MTLSCert: UpstreamCredential{Kind: "mtls", Secret: bundle},
		}
		trans, _ := LookupTransport(TransportStreamableHTTP)
		_, err := trans.CallTool(t.Context(), b, "ping", json.RawMessage(`{}`))
		return err
	}

	// 🔴 The positive case first. Without it, the negative case below passes on a
	// server that refuses everybody — the classic way a "wrong input is rejected"
	// test proves nothing.
	if err := dial("alias-right", rightBundle); err != nil {
		t.Fatalf("the CORRECT client certificate could not connect: %v.\n"+
			"This half exists so the refusal below means something: a server that refuses "+
			"everyone would satisfy it for free.", err)
	}

	if err := dial("alias-wrong", wrongBundle); err == nil {
		t.Fatal("a client certificate the server does not trust CONNECTED.\n" +
			"🔴 Mutual TLS is the backend's guarantee about who is calling it. If any certificate " +
			"is accepted, the backend's access control is decorative and the customer's audit " +
			"trail names a client that was never verified.")
	}
}

// TestEveryOutboundClientStripsHeaders — the widened form of 15.F3.
//
// 🔴 The original fence named `upstreamHTTPClient`, because it was the only
// outbound client. mTLS adds one per certificate alias, and a fence that names
// one client says nothing about the others: it would have stayed green while a
// new client shipped `X-Aikey-*` and `traceparent` to a customer's backend.
//
// 能红: build an outbound client whose transport is not wrapped in headerStripper.
func TestEveryOutboundClientStripsHeaders(t *testing.T) {
	bundle, _ := makeCertPEM(t, "client-strip")
	mtlsClients.Delete("alias-strip")
	if _, err := mtlsClientFor("alias-strip", UpstreamCredential{Kind: "mtls", Secret: bundle}); err != nil {
		t.Fatal(err)
	}

	clients := outboundClients()
	if len(clients) < 2 {
		t.Fatalf("outboundClients() returned %d clients; the mTLS client just built is missing, "+
			"so this fence would be inspecting only the one that was already safe", len(clients))
	}
	for i, c := range clients {
		if _, ok := c.Transport.(*headerStripper); !ok {
			t.Errorf("outbound client %d dials through %T, which is not the header stripper.\n"+
				"🔴 D-13/I32 is a property of EVERY client that can reach a third party, not of "+
				"the first one somebody wrote. Wrap it in headerStripper.", i, c.Transport)
		}
	}
}

// TestMTLSMaterialThatDoesNotParseIsRefusedNotDowngraded.
//
// 🔴 The failure mode this prevents is a QUIET one: falling back to the plain
// client would dial without a certificate, the backend would refuse the
// handshake, and the administrator would be sent to debug a network they have
// not broken while the real cause — material this process could see was
// unusable — went unreported.
func TestMTLSMaterialThatDoesNotParseIsRefusedNotDowngraded(t *testing.T) {
	mtlsClients.Delete("alias-broken")
	_, err := mtlsClientFor("alias-broken", UpstreamCredential{Kind: "mtls", Secret: "not a pem"})
	if err == nil {
		t.Fatal("unusable certificate material produced a client; it must be refused, never " +
			"downgraded to a plain connection")
	}
	if !strings.Contains(err.Error(), "alias-broken") {
		t.Errorf("the error does not name the alias, so an admin cannot tell which credential to "+
			"re-upload: %v", err)
	}
	// 🚫 And it must not quote the material: this is a private key.
	if strings.Contains(err.Error(), "not a pem") {
		t.Error("the error quotes the credential material back; that material is a private key")
	}
}

// resetMTLSState clears the process-wide client and validity tables.
//
// 🔴 These are package-level sync.Maps that outlive a single test, so a fence
// asserting "absent when nothing has been resolved" would otherwise pass or fail
// depending on which test ran before it — the kind of green that means nothing.
func resetMTLSState(t *testing.T) {
	t.Helper()
	clear := func(m *sync.Map) {
		m.Range(func(k, _ any) bool { m.Delete(k); return true })
	}
	clear(&mtlsClients)
	clear(&mtlsCertStates)
	t.Cleanup(func() { clear(&mtlsClients); clear(&mtlsCertStates) })
}

// TestMTLSExpiredCertificateIsRefusedAndIsVisible — fence 4.F14 (task 4.8c).
//
// 🔴 Two assertions, and the second is the one with teeth. Refusing an expired
// certificate is the easy half; the half that fails silently in production is
// that nobody can SEE it. tls.X509KeyPair does not check dates, so before 4.8c
// an expired certificate built a perfectly healthy-looking client and died at
// the handshake — surfacing to the administrator as "the backend is
// unreachable", which sends them to debug a network that is not broken.
func TestMTLSExpiredCertificateIsRefusedAndIsVisible(t *testing.T) {
	resetMTLSState(t)
	dead := time.Now().Add(-72 * time.Hour)
	bundle, _ := makeCertPEMValidUntil(t, "expired-client", dead)

	_, err := mtlsClientFor("alias-expired", UpstreamCredential{Secret: bundle})
	if err == nil {
		t.Fatal("an expired client certificate was accepted; 4.8c requires a refusal")
	}
	// The date has to be IN the message: "certificate expired" without it leaves
	// the operator unable to tell a stale upload from a clock problem.
	if !strings.Contains(err.Error(), "alias-expired") ||
		!strings.Contains(err.Error(), dead.UTC().Format(time.RFC3339)) {
		t.Errorf("refusal names neither the alias nor the expiry date: %v", err)
	}

	// 🔴 Recorded despite the refusal. If the state table only remembered
	// certificates that worked, the expired one — the only one anybody needs to
	// act on — would be the one missing from /health/mcp.
	got := mtlsCertHealth()
	if got["alias-expired"] != "expired" {
		t.Errorf("health does not report the expired certificate: %#v", got)
	}
}

// TestMTLSCertificateExpiringSoonSaysHowLong — fence 4.F15 (task 4.8c).
//
// A certificate that is still valid but running out must be visible BEFORE it
// dies, and with the number of days on it: "expiring" alone cannot be triaged
// against a customer's certificate-issuing lead time.
func TestMTLSCertificateExpiringSoonSaysHowLong(t *testing.T) {
	resetMTLSState(t)
	bundle, _ := makeCertPEMValidUntil(t, "soon-client", time.Now().Add(10*24*time.Hour+time.Hour))

	if _, err := mtlsClientFor("alias-soon", UpstreamCredential{Secret: bundle}); err != nil {
		t.Fatalf("a certificate valid for another 10 days must still be usable: %v", err)
	}
	got := mtlsCertHealth()["alias-soon"]
	// 9 or 10: the projection truncates, so the boundary is not worth pinning.
	if got != "expires_in_10d" && got != "expires_in_9d" {
		t.Errorf("expected days-remaining for a soon-expiring cert, got %q", got)
	}
}

// TestMTLSHealthyCertificateIsNotAlarming — the control arm for the two above.
//
// Without it, a projection that returned "expired" for everything would satisfy
// both expiry fences and still be useless.
func TestMTLSHealthyCertificateIsNotAlarming(t *testing.T) {
	resetMTLSState(t)
	bundle, _ := makeCertPEMValidUntil(t, "fine-client", time.Now().Add(365*24*time.Hour))

	if _, err := mtlsClientFor("alias-fine", UpstreamCredential{Secret: bundle}); err != nil {
		t.Fatalf("a certificate valid for a year was refused: %v", err)
	}
	if got := mtlsCertHealth()["alias-fine"]; got != "ok" {
		t.Errorf("a healthy certificate reports %q", got)
	}
}

// TestMTLSHealthIsAbsentNotEmptyWhenUnused — fence 4.F16 (task 4.8c).
//
// 🔴 Absent and empty are different claims. `{}` in the payload reads as "we
// track mTLS certificates and all of them are fine"; absence reads as "nothing
// here has used one". Conflating them is how a deployment with an untouched,
// long-dead certificate renders as healthy.
func TestMTLSHealthIsAbsentNotEmptyWhenUnused(t *testing.T) {
	resetMTLSState(t)
	if got := mtlsCertHealth(); got != nil {
		t.Errorf("expected absent (nil) when no certificate has been resolved, got %#v", got)
	}
}

// TestMTLSCachedClientStopsServingAnExpiredCertificate — fence 4.F17 (task 4.8c).
//
// 🔴 The client is cached for the life of the process, deliberately, so that mTLS
// does not cost a handshake per call. That cache is also how an expiry gets
// missed: a proxy that started while the certificate was valid would keep
// presenting it forever. This drives the expiry from the state table so the
// clock can be moved without minting a second certificate.
func TestMTLSCachedClientStopsServingAnExpiredCertificate(t *testing.T) {
	resetMTLSState(t)
	bundle, _ := makeCertPEMValidUntil(t, "rollover-client", time.Now().Add(365*24*time.Hour))

	if _, err := mtlsClientFor("alias-rollover", UpstreamCredential{Secret: bundle}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// The certificate expires while the process keeps running.
	past := time.Now().Add(-time.Minute)
	mtlsCertStates.Store("alias-rollover", mtlsCertState{NotAfter: past, Expired: true})

	if _, err := mtlsClientFor("alias-rollover", UpstreamCredential{Secret: bundle}); err == nil {
		t.Fatal("the cached client kept serving an expired certificate")
	}
}

// TestMTLSBackendWithoutResolvedMaterialIsRefusedNotDialledPlain — fence 4.F18
// (task 4.8b, the "不带证书去连" arm).
//
// 🔴 The dangerous outcome here is not an error, it is a SUCCESS: a backend that
// declares an alias whose material never resolved (unbound in the console, a
// failed credential poll, a revoked entry) must not quietly fall back to the
// shared client. That fallback dials WITHOUT a client certificate, so a backend
// which is only reachable by mutual TLS answers with a TLS alert — and the
// administrator reads it as "the gateway cannot reach the backend", debugging a
// network that is not broken while the real cause is an unbound credential.
//
// The control arm matters as much: a backend with no alias must still get the
// plain client, or "refuse when unresolved" would be satisfied by refusing
// everything.
func TestMTLSBackendWithoutResolvedMaterialIsRefusedNotDialledPlain(t *testing.T) {
	resetMTLSState(t)

	// Control: no alias at all → the shared client, unchanged behaviour.
	plain, err := clientFor(UpstreamBackend{ID: "b0", Name: "no-mtls"})
	if err != nil {
		t.Fatalf("a backend that does not use mTLS was refused: %v", err)
	}
	if plain != upstreamHTTPClient {
		t.Error("a backend without an alias must use the shared client")
	}

	// The fence: alias declared, material absent.
	got, err := clientFor(UpstreamBackend{ID: "b1", Name: "needs-mtls", MTLSCertAlias: "alias-unbound"})
	if err == nil {
		t.Fatal("a backend requiring a client certificate was given a client despite unresolved material")
	}
	if got == upstreamHTTPClient {
		t.Error("🔴 fell back to the shared client — this dials without presenting any certificate")
	}
	if !strings.Contains(err.Error(), "alias-unbound") {
		t.Errorf("the refusal does not name the unresolved alias: %v", err)
	}
}
