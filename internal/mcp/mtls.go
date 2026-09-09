package mcp

// mtls.go — client certificates for a backend that requires mutual TLS
// (P4 · task 4.8 · D-10).
//
// # What the backend row has always said, and what was missing
//
// `mcp_backend.mtls_cert_alias` has been on the wire since the alpha.9 baseline:
// a backend can say "authenticate to me with a client certificate called X". Up
// to v1.0.1-alpha.15 there was nowhere to store certificate X — the credential
// table's `kind` admitted only the four injection shapes — so the alias pointed
// at something the system could not hold. That gap is what this file and the
// alpha.15 migration close together.
//
// # 🔴 Why a client PER CERTIFICATE, and not one shared client
//
// A TLS client certificate is presented during the HANDSHAKE, so it is a
// property of the CONNECTION, not of the request. `http.Transport` keeps a
// connection POOL: a request sent on a pooled connection reuses whatever
// certificate that connection was established with. So a single shared client
// cannot vary the certificate per backend — it would present whichever cert the
// pooled connection happened to carry, which on a machine with two mTLS backends
// means one of them silently authenticates as the other.
//
// 🚫 Do not "optimise" this into one client with a `GetClientCertificate`
// callback either: that callback receives the server's certificate request, not
// our backend identity, so it cannot make the choice on any input it is given.
//
// # 🔴 Every client here strips headers, and that is not optional
//
// `upstreamHTTPClient` gets D-13/I32 (nothing of ours leaves for a third party)
// from its `headerStripper` transport. A second outbound client is exactly how
// that guarantee gets lost — silently, because the existing fence only knew
// about the one client. Every client built here therefore wraps the SAME
// stripper, and `outboundClients` (below) is what the widened fence enumerates
// so a third client cannot be added without one.
// Fence: TestEveryOutboundClientStripsHeaders.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// mtlsClients caches one http.Client per certificate alias.
//
// 🔴 Cached rather than built per call: building a client is cheap, but a new
// client means a new connection POOL, so building one per request would
// re-handshake every time — turning mTLS into a per-call TLS round trip on the
// path a developer's agent walks constantly.
//
// Keyed by alias, not by the certificate material: the alias is what the backend
// row names, and two backends sharing an alias legitimately share a pool.
var mtlsClients sync.Map // alias -> *http.Client

// mtlsCertStates records what we last observed about each alias's validity
// window (task 4.8c).
//
// 🔴 Written on the REFUSAL path too, not only on success. An expired
// certificate is exactly the case an administrator must be able to see, and a
// table that only remembers the certificates that worked would leave the one
// that matters invisible — a silent failure, which 4.8c exists to forbid.
//
// 🔴 This covers aliases THIS PROCESS HAS RESOLVED. A backend that has not
// been dialled since start-up is not pre-checked, so absence here means "no mTLS
// certificate has been used on this process", NOT "every certificate is valid".
// Pre-flighting every configured alias needs the credential material for
// backends nobody has called, which is a separate change; saying so here is the
// honest form, because a health field that silently omits what it cannot see
// reads identically to one reporting good news.
var mtlsCertStates sync.Map // alias -> mtlsCertState

type mtlsCertState struct {
	NotAfter time.Time
	Expired  bool
}

// mtlsExpiryError is the refusal an expired certificate produces. It names the
// alias and the date, because "TLS handshake failed" sends an administrator to
// debug a network that is not broken.
func mtlsExpiryError(alias string, notAfter time.Time) error {
	return fmt.Errorf("the client certificate stored under alias %q expired on %s; "+
		"rotate it in the console (Keys \u2192 MCP credentials) \u2014 the backend will refuse "+
		"this connection until you do", alias, notAfter.UTC().Format(time.RFC3339))
}

// mtlsCertHealth projects the table for /health/mcp.
//
// Returns nil (absent), never an empty map, when no alias has been resolved:
// "this build does not use mTLS" and "it uses mTLS and every certificate is
// fine" are different claims, and the same distinction the Backends map draws.
func mtlsCertHealth() map[string]string {
	out := map[string]string{}
	now := time.Now()
	mtlsCertStates.Range(func(k, v any) bool {
		alias := k.(string)
		st := v.(mtlsCertState)
		switch {
		case st.Expired || now.After(st.NotAfter):
			out[alias] = "expired"
		case now.Add(mtlsExpiryWarnWindow).After(st.NotAfter):
			// Days remaining, not a bare "expiring": the administrator's next
			// question is always "how long have I got".
			out[alias] = fmt.Sprintf("expires_in_%dd", int(time.Until(st.NotAfter).Hours()/24))
		default:
			out[alias] = "ok"
		}
		return true
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// mtlsExpiryWarnWindow is how far ahead /health/mcp starts saying a certificate
// is running out. 30 days is the shortest notice that still leaves room for a
// customer's own certificate-issuing process, which is rarely same-day.
const mtlsExpiryWarnWindow = 30 * 24 * time.Hour

// mtlsClientFor returns the client that presents the certificate stored under
// alias, building it on first use.
//
// 🔴 An ERROR when the material does not parse, never a fallback to the plain
// client. Falling back would connect WITHOUT a client certificate, and the
// backend's refusal reads as "the gateway cannot reach it" — sending the
// administrator to debug a network they have not broken, while the actual cause
// is a certificate this process could see was malformed.
func mtlsClientFor(alias string, cred UpstreamCredential) (*http.Client, error) {
	if c, ok := mtlsClients.Load(alias); ok {
		// 🔴 Re-checked on the CACHED path, not only when building. A
		// certificate expires while this process runs, and the client is cached
		// for the life of the process precisely so we do not re-handshake. Only
		// checking at build time would mean a proxy that started before expiry
		// keeps presenting a dead certificate until someone restarts it, and the
		// backend's 4xx is what the administrator would have to debug from.
		if v, ok := mtlsCertStates.Load(alias); ok {
			if st := v.(mtlsCertState); time.Now().After(st.NotAfter) {
				return nil, mtlsExpiryError(alias, st.NotAfter)
			}
		}
		return c.(*http.Client), nil
	}
	raw := []byte(cred.Secret)
	pair, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		// 🚫 The underlying error is not wrapped in: it can quote PEM block
		// types and offsets, and this material is a private key. The control
		// plane already refuses an unparseable bundle at the door
		// (validateMTLSKeypair), so reaching this line means the material was
		// changed underneath us — which is worth saying, without saying what it
		// contains.
		return nil, fmt.Errorf("the client certificate stored under alias %q is not a usable "+
			"certificate/key pair; re-upload it in the console (Keys → MCP credentials)", alias)
	}

	// 🔴 The leaf is parsed for its validity window (4.8c). tls.X509KeyPair
	// does NOT check dates -- it only proves the key matches the certificate --
	// so without this an expired certificate builds a perfectly good client and
	// fails later at the handshake, which is the silent failure 4.8c forbids.
	leaf, lerr := x509.ParseCertificate(pair.Certificate[0])
	if lerr != nil {
		// 🚫 Same reasoning as the pair error above: the parser can quote
		// offsets into material that includes a private key.
		return nil, fmt.Errorf("the client certificate stored under alias %q parses as a key pair "+
			"but its certificate cannot be read; re-upload it in the console (Keys \u2192 MCP credentials)", alias)
	}
	expired := time.Now().After(leaf.NotAfter)
	// Recorded BEFORE the refusal below, so an expired certificate is visible in
	// /health/mcp rather than only in the error returned to one caller.
	mtlsCertStates.Store(alias, mtlsCertState{NotAfter: leaf.NotAfter, Expired: expired})
	if expired {
		return nil, mtlsExpiryError(alias, leaf.NotAfter)
	}

	client := &http.Client{
		// The same hard ceiling the shared client uses, and for the same reason:
		// a context deadline bounds the request, this bounds the connection.
		Timeout: 120 * time.Second,
		Transport: &headerStripper{next: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{pair},
				// 🔴 MinVersion is set explicitly rather than left to the default.
				// The default is already 1.2, but this is the one TLS config in
				// the product an operator's certificate rides on, and "whatever
				// the runtime defaults to" is not a property anybody can check.
				MinVersion: tls.VersionTLS12,
				// 🔴 InsecureSkipVerify is DELIBERATELY not set, and must never
				// be. Mutual TLS authenticates BOTH ends; skipping server
				// verification would leave a deployment that believes it has
				// mutual authentication while accepting any server that asks —
				// the exact inversion of what the customer bought. A backend with
				// a private CA belongs in RootCAs, which is a separate, honest
				// change. Fence: TestMTLSNeverSkipsServerVerification.
			},
		}},
	}
	actual, _ := mtlsClients.LoadOrStore(alias, client)
	return actual.(*http.Client), nil
}

// outboundClients returns every http.Client this package can dial a third-party
// backend with.
//
// 🔴 It exists for the fence, and that is a legitimate reason for it to exist:
// the header-stripping guarantee is a property of the SET of clients, and a set
// nobody enumerates is a set that grows one forgetful commit at a time. The
// alternative — a fence that names `upstreamHTTPClient` — proved exactly nothing
// about the client this file adds.
//
// 🚫 Adding an outbound client without adding it here is the failure this
// guards; the fence asserts the set is non-empty and that every member strips.
func outboundClients() []*http.Client {
	out := []*http.Client{upstreamHTTPClient}
	mtlsClients.Range(func(_, v any) bool {
		out = append(out, v.(*http.Client))
		return true
	})
	return out
}
