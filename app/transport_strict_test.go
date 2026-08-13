package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AiKeyLabs/pkg/egress"
)

// The two functions encode OPPOSITE policies on purpose. These fences exist so a
// future "let's just have one" refactor has to confront the reason:
//
//	buildTransport       live path — degrade rather than fail a request in flight
//	buildTransportStrict test path — a test must exercise what it was handed
//
// Collapsing them reintroduces the 2026-07-24 bug: a malformed fragment fell back
// to the machine's system proxy and the "Test connectivity" button reported that
// proxy's timeout, so the user debugged a node that was never dialed while the
// real cause sat in a WARN log they never saw.

// malformedFragment looks like an engine spec (so IsEngineSpec routes it to the
// engine) but is not a valid proxies/proxy-groups document. This is the exact
// shape a YAML-vs-JS syntax slip produces — the field case was a config pasted
// with trailing commas and `//` comments.
const malformedFragment = "proxies:\n  - name: x, type: ss, server: h, port: 1,\n"

// A fragment reaches TWO distinct strict-error paths depending on the build, and
// they must be asserted separately — asserting only "some error came back" let an
// injected regression slip through (found while red-proving these fences):
//
//	OSS build         → capability gate rejects it (mihomo absent)
//	enterprise build  → BuildEgressTransport parses it and rejects the syntax
//
// Whichever path this build takes, strict must ERROR and must not hand back a
// transport. The parse path additionally has to carry mihomo's own wording, since
// that string is the only thing telling the user their YAML is malformed.
func TestBuildTransportStrict_FragmentErrorsOnThisBuild(t *testing.T) {
	tr, closer, err := buildTransportStrict(malformedFragment, nil)
	if closer != nil {
		defer closer.Close()
	}
	if err == nil {
		t.Fatalf("buildTransportStrict accepted a malformed fragment (transport=%v).\n"+
			"It must return the build error so the probe can show it; falling back here is\n"+
			"what made the Test-connectivity button report an unrelated system-proxy timeout.", tr != nil)
	}
	if tr != nil {
		t.Error("a failed strict build must not also return a transport — the caller could use it by mistake")
	}

	msg := err.Error()
	if egress.MultiProtocolAvailable() {
		// Enterprise: the error must be mihomo's parse complaint, NOT the
		// capability message — otherwise the user is told to buy a package they
		// already have while their real problem (bad YAML) stays hidden.
		if strings.Contains(msg, "enterprise package") {
			t.Errorf("enterprise build reported a capability error for a PARSE failure: %q", msg)
		}
	} else if !strings.Contains(msg, "enterprise package") {
		// OSS: must name the missing capability so the user knows what to install.
		t.Errorf("OSS build should explain the missing enterprise capability; got %q", msg)
	}
}

// TestBuildTransportStrict_ParsePathErrorsIndependently pins the parse branch
// directly, so it stays covered on OSS builds where the capability gate would
// otherwise short-circuit before BuildEgressTransport is ever reached. A socks5
// chain is engine-handled on EVERY edition, so a malformed chain exercises the
// parse/build path without needing mihomo.
func TestBuildTransportStrict_ParsePathErrorsIndependently(t *testing.T) {
	// Engine-routed (comma chain) but each hop is an unusable URL.
	tr, closer, err := buildTransportStrict("socks5://:::::,socks5://:::::", nil)
	if closer != nil {
		defer closer.Close()
	}
	if err == nil {
		t.Fatalf("strict accepted an unusable socks5 chain (transport=%v) — the build error must surface", tr != nil)
	}
	if strings.Contains(err.Error(), "enterprise package") {
		t.Errorf("a socks5 chain must never report a missing-enterprise error; got %q", err)
	}
}

func TestBuildTransport_StillFallsBackOnLivePath(t *testing.T) {
	// The live path deliberately keeps degrading: an in-flight request should not
	// hard-fail because a stored spec went bad.
	tr, closer := buildTransport(malformedFragment, nil)
	if closer != nil {
		defer closer.Close()
	}
	if tr == nil {
		t.Fatal("buildTransport must always return a usable transport (fallback is the live-path contract)")
	}
}

func TestBuildTransportStrict_EmptySpecIsDirectNotAnError(t *testing.T) {
	// "no egress configured" is a valid state, not a failure — the probe endpoint
	// rejects an empty spec earlier, but strict must not turn direct into an error.
	tr, closer, err := buildTransportStrict("", nil)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		t.Fatalf("empty spec must build a direct transport, got error: %v", err)
	}
	if tr == nil {
		t.Fatal("empty spec must return a transport")
	}
}

func TestBuildTransportStrict_InvalidURLNamesTheInput(t *testing.T) {
	// A single-URL spec that won't parse must say WHICH value was rejected —
	// "invalid url" alone sends the user hunting.
	_, closer, err := buildTransportStrict("http://[::1", nil)
	if closer != nil {
		defer closer.Close()
	}
	if err == nil {
		t.Fatal("an unparseable upstream URL must be an error under strict")
	}
	if !strings.Contains(err.Error(), "[::1") {
		t.Errorf("error should quote the offending input so the user can see it; got %q", err)
	}
}

func TestBuildTransportStrict_SocksChainBuildsOnEveryEdition(t *testing.T) {
	// A socks5 CHAIN is handled by the built-in GPL-free engine on every build
	// (requirements/2026-07-17-egress-spec-capability-by-edition.md). Strict must
	// not reject it as if it needed the enterprise package — no dial happens here,
	// so this stays hermetic.
	tr, closer, err := buildTransportStrict("socks5://127.0.0.1:11080,socks5://127.0.0.1:11081", nil)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		t.Fatalf("socks5 chain must build on every edition, got: %v", err)
	}
	if tr == nil {
		t.Fatal("socks5 chain must return a transport")
	}
}

// TestProbeUpstreamProxy_RejectsBadSpecWithoutDialing is the fence for the bug
// itself: the probe must refuse a spec it cannot build rather than quietly dialing
// through whatever the machine's system proxy happens to be.
//
// Design note — why a LIVE local server as the target: an unreachable target makes
// this fence useless, because the fallback path also errors (connection refused)
// and "err != nil" then proves nothing. Pointing at a server that ANSWERS 200
// splits the two behaviors cleanly:
//
//	strict (correct)  → build error, nothing dialed, status 0
//	fallback (bug)    → direct transport reaches the server, status 200
func TestProbeUpstreamProxy_RejectsBadSpecWithoutDialing(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	status, _, err := probeUpstreamProxy(malformedFragment, nil, srv.URL)
	if err == nil {
		t.Fatalf("probe accepted an unbuildable spec (status=%d) — it must report the build error, "+
			"not fall back and report an unrelated result", status)
	}
	if status != 0 {
		t.Errorf("status = %d, want 0: nothing should have been dialed", status)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("target received %d request(s): the spec was ignored and the probe dialed anyway "+
			"(this is exactly the 2026-07-24 regression)", n)
	}
}
