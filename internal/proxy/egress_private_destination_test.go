package proxy

import (
	"errors"
	"net/http"
	"testing"
)

// errRoundTripper always fails, standing in for a tunnel whose far end cannot
// reach the destination (staging saw this as a bare `EOF`).
type errRoundTripper struct{ err error }

func (r errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, r.err }

func mustRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, nil)
	if err != nil {
		t.Fatalf("build request %q: %v", rawURL, err)
	}
	return req
}

// TestEgressDiagnosticTransport_TagsIntranetDestination is the regression fence
// for the 2026-08-26 staging finding: a custom provider on a LAN address, on a
// Cluster node with `upstream_proxy`, failed with an opaque UPSTREAM_ERROR/EOF
// that named neither the cause nor the remedy.
//
// The fence asserts the DIAGNOSIS, not the routing: routing is unchanged, and
// which hosts bypass the egress is still NoProxyBypass's decision (2026-07-16
// option ② 拍板). Bugfix:
// workflow/CI/bugfix/20260826-egress-private-destination-undiagnosable.md
func TestEgressDiagnosticTransport_TagsIntranetDestination(t *testing.T) {
	underlying := errors.New("EOF")
	// Nothing is NO_PROXY-declared — the staging condition exactly.
	noBypass := func(string) bool { return false }

	t.Run("intranet destination is tagged and names the host", func(t *testing.T) {
		rt := &egressDiagnosticTransport{base: errRoundTripper{underlying}, bypass: noBypass}
		_, err := rt.RoundTrip(mustRequest(t, "http://10.0.0.93:19099/v1/chat/completions"))

		var privErr *PrivateDestinationEgressError
		if !errors.As(err, &privErr) {
			t.Fatalf("an intranet dial failure must surface as *PrivateDestinationEgressError "+
				"so the operator is told about NO_PROXY; got %T: %v", err, err)
		}
		if privErr.Host != "10.0.0.93" {
			t.Errorf("Host = %q, want %q — the message quotes it as the NO_PROXY entry", privErr.Host, "10.0.0.93")
		}
		if !errors.Is(err, underlying) {
			t.Error("the original transport error must stay unwrappable (forensics)")
		}
	})

	// Anti-vacuity: the two ways this tag would be WRONG. Without these, a
	// transport that tagged unconditionally would still pass the case above.
	t.Run("public destination is left alone", func(t *testing.T) {
		rt := &egressDiagnosticTransport{base: errRoundTripper{underlying}, bypass: noBypass}
		_, err := rt.RoundTrip(mustRequest(t, "https://api.openai.com/v1/chat/completions"))

		var privErr *PrivateDestinationEgressError
		if errors.As(err, &privErr) {
			t.Fatal("a PUBLIC provider outage must not be blamed on the egress tunnel — " +
				"that sends the operator to edit NO_PROXY for an unrelated fault")
		}
		if !errors.Is(err, underlying) {
			t.Errorf("error must pass through unchanged, got %v", err)
		}
	})

	t.Run("NO_PROXY-bypassed intranet host is left alone", func(t *testing.T) {
		// This host dials DIRECT, so its failure is not the tunnel's doing.
		bypassAll := func(string) bool { return true }
		rt := &egressDiagnosticTransport{base: errRoundTripper{underlying}, bypass: bypassAll}
		_, err := rt.RoundTrip(mustRequest(t, "http://10.0.0.93:19099/v1/chat/completions"))

		var privErr *PrivateDestinationEgressError
		if errors.As(err, &privErr) {
			t.Fatal("a host the operator ALREADY declared in NO_PROXY went direct; " +
				"telling them to declare it again is a dead end")
		}
	})

	t.Run("success is never touched", func(t *testing.T) {
		ok := &http.Response{StatusCode: http.StatusOK}
		rt := &egressDiagnosticTransport{
			base: rtFunc(func(*http.Request) (*http.Response, error) { return ok, nil }),
			// Would tag everything if it were consulted on the success path.
			bypass: noBypass,
		}
		resp, err := rt.RoundTrip(mustRequest(t, "http://10.0.0.93:19099/v1/chat/completions"))
		if err != nil || resp != ok {
			t.Fatalf("a successful round trip must pass through untouched, got resp=%v err=%v", resp, err)
		}
	})
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestNewEgressDiagnosticTransport_NilPassthrough keeps callers able to wrap
// unconditionally without a nil check at each site.
func TestNewEgressDiagnosticTransport_NilPassthrough(t *testing.T) {
	if got := NewEgressDiagnosticTransport(nil); got != nil {
		t.Fatalf("NewEgressDiagnosticTransport(nil) = %v, want nil", got)
	}
}
