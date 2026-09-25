package admin

// Fence: a single upstream proxy URL that does not parse is refused WITHOUT its
// credentials, at every entry a user reaches:
//
//   - POST /admin/upstream-proxy/probe (settings page "Test connectivity");
//   - PUT  /admin/upstream-proxy       (settings page save);
//   - POST /admin/egress-test          (node egress test);
//   - POST /admin/probe/ping in its fallback mode (no live transport wired:
//     the configured URL goes to httpHeadViaProxy, and classifyNetError echoes
//     any error it does not recognize).
//
// The first three stop at config.ValidateUpstreamProxyURL before any transport
// is built, so fixing buildTransportStrict alone (task 2.4, first segment) did
// not reach them (review-2.4 I-1: 9/9 probes echoed the credentials). That is
// why this fence goes in through the handlers, not the validator.
//
// spec: R-master-central-login-6.S4 秘密不外泄（出口凭据部分）
// DEC-master-central-login-15; Ruling-32, Ruling-34
// bugfix: workflow/CI/bugfix/2026-09-24-egress-credentials-echoed-in-errors.md
//
// 能红: in internal/config/upstream_proxy.go wrap url.Parse's error again
// (`fmt.Errorf("not a valid URL: %w", err)`), or in handlers.go
// httpHeadViaProxy return `fmt.Errorf("invalid proxy URL: %w", err)`, and the
// markers appear.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/pkg/egress"
)

const (
	echoUser = "u-MARK7"
	echoPass = "p-MARK7"
	echoCred = echoUser + ":" + echoPass + "@"
)

// unparseableSingleURLs are single URLs url.Parse rejects, each with the
// credentials in it; want is what the error must still name.
var unparseableSingleURLs = []struct{ name, url, want string }{
	// D2 甲 (2026-09-24): a port that is not a number shows "(unparseable)" and
	// the shared hint only, never host:port.
	{"http, port not a number", "http://" + echoCred + "proxy.example.test:abc", "(unparseable)"},
	{"socks5, port not a number", "socks5://" + echoCred + "proxy.example.test:abc", "(unparseable)"},
	// D2 甲 (review-2.4 I-2): written backwards, the part after '@' is the user
	// name and password.
	{"http, written backwards", "http://proxy.example.test:3128@" + echoUser + ":" + echoPass, "(unparseable)"},
	// An unescaped '/' in the password ends Go's authority early, so even the
	// parser's own reason quotes the password (`invalid port ":p-MARK7"`).
	{"http, slash in the password", "http://" + echoUser + ":" + echoPass + "/x@proxy.example.test:3128", "http://proxy.example.test:3128"},
	// D3 甲 (review-2.4 I-3): with digits before the '/', it parses cleanly
	// into the wrong host ("u-MARK7:12") and used to be accepted. The shared
	// reason it now carries tells the user to write '/' as %2F.
	{"http, unescaped slash with digits before it", "http://" + echoUser + ":12/" + echoPass + "@proxy.example.test:3128", "http://proxy.example.test:3128"},
	{"socks5, unescaped slash with digits before it", "socks5://" + echoUser + ":12/" + echoPass + "@proxy.example.test:1080", "socks5://proxy.example.test:1080"},
}

func assertNoEchoedCredentials(t *testing.T, where, got string) {
	t.Helper()
	for _, mark := range []string{echoUser, echoPass} {
		if strings.Contains(got, mark) {
			t.Errorf("%s echoed the proxy credential %q: %s", where, mark, got)
		}
	}
}

// errorField decodes the handler's JSON body and returns its "error" field.
func errorField(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("non-JSON response %q", body)
	}
	return out.Error
}

func TestUpstreamProxyEntries_UnparseableURLNeverEchoesProxyCredentials(t *testing.T) {
	hooked := 0
	h := &Handler{
		// Validation must refuse the URL before either hook runs.
		SetUpstreamProxyFn:   func(string) error { hooked++; return nil },
		ProbeUpstreamProxyFn: func(string) (int, int64, error) { hooked++; return 200, 1, nil },
	}
	for _, entry := range []struct {
		name, method, path, field string
		serve                     func(http.ResponseWriter, *http.Request)
	}{
		{"settings Test connectivity", http.MethodPost, "/admin/upstream-proxy/probe", "url", h.UpstreamProxyProbe},
		{"settings save", http.MethodPut, "/admin/upstream-proxy", "url", h.UpstreamProxySet},
		{"node egress test", http.MethodPost, "/admin/egress-test", "spec", h.EgressTest},
	} {
		for _, tc := range unparseableSingleURLs {
			t.Run(entry.name+"/"+tc.name, func(t *testing.T) {
				// The egress test would dial this echo only for a spec that
				// passes validation; none here does.
				t.Setenv("AIKEY_EGRESS_TEST_ECHO", "http://echo.invalid/")
				before := hooked
				body := `{"` + entry.field + `":` + strconv.Quote(tc.url) + `}`
				w := httptest.NewRecorder()
				entry.serve(w, httptest.NewRequest(entry.method, entry.path, strings.NewReader(body)))

				if w.Code != http.StatusBadRequest {
					t.Fatalf("%s %s = %d, want 400: %s", entry.method, entry.path, w.Code, w.Body.String())
				}
				if hooked != before {
					t.Fatal("the hot-swap or probe hook ran for a URL that does not parse")
				}
				assertNoEchoedCredentials(t, entry.name, w.Body.String())
				got := errorField(t, w.Body.Bytes())
				if !strings.Contains(got, tc.want) {
					t.Errorf("error %q does not name %q, so the user cannot see which address is wrong", got, tc.want)
				}
				// Ruling-35: the one shared reason, not a local copy of it.
				if !strings.Contains(got, egress.ErrUnparseableProxyURL.Error()) {
					t.Errorf("error %q does not carry egress.ErrUnparseableProxyURL", got)
				}
			})
		}
	}
}

// The validator behind the three entries above WRAPS the shared reason; a
// copy of the same sentence would pass the text checks there, not this one.
func TestValidateUpstreamProxyURL_WrapsTheSharedReason(t *testing.T) {
	for _, tc := range unparseableSingleURLs {
		if err := config.ValidateUpstreamProxyURL(tc.url); !errors.Is(err, egress.ErrUnparseableProxyURL) {
			t.Errorf("ValidateUpstreamProxyURL(%s) = %v, want it to wrap egress.ErrUnparseableProxyURL", tc.want, err)
		}
	}
}

// testThroughURLProxy's parse guard (egresstest.go) is unreachable from the
// handler — the validator answers first — so a handler-level fence cannot see
// it; it is called directly here (Ruling-32).
func TestThroughURLProxy_UnparseableURLNeverEchoesCredentials(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/egress-test", nil)
	for _, tc := range unparseableSingleURLs {
		res := testThroughURLProxy(r, tc.url)
		if res.Ok {
			t.Fatalf("%s: a URL that does not parse was reported ok", tc.name)
		}
		assertNoEchoedCredentials(t, "testThroughURLProxy", res.Error)
		if !strings.Contains(res.Error, tc.want) || !strings.Contains(res.Error, egress.ErrUnparseableProxyURL.Error()) {
			t.Errorf("%s: error %q should name %q and carry the shared reason", tc.name, res.Error, tc.want)
		}
	}
}

// /admin/probe/ping without a live transport falls back to the configured
// URL; for a single URL that is httpHeadViaProxy, whose parse error went to
// the caller through classifyNetError's echo of unknown errors.
func TestProbePingFallback_UnparseableProxyURLNeverEchoesCredentials(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the probe reached the target through a URL that does not parse")
	}))
	defer target.Close()
	for _, tc := range unparseableSingleURLs {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandlerForTest(&config.Config{UpstreamProxy: config.UpstreamProxyConfig{URL: tc.url}})
			rr := postProbePing(t, h, ProbePingRequest{BaseURL: target.URL})
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
			}
			assertNoEchoedCredentials(t, "probe ping", rr.Body.String())
			var resp ProbePingResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v; body = %s", err, rr.Body.String())
			}
			if resp.OK {
				t.Fatal("probe ping reported ok through a URL that does not parse")
			}
			if !strings.Contains(resp.Error, tc.want) || !strings.Contains(resp.Error, egress.ErrUnparseableProxyURL.Error()) {
				t.Errorf("error %q should name %q and carry the shared reason", resp.Error, tc.want)
			}
		})
	}
}
