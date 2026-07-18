package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
)

// callEgressTest posts a spec (with the echo env pinned to a local server) and
// returns status + decoded body.
func callEgressTest(t *testing.T, h *Handler, echoURL, body string) (int, map[string]any) {
	t.Helper()
	t.Setenv("AIKEY_EGRESS_TEST_ECHO", echoURL)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/egress-test", strings.NewReader(body))
	h.EgressTest(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("non-JSON response %q", w.Body.String())
		}
	}
	return w.Code, out
}

func newEchoServer(t *testing.T, ip string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, ip)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The endpoint dials the echo THROUGH a real socks5 (the same rig the TestDial
// unit test uses), reporting exit IP + engine — the wire shape the master
// console's Nodes page renders.
func TestEgressTest_DialsThroughSocks5AndReportsExitIP(t *testing.T) {
	echo := newEchoServer(t, "203.0.113.9")
	proxySrv := egresstest.NewSocks5Server(t, "", "")

	code, out := callEgressTest(t, &Handler{}, echo.URL,
		fmt.Sprintf(`{"spec":"socks5://%s"}`, proxySrv.Addr()))
	if code != http.StatusOK {
		t.Fatalf("status = %d body = %v", code, out)
	}
	if out["ok"] != true || out["exit_ip"] != "203.0.113.9" || out["engine"] != "builtin-socks5" {
		t.Fatalf("result = %v", out)
	}
	if n, _ := proxySrv.Stats(); n == 0 {
		t.Fatal("socks5 was not traversed — the probe did not use the spec")
	}
}

// Empty spec falls back to the node's CURRENT explicit upstream ("test what's
// applied"); with neither, 400 with actionable guidance.
func TestEgressTest_EmptySpecUsesCurrentUpstream(t *testing.T) {
	echo := newEchoServer(t, "198.51.100.4")
	proxySrv := egresstest.NewSocks5Server(t, "", "")

	h := &Handler{GetUpstreamProxyFn: func() string { return "socks5://" + proxySrv.Addr() }}
	code, out := callEgressTest(t, h, echo.URL, `{"spec":""}`)
	if code != http.StatusOK || out["ok"] != true || out["exit_ip"] != "198.51.100.4" {
		t.Fatalf("current-upstream probe: code=%d out=%v", code, out)
	}

	code, out = callEgressTest(t, &Handler{}, echo.URL, `{"spec":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("no spec anywhere: code=%d out=%v (want 400)", code, out)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "aikey env") {
		t.Fatalf("400 lacks guidance: %v", out)
	}
}

// A dead proxy is a VALID diagnostic result: 200 + ok=false + reason (能红:
// removing the failure branch would return ok=true or a 5xx here).
func TestEgressTest_DeadProxyReportsOkFalse(t *testing.T) {
	echo := newEchoServer(t, "203.0.113.9")
	code, out := callEgressTest(t, &Handler{}, echo.URL, `{"spec":"socks5://127.0.0.1:1"}`)
	if code != http.StatusOK {
		t.Fatalf("dead proxy: status = %d (a failed probe is a result, not an HTTP error)", code)
	}
	if out["ok"] != false {
		t.Fatalf("dead proxy: %v", out)
	}
	if msg, _ := out["error"].(string); msg == "" {
		t.Fatal("dead proxy: empty error — admin cannot debug")
	}
}

// Shape gate: garbage → 400; on this GPL-free OSS build a mihomo fragment is
// refused with the enterprise-package guidance (capability matrix: fragments
// need the enterprise build; this test pins the actionable message).
func TestEgressTest_InvalidAndFragmentSpecs400(t *testing.T) {
	echo := newEchoServer(t, "203.0.113.9")

	code, out := callEgressTest(t, &Handler{}, echo.URL, `{"spec":"ftp://h:21"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("bad scheme: code=%d out=%v", code, out)
	}

	code, out = callEgressTest(t, &Handler{}, echo.URL, `{"spec":"{\"proxies\":[{\"type\":\"ss\"}]}"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("fragment on OSS build: code=%d out=%v (want 400 with guidance)", code, out)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "enterprise offline package") {
		t.Fatalf("fragment 400 lacks enterprise guidance: %v", out)
	}

	if code, _ := callEgressTest(t, &Handler{}, echo.URL, `{`); code != http.StatusBadRequest {
		t.Fatal("malformed body must 400")
	}
}

// A plain http forward proxy is probed the way the node transport uses it
// (http.ProxyURL) — through a real local forward proxy, not a lookalike.
func TestEgressTest_HTTPForwardProxyPath(t *testing.T) {
	echo := newEchoServer(t, "192.0.2.55")

	var traversed atomic.Int32
	fwd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A plain-HTTP forward proxy receives the absolute-URI request; relay it.
		traversed.Add(1)
		resp, err := http.Get(r.URL.String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(fwd.Close)

	code, out := callEgressTest(t, &Handler{}, echo.URL,
		fmt.Sprintf(`{"spec":"%s"}`, fwd.URL))
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("http-proxy probe: code=%d out=%v", code, out)
	}
	if out["exit_ip"] != "192.0.2.55" || out["engine"] != "http-proxy" {
		t.Fatalf("http-proxy result = %v", out)
	}
	if traversed.Load() == 0 {
		t.Fatal("forward proxy was not traversed")
	}
}
