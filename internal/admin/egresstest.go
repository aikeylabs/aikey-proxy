// egresstest.go — POST /admin/egress-test: exit-IP identity probe for a node
// upstream spec (节点管理 Nodes page test button; update 20260718-集群节点出口
// 代理管理, R1 方案甲).
//
// Relationship to POST /admin/upstream-proxy/probe (kept, unchanged): probe
// answers "can this candidate URL carry a request to the AI provider" (status
// only); THIS endpoint answers "which exit IP does a spec leave from, via which
// engine" — the anti-ban question the Nodes page asks. Same TestDial code the
// real forwarding egress uses (pkg/egress single truth), so a green result here
// is the dial path that serves traffic, not a lookalike.
//
// The master console reaches this over the cluster's INTERNAL network
// (node_addr:27200); the public face never sees it — worker nginx denies
// /admin/* (P3 方案C), which covers this route automatically.
package admin

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/pkg/egress"
)

// egressTestTimeout bounds a single probe (dial + one echo GET). Same value as
// the master console's per-account test endpoint.
const egressTestTimeout = 15 * time.Second

// egressTestEchoURL is the "what's my IP" endpoint the probe dials THROUGH the
// spec to learn the exit IP. AIKEY_EGRESS_TEST_ECHO overrides it — same knob
// name as the master console test endpoint, so an air-gapped deployment points
// both at one internal echo.
func egressTestEchoURL() string {
	if v := strings.TrimSpace(os.Getenv("AIKEY_EGRESS_TEST_ECHO")); v != "" {
		return v
	}
	return "https://api.ipify.org"
}

// egressTestResult mirrors the master per-account test endpoint's wire shape so
// the console renders both with one component.
type egressTestResult struct {
	Ok        bool   `json:"ok"`
	ExitIP    string `json:"exit_ip,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Engine    string `json:"engine,omitempty"`
	Body      string `json:"body,omitempty"`
	Error     string `json:"error,omitempty"`
}

// EgressTest serves POST /admin/egress-test {spec}. An empty spec tests the
// node's CURRENT explicit upstream (the page's "test what's applied" action);
// no spec anywhere → 400 (probing the implicit env/system chain is `aikey env`'s
// job, not this endpoint's). A probe that runs but fails is a VALID result:
// 200 + ok=false + the actionable reason — not a 5xx.
func (h *Handler) EgressTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Spec string `json:"spec"`
	}
	// 64 KiB: multi-node mihomo fragments are bigger than the 4 KiB URL bodies
	// the other upstream-proxy endpoints cap at.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	spec := strings.TrimSpace(req.Spec)
	if spec == "" && h.GetUpstreamProxyFn != nil {
		spec = strings.TrimSpace(h.GetUpstreamProxyFn())
	}
	if spec == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "nothing to test: pass a spec or configure an explicit upstream first (env/system-proxy layers are shown by `aikey env`)"})
		return
	}
	// Authoritative node-side shape gate — on a build without the mihomo engine
	// a fragment is refused here with the "needs the enterprise offline package"
	// guidance (capability matrix), instead of a confusing dial failure.
	if err := config.ValidateUpstreamProxyURL(spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Engine specs (socks5 single/chain, config fragment) go through the same
	// registry the forwarding transport uses; a plain http(s) forward proxy is
	// not an engine spec (the node routes it via http.ProxyURL) so it gets the
	// equivalent transport probe.
	if strings.Contains(spec, ",") || egress.IsFragment(spec) || strings.HasPrefix(spec, "socks5://") {
		res, err := egress.TestDial(r.Context(), spec, egressTestEchoURL(), egressTestTimeout)
		if err != nil {
			writeJSON(w, http.StatusOK, egressTestResult{Ok: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, egressTestResult{
			Ok: true, ExitIP: res.ExitIP, LatencyMs: res.LatencyMs, Engine: res.Engine, Body: res.Body,
		})
		return
	}
	res := testThroughURLProxy(r, spec)
	writeJSON(w, http.StatusOK, res)
}

// testThroughURLProxy probes a single http/https forward-proxy URL the same way
// the node transport uses it (http.ProxyURL), GETting the echo through it.
func testThroughURLProxy(r *http.Request, rawURL string) egressTestResult {
	u, err := url.Parse(rawURL)
	if err != nil { // unreachable after ValidateUpstreamProxyURL; belt-and-braces
		return egressTestResult{Ok: false, Error: "not a valid URL: " + err.Error()}
	}
	transport := &http.Transport{
		Proxy:               http.ProxyURL(u),
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: egressTestTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: egressTestTimeout}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, egressTestEchoURL(), nil)
	if err != nil {
		return egressTestResult{Ok: false, Error: "bad echo url: " + err.Error()}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return egressTestResult{Ok: false, Error: "egress unreachable via http-proxy: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	body := readTrimmed(resp.Body, 4096)
	res := egressTestResult{
		Ok: true, LatencyMs: time.Since(start).Milliseconds(), Engine: "http-proxy", Body: body,
	}
	if net.ParseIP(body) != nil {
		res.ExitIP = body
	}
	return res
}

func readTrimmed(r io.Reader, limit int64) string {
	b, _ := io.ReadAll(io.LimitReader(r, limit))
	return strings.TrimSpace(string(b))
}
