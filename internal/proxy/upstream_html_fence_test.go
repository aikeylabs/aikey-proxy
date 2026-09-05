package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Fence for bugfix 2026-09-05-add-key-dialog-draft-probe-sends-unresolvable-
// source-ref.md (part C): a 2xx upstream response whose body is a web page
// must NOT be relayed as if it were an API answer.
//
// Reproduction on winpc2 (2026-09-04): a personal key saved with
// base_url=https://pingtoken.ai (site, no /v1). The gateway's SPA catch-all
// answered `200 text/html` to /v1/models and /v1/responses; the proxy relayed
// the page, so `aikey test` showed green while Codex failed with "stream
// closed before response.completed". The proxy is the ONE place every
// client passes through, so it is where the page is turned into a
// structured 502 that names the likely cause.
func TestServeRoute_Upstream2xxHTMLBecomesStructured502(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ct        string
		wantHTML  bool // true → guard fires
		streaming bool
	}{
		{"spa page, non-streaming", "text/html; charset=utf-8", true, false},
		{"spa page, streaming request", "text/html", true, true},
		{"json answer untouched", "application/json", false, false},
		{"sse answer untouched", "text/event-stream", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.ct)
				w.WriteHeader(http.StatusOK)
				switch {
				case strings.HasPrefix(tc.ct, "text/html"):
					_, _ = w.Write([]byte("<!doctype html><html><head><title>gateway</title></head><body>app</body></html>"))
				case strings.HasPrefix(tc.ct, "text/event-stream"):
					_, _ = w.Write([]byte("data: {\"id\":\"x\",\"choices\":[]}\n\ndata: [DONE]\n\n"))
				default:
					_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o"}]}`))
				}
			}))
			defer upstream.Close()

			av := &mockActiveVault{
				personalAlias:   "my-openai",
				personalText:    "sk-from-vault",
				personalProv:    "openai",
				personalBaseURL: upstream.URL,
			}
			p := setupTestProxyWithActive(t, av)

			var req *http.Request
			if tc.streaming {
				req = httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions",
					strings.NewReader(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(http.MethodGet, "/openai/v1/models", nil)
			}
			req.Header.Set("Authorization", "Bearer aikey_probe_my-openai")
			w := httptest.NewRecorder()
			p.Handle(w, req)

			if !tc.wantHTML {
				if w.Code != http.StatusOK {
					t.Fatalf("non-HTML 2xx must pass through unchanged, got %d: %s", w.Code, w.Body.String())
				}
				if strings.Contains(w.Body.String(), errCodeUpstreamReturnedHTML) {
					t.Fatalf("guard fired on a %s body", tc.ct)
				}
				return
			}
			if w.Code != http.StatusBadGateway {
				t.Fatalf("HTML 2xx relayed as-is: status %d (want 502) body=%q", w.Code, w.Body.String())
			}
			var env struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
				t.Fatalf("502 body is not the structured envelope: %v — %q", err, w.Body.String())
			}
			if env.Error.Code != errCodeUpstreamReturnedHTML {
				t.Errorf("error.code = %q, want %q", env.Error.Code, errCodeUpstreamReturnedHTML)
			}
			if !strings.Contains(env.Error.Message, "/v1") {
				t.Errorf("message must name the likely fix (/v1 suffix); got %q", env.Error.Message)
			}
			if strings.Contains(w.Body.String(), "<html") {
				t.Errorf("HTML leaked into the client response")
			}
		})
	}
}

func TestUpstreamAnsweredHTML_OnlyOn2xxTextHTML(t *testing.T) {
	mk := func(status int, ct string) *http.Response {
		h := http.Header{}
		if ct != "" {
			h.Set("Content-Type", ct)
		}
		return &http.Response{StatusCode: status, Header: h}
	}
	cases := []struct {
		status int
		ct     string
		want   bool
	}{
		{200, "text/html", true},
		{200, "TEXT/HTML; charset=utf-8", true},
		{201, "text/html", true},
		{200, "application/json", false},
		{200, "text/event-stream", false},
		{200, "", false},
		{404, "text/html", false}, // error branch handles non-2xx already
		{502, "text/html", false},
	}
	for _, c := range cases {
		if got := upstreamAnsweredHTML(mk(c.status, c.ct)); got != c.want {
			t.Errorf("status=%d ct=%q: got %v want %v", c.status, c.ct, got, c.want)
		}
	}
	if upstreamAnsweredHTML(nil) {
		t.Error("nil response must not trigger")
	}
}
