package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpstreamProxyGet(t *testing.T) {
	h := &Handler{GetUpstreamProxyFn: func() string { return "http://127.0.0.1:7890" }}
	w := httptest.NewRecorder()
	h.UpstreamProxyGet(w, httptest.NewRequest(http.MethodGet, "/admin/upstream-proxy", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body upstreamProxyBody
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.URL != "http://127.0.0.1:7890" {
		t.Fatalf("url = %q, want http://127.0.0.1:7890", body.URL)
	}
}

func TestUpstreamProxyGet_NotWired(t *testing.T) {
	h := &Handler{} // GetUpstreamProxyFn nil
	w := httptest.NewRecorder()
	h.UpstreamProxyGet(w, httptest.NewRequest(http.MethodGet, "/admin/upstream-proxy", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when not wired", w.Code)
	}
}

func TestUpstreamProxySet_ValidCallsHotSwap(t *testing.T) {
	var got string
	called := 0
	h := &Handler{SetUpstreamProxyFn: func(url string) error { called++; got = url; return nil }}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/admin/upstream-proxy", strings.NewReader(`{"url":"socks5://127.0.0.1:7891"}`))
	h.UpstreamProxySet(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if called != 1 || got != "socks5://127.0.0.1:7891" {
		t.Fatalf("SetUpstreamProxyFn called=%d url=%q", called, got)
	}
}

func TestUpstreamProxySet_EmptyClears(t *testing.T) {
	called := 0
	h := &Handler{SetUpstreamProxyFn: func(string) error { called++; return nil }}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/admin/upstream-proxy", strings.NewReader(`{"url":""}`))
	h.UpstreamProxySet(w, r)
	if w.Code != http.StatusOK || called != 1 {
		t.Fatalf("empty url should be accepted (clear): status=%d called=%d", w.Code, called)
	}
}

func TestUpstreamProxySet_InvalidURLNoHotSwap(t *testing.T) {
	called := 0
	h := &Handler{SetUpstreamProxyFn: func(string) error { called++; return nil }}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/admin/upstream-proxy", strings.NewReader(`{"url":"ftp://nope"}`))
	h.UpstreamProxySet(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for bad scheme", w.Code)
	}
	if called != 0 {
		t.Fatalf("invalid URL must NOT reach the hot-swap (called=%d)", called)
	}
}

func TestUpstreamProxySet_NotWired(t *testing.T) {
	h := &Handler{} // SetUpstreamProxyFn nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/admin/upstream-proxy", strings.NewReader(`{"url":"http://127.0.0.1:7890"}`))
	h.UpstreamProxySet(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when not wired", w.Code)
	}
}

func TestUpstreamProxyProbe_Reachable(t *testing.T) {
	var got string
	h := &Handler{ProbeUpstreamProxyFn: func(url string) (int, int64, error) { got = url; return 401, 42, nil }}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/upstream-proxy/probe", strings.NewReader(`{"url":"http://127.0.0.1:7890"}`))
	h.UpstreamProxyProbe(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var res upstreamProbeResult
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if !res.Ok || res.Status != 401 || res.ElapsedMs != 42 {
		t.Fatalf("probe result = %+v, want ok/401/42 (any HTTP status = reachable)", res)
	}
	if got != "http://127.0.0.1:7890" {
		t.Fatalf("probe url = %q", got)
	}
}

func TestUpstreamProxyProbe_Unreachable(t *testing.T) {
	h := &Handler{ProbeUpstreamProxyFn: func(string) (int, int64, error) {
		return 0, 10, errors.New("dial tcp: connect: connection refused")
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/upstream-proxy/probe", strings.NewReader(`{"url":"http://127.0.0.1:9999"}`))
	h.UpstreamProxyProbe(w, r)
	if w.Code != http.StatusOK { // a failed probe is a 200 with ok=false, not an HTTP error
		t.Fatalf("status = %d, want 200 (probe ran, target unreachable)", w.Code)
	}
	var res upstreamProbeResult
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.Ok || res.Error == "" {
		t.Fatalf("probe result = %+v, want ok=false with error", res)
	}
}

func TestUpstreamProxyProbe_InvalidURLNoCall(t *testing.T) {
	called := 0
	h := &Handler{ProbeUpstreamProxyFn: func(string) (int, int64, error) { called++; return 200, 1, nil }}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/upstream-proxy/probe", strings.NewReader(`{"url":"ftp://nope"}`))
	h.UpstreamProxyProbe(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for bad scheme", w.Code)
	}
	if called != 0 {
		t.Fatalf("invalid URL must NOT reach the probe (called=%d)", called)
	}
}

func TestUpstreamProxyProbe_NotWired(t *testing.T) {
	h := &Handler{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/upstream-proxy/probe", strings.NewReader(`{"url":"http://127.0.0.1:7890"}`))
	h.UpstreamProxyProbe(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when not wired", w.Code)
	}
}
