package proxy

// filter_restore_test.go — B3 (2026-08-08) proxy half of the CN_ADDRESS
// restorable-mask chain: per-request renumbering (请求侧) + non-streaming
// placeholder restoration (响应侧). The detector half is fenced in
// ai-compliance-detector cmd/detector/address_mask_meta_test.go; the SSE
// streaming half in sse_restore_test.go.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

const (
	tAddrToken  = "[地址(已隐藏)]"
	tAddrPrefix = "[地址#"
	tAddrSuffix = "(已隐藏)]"
)

func addrRestorable(head string, addrs ...string) apphook.RestorableMask {
	r := apphook.RestorableMask{Token: tAddrToken, NumberedPrefix: tAddrPrefix, NumberedSuffix: tAddrSuffix}
	off := 0
	for _, a := range addrs {
		i := strings.Index(head[off:], a)
		if i < 0 {
			panic("test addr not in head")
		}
		start := off + i
		r.Spans = append(r.Spans, [2]int{start, start + len(a)})
		off = start + len(a)
	}
	return r
}

func maskAddrs(head string, addrs ...string) string {
	out := head
	for _, a := range addrs {
		out = strings.Replace(out, a, tAddrToken, 1)
	}
	return out
}

// --- renumberRestorables (请求侧) --------------------------------------------

func TestRenumberRestorables_SequentialLabelsAndMapping(t *testing.T) {
	a1, a2 := "北京市朝阳区建国路88号", "上海市浦东新区世纪大道100号"
	head := "收货：" + a1 + "；备用：" + a2
	masked := maskAddrs(head, a1, a2)
	st := newMaskRestore()
	got := renumberRestorables(head, masked, []apphook.RestorableMask{addrRestorable(head, a1, a2)}, st, discardLogger())

	want := "收货：[地址#1(已隐藏)]；备用：[地址#2(已隐藏)]"
	if got != want {
		t.Fatalf("renumbered = %q, want %q", got, want)
	}
	if st.entries["[地址#1(已隐藏)]"] != a1 || st.entries["[地址#2(已隐藏)]"] != a2 {
		t.Fatalf("mapping wrong: %v", st.entries)
	}
}

// Numbering is REQUEST-scoped and continues across pieces (同请求内按出现顺序编号).
func TestRenumberRestorables_ContinuesAcrossPieces(t *testing.T) {
	a1, a2 := "广州市天河区体育西路1号", "深圳市南山区科技园2号"
	st := newMaskRestore()
	h1 := "第一条：" + a1
	h2 := "第二条：" + a2
	out1 := renumberRestorables(h1, maskAddrs(h1, a1), []apphook.RestorableMask{addrRestorable(h1, a1)}, st, discardLogger())
	out2 := renumberRestorables(h2, maskAddrs(h2, a2), []apphook.RestorableMask{addrRestorable(h2, a2)}, st, discardLogger())
	if !strings.Contains(out1, "[地址#1(已隐藏)]") || !strings.Contains(out2, "[地址#2(已隐藏)]") {
		t.Fatalf("cross-piece numbering broken: %q / %q", out1, out2)
	}
	if st.entries["[地址#2(已隐藏)]"] != a2 {
		t.Fatalf("mapping wrong: %v", st.entries)
	}
}

// User-typed literal token → occurrence/span count mismatch → alignment is
// ambiguous → keep the (safe) numberless mask, no mapping entries.
func TestRenumberRestorables_CountMismatchKeepsNumberlessMask(t *testing.T) {
	a1 := "杭州市西湖区文一路3号"
	head := "我打的字面量 " + tAddrToken + " 和真实地址 " + a1
	masked := strings.Replace(head, a1, tAddrToken, 1) // now TWO token occurrences, ONE span
	st := newMaskRestore()
	got := renumberRestorables(head, masked, []apphook.RestorableMask{addrRestorable(head, a1)}, st, discardLogger())
	if got != masked {
		t.Fatalf("mismatch case must keep masked text unchanged: %q", got)
	}
	if len(st.entries) != 0 {
		t.Fatalf("mismatch case must record no mapping: %v", st.entries)
	}
}

func TestRenumberRestorables_InvalidSpansSkipped(t *testing.T) {
	head := "内容"
	masked := tAddrToken
	st := newMaskRestore()
	bad := apphook.RestorableMask{Token: tAddrToken, NumberedPrefix: tAddrPrefix, NumberedSuffix: tAddrSuffix,
		Spans: [][2]int{{0, 999}}} // out of range
	if got := renumberRestorables(head, masked, []apphook.RestorableMask{bad}, st, discardLogger()); got != masked || len(st.entries) != 0 {
		t.Fatalf("invalid spans must be skipped: got %q entries %v", got, st.entries)
	}
}

// --- applyInboundFilter integration (stub detector, real dispatch path) ------

// stubRestorableHook mimics the v4 detector: mask verdict + numberless token +
// span metadata, derived per piece from the payload it receives.
type stubRestorableHook struct {
	addrs  []string
	called int
}

func (h *stubRestorableHook) Name() string { return "stub-restorable" }
func (h *stubRestorableHook) Detect(_ context.Context, req *apphook.Request) *apphook.Response {
	h.called++
	head := string(req.Payload)
	var present []string
	for _, a := range h.addrs {
		if strings.Contains(head, a) {
			present = append(present, a)
		}
	}
	if len(present) == 0 {
		return &apphook.Response{Action: apphook.ActionAllow}
	}
	return &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte(maskAddrs(head, present...)),
		Restorables:    []apphook.RestorableMask{addrRestorable(head, present...)},
	}
}
func (h *stubRestorableHook) Status() *apphook.Status { return &apphook.Status{Healthy: true} }

func TestApplyInboundFilter_RestorableMaskEndToEnd(t *testing.T) {
	a1, a2 := "北京市朝阳区建国路88号", "上海市浦东新区世纪大道100号"
	hook := &stubRestorableHook{addrs: []string{a1, a2}}
	p := &Proxy{filterHook: hook}
	body := `{"model":"m","messages":[{"role":"user","content":"送到` + a1 + `，发票寄` + a2 + `"}]}`
	r := newReq(body)
	w := httptest.NewRecorder()

	if proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", discardLogger()); !proceed {
		t.Fatal("expected proceed")
	}
	forwarded := readReqBody(t, r)
	// 请求侧: numbered labels forwarded, raw addresses gone.
	if strings.Contains(forwarded, a1) || strings.Contains(forwarded, a2) {
		t.Fatalf("raw address leaked to upstream body: %s", forwarded)
	}
	if !strings.Contains(forwarded, "[地址#1(已隐藏)]") || !strings.Contains(forwarded, "[地址#2(已隐藏)]") {
		t.Fatalf("numbered labels missing: %s", forwarded)
	}
	// Mapping hangs on the request context for the response leg.
	st := maskRestoreFromContext(r.Context())
	if st == nil {
		t.Fatal("restore state missing from request context")
	}
	if st.entries["[地址#1(已隐藏)]"] != a1 || st.entries["[地址#2(已隐藏)]"] != a2 {
		t.Fatalf("context mapping wrong: %v", st.entries)
	}

	// 响应侧 (non-streaming): the LLM echoes both labels → restored to originals.
	respBody := []byte(`{"id":"msg_1","content":[{"type":"text","text":"好的，会送到[地址#1(已隐藏)]，发票寄[地址#2(已隐藏)]。"}],"usage":{"input_tokens":10,"output_tokens":20}}`)
	restored := restoreMaskedResponseBody(r.Context(), respBody, discardLogger())
	s := string(restored)
	if !strings.Contains(s, a1) || !strings.Contains(s, a2) || strings.Contains(s, "[地址#") {
		t.Fatalf("response restore failed: %s", s)
	}
	var parsed map[string]any
	if err := json.Unmarshal(restored, &parsed); err != nil {
		t.Fatalf("restored body is not valid JSON: %v", err)
	}
	if n, _ := parsed["usage"].(map[string]any)["input_tokens"].(float64); n != 10 {
		t.Fatalf("non-string fields must survive restore, usage=%v", parsed["usage"])
	}
}

// Cache replay must rebuild the mapping WITHOUT a second detector call: the
// cached verdict stores offsets only; originals are re-sliced from the
// hash-identical head (缓存不存原文不变量).
func TestApplyInboundFilter_CacheReplayRebuildsMapping(t *testing.T) {
	a1 := "南京市玄武区中山路9号"
	hook := &stubRestorableHook{addrs: []string{a1}}
	p := &Proxy{filterHook: hook, filterCache: newSessionMaskCache(4, 8, time.Hour)}
	body := `{"model":"m","messages":[{"role":"user","content":"合同请寄` + a1 + `"}]}`

	r1 := newReq(body)
	if !p.applyInboundFilter(httptest.NewRecorder(), r1, "m", "personal", "", "", "", "", discardLogger()) {
		t.Fatal("req1: expected proceed")
	}
	if hook.called != 1 {
		t.Fatalf("req1 detector calls = %d, want 1", hook.called)
	}
	r2 := newReq(body)
	if !p.applyInboundFilter(httptest.NewRecorder(), r2, "m", "personal", "", "", "", "", discardLogger()) {
		t.Fatal("req2: expected proceed")
	}
	if hook.called != 1 {
		t.Fatalf("req2 must be served from cache; detector calls = %d", hook.called)
	}
	if got := readReqBody(t, r2); !strings.Contains(got, "[地址#1(已隐藏)]") || strings.Contains(got, a1) {
		t.Fatalf("cache-replayed request not renumbered: %s", got)
	}
	st := maskRestoreFromContext(r2.Context())
	if st == nil || st.entries["[地址#1(已隐藏)]"] != a1 {
		t.Fatalf("cache replay lost the mapping: %+v", st)
	}
}

// --- restoreMaskedResponseBody edge cases ------------------------------------

func restoreStateCtx(labels map[string]string) context.Context {
	st := newMaskRestore()
	for k, v := range labels {
		st.add(k, v)
	}
	return context.WithValue(context.Background(), ctxKeyMaskRestore, st)
}

// A provider that \u-escapes CJK must still restore — decoding the JSON tree
// (not raw byte replace) is what makes escaped placeholders reachable.
func TestRestoreMaskedResponseBody_UnicodeEscapedPlaceholder(t *testing.T) {
	ctx := restoreStateCtx(map[string]string{"[地址#1(已隐藏)]": "北京市海淀区中关村1号"})
	body := []byte(`{"choices":[{"message":{"content":"地址是[地址#1(已隐藏)]"}}]}`)
	got := string(restoreMaskedResponseBody(ctx, body, discardLogger()))
	if !strings.Contains(got, "北京市海淀区中关村1号") {
		t.Fatalf("escaped placeholder not restored: %s", got)
	}
}

// 无占位符时零改动直通 (non-streaming): the upstream bytes are forwarded verbatim.
func TestRestoreMaskedResponseBody_NoPlaceholderPassthrough(t *testing.T) {
	ctx := restoreStateCtx(map[string]string{"[地址#1(已隐藏)]": "x"})
	body := []byte(`{"content":[{"type":"text","text":"plain answer"}],"n":1.25}`)
	if got := restoreMaskedResponseBody(ctx, body, discardLogger()); string(got) != string(body) {
		t.Fatalf("placeholder-free body must pass through byte-identical:\n got %s\nwant %s", got, body)
	}
}

func TestRestoreMaskedResponseBody_NonJSONFailOpen(t *testing.T) {
	ctx := restoreStateCtx(map[string]string{"[地址#1(已隐藏)]": "x"})
	body := []byte("not json at all")
	if got := restoreMaskedResponseBody(ctx, body, discardLogger()); string(got) != string(body) {
		t.Fatalf("non-JSON body must be untouched: %s", got)
	}
}

// Number fidelity: large ints / high-precision decimals must survive the
// decode-walk-encode round trip (json.Number, not float64).
func TestRestoreMaskedResponseBody_NumberFidelity(t *testing.T) {
	ctx := restoreStateCtx(map[string]string{"[地址#1(已隐藏)]": "天津市和平区4号"})
	body := []byte(`{"big":9007199254740993,"text":"[地址#1(已隐藏)]"}`)
	got := string(restoreMaskedResponseBody(ctx, body, discardLogger()))
	if !strings.Contains(got, "9007199254740993") {
		t.Fatalf("int64 precision lost: %s", got)
	}
	if !strings.Contains(got, "天津市和平区4号") {
		t.Fatalf("placeholder not restored: %s", got)
	}
}
