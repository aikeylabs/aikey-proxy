package proxy

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// TestApplyInboundFilter_LiveDetector wires the REAL ai-compliance-detector
// child binary into applyInboundFilter and proves the full P4 path end-to-end:
//
//	PII prompt → applyInboundFilter → apphook IPC → detector Engine → mask verdict
//	          → rewritten body with the PII redacted.
//
// This is the live closed-loop proof (Phase 3a) with ZERO external cost — the
// LLM upstream is never contacted; we assert on the masked body the proxy WOULD
// forward.
//
// Guarded by env so normal `go test ./...` (and CI) does not require the binary.
// Run it explicitly after building the detector:
//
//	go build -o /tmp/aikey-detector ./cmd/detector   # in ai-compliance-detector
//	AIKEY_TEST_DETECTOR_BINARY=/tmp/aikey-detector \
//	  go test ./internal/proxy -run TestApplyInboundFilter_LiveDetector -v
func TestApplyInboundFilter_LiveDetector(t *testing.T) {
	bin := os.Getenv("AIKEY_TEST_DETECTOR_BINARY")
	if bin == "" {
		t.Skip("set AIKEY_TEST_DETECTOR_BINARY to the built detector binary to run the live closed-loop test")
	}

	hook := apphook.NewChildHook(apphook.ChildHookConfig{
		Name:       "ai-compliance-detector",
		BinaryPath: bin,
		// Generous deadline — real char+token CRF NER on a full prompt needs
		// well above the 1ms apphook default. Too tight → fail-open (no mask),
		// which would make this test silently pass for the wrong reason.
		Timeout:      500 * time.Millisecond,
		ReadyTimeout: 15 * time.Second,
	})
	if err := hook.Start(context.Background()); err != nil {
		t.Fatalf("spawn detector: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = hook.Shutdown(ctx)
		cancel()
	}()

	p := &Proxy{filterHook: hook}

	// Synthetic, obviously-fake PII embedded in an Anthropic-style chat body.
	// Phone matches pii.cn.phone (1[3-9]\d{9}); the 18-digit string matches
	// pii.cn.id_card (\d{17}[\dXx]). Neither is a real person's data.
	const phone = "13800138000"
	const idCard = "11010119900307742X"
	body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":` +
		`"请帮我核对客户信息：手机号 ` + phone + `，身份证号 ` + idCard + ` 是否正确"}]}`

	r := newReq(body)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "personal", "", "", discardLogger())

	// Mask verdict forwards the request (the LLM still answers, just on redacted
	// input). Block would also be acceptable policy, but for PII the baseline
	// masks — so we expect proceed=true. If the detector degraded (binary/IPC
	// issue) it fails open with the body unchanged, which the assertions catch.
	if !proceed {
		t.Fatalf("expected proceed=true (mask forwards); got blocked. status=%d body=%s",
			w.Code, w.Body.String())
	}

	forwarded := readReqBody(t, r)
	if forwarded == body {
		t.Fatalf("body was NOT modified — detector returned Allow (degraded fail-open?). "+
			"Expected PII to be masked.\n got: %s", forwarded)
	}
	if strings.Contains(forwarded, phone) {
		t.Errorf("raw phone %q still present in forwarded body — not masked:\n%s", phone, forwarded)
	}
	if strings.Contains(forwarded, idCard) {
		t.Errorf("raw id card %q still present in forwarded body — not masked:\n%s", idCard, forwarded)
	}
	// Mask must be byte-correct on CJK (bugfix 2026-05-30 CJK mask offset): no
	// multibyte rune sliced (U+FFFD), CJK context around entities intact, and no
	// residual entity tail. Pre-fix this produced 「手机�***PHONE***00」.
	if strings.ContainsRune(forwarded, '�') {
		t.Errorf("masked body contains U+FFFD — multibyte rune sliced:\n%s", forwarded)
	}
	for _, ctx := range []string{"手机号", "身份证号"} {
		if !strings.Contains(forwarded, ctx) {
			t.Errorf("CJK context %q missing — mask corrupted the prefix:\n%s", ctx, forwarded)
		}
	}
	if strings.Contains(forwarded, "742X") {
		t.Errorf("residual id-card tail '742X' leaked — mask span misaligned:\n%s", forwarded)
	}
	t.Logf("LIVE closed loop OK — masked body forwarded:\n%s", forwarded)
}

// TestApplyInboundFilter_LiveDetector_ASCII is the ASCII control for the live
// test: same path, pure-ASCII PII (no multibyte runes). Comparing its masked
// output against the CJK case isolates whether mask misalignment is triggered
// by UTF-8 multibyte offsets. Asserts the same P4 contract (raw PII removed).
func TestApplyInboundFilter_LiveDetector_ASCII(t *testing.T) {
	bin := os.Getenv("AIKEY_TEST_DETECTOR_BINARY")
	if bin == "" {
		t.Skip("set AIKEY_TEST_DETECTOR_BINARY to run the live closed-loop test")
	}

	hook := apphook.NewChildHook(apphook.ChildHookConfig{
		Name:         "ai-compliance-detector",
		BinaryPath:   bin,
		Timeout:      500 * time.Millisecond,
		ReadyTimeout: 15 * time.Second,
	})
	if err := hook.Start(context.Background()); err != nil {
		t.Fatalf("spawn detector: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = hook.Shutdown(ctx)
		cancel()
	}()

	p := &Proxy{filterHook: hook}

	const email = "john.doe.test@example.com"
	body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":` +
		`"Please verify the contact email ` + email + ` for the account"}]}`

	r := newReq(body)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "personal", "", "", discardLogger())
	if !proceed {
		t.Fatalf("expected proceed=true; got blocked. status=%d", w.Code)
	}
	forwarded := readReqBody(t, r)
	if strings.Contains(forwarded, email) {
		t.Errorf("raw email %q still present in forwarded body — not masked:\n%s", email, forwarded)
	}
	t.Logf("ASCII control — masked body forwarded:\n%s", forwarded)
}
