package proxy

import (
	"context"
	"net/http/httptest"
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
//
// HERMETIC BY CONSTRUCTION: the binary comes from liveDetectorBinary (see
// detector_door_test.go), which seals the four $HOME-rooted detector inputs
// before anything is spawned, and sealed.AssertHeld below makes the child
// confirm it. Without that pair, "the shipped detector masks this prompt" and
// "this developer's installed ~/.aikey masks this prompt" are indistinguishable.
func TestApplyInboundFilter_LiveDetector(t *testing.T) {
	bin, sealed := liveDetectorBinary(t, "the live closed-loop test")

	hook := apphook.NewChildHook(&apphook.ChildHookConfig{
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
	// Anti-regression: prove the child actually resolved the sealed home, before
	// any content assertion runs. Setting the env is not evidence that it took.
	sealed.AssertHeld(t, hook)

	p := &Proxy{filterHook: hook}

	// Synthetic PII embedded in an Anthropic-style chat body. Neither value is a
	// real person's data, but BOTH must still satisfy the rules' own admission
	// contract — a fixture that the ruleset legitimately rejects proves nothing
	// about the mask path.
	//
	// WHY THE ID CARD ENDS 7424 AND NOT 742X (fixture correction 2026-08-13)
	//
	// pii.cn.id_card (internal/baselines/built-in/cn-pii.yaml) declares
	// `validator: cn_id_card` = GB 11643-1999 check digit + birthdate
	// plausibility. Matching the \b\d{17}[\dXx]\b pattern is NOT detection; the
	// validator is what makes the rule high-precision. The previous fixture
	// "11010119900307742X" has an INVALID check digit (GB 11643 requires 4), so
	// CN_ID_CARD was never emitted for it — verified by probing engine.Detect
	// across 2026-06-10 → 2026-08-13: the entity is absent at every commit.
	// The assertion nevertheless passed for a while because five INTERNATIONAL
	// numeric-ID regexes (FI/PL/DE/TR/SE) also match any 17-digit+1 string and
	// used to mask, so the raw substring disappeared for the wrong reason. That
	// is a false green, not coverage. 110101199003077424 carries a valid check
	// digit, so this now exercises pii.cn.id_card itself.
	const idCard = "110101199003077424"

	// WHY THE PROMPT SAYS 客户手机号 AND NOT 客户信息：手机号
	//
	// The production action-policy bundle gates CN_PHONE on CLAUSE-LOCAL
	// ownership evidence (`phone_ownership` in actionpolicy bundles/
	// wave-1-risk-accepted/v5-recovery.json: 客户手机号 / 用户手机号 / 联系方式 …).
	// A bare 11-digit number next to a bare 手机号 is the measured 12.9%
	// user-impact false-positive shape the gate exists to remove. The old
	// phrasing put 客户 and 手机号 in DIFFERENT clauses (the full-width colon
	// splits them), so the phone finding was capped at warn with
	// reason=positive_context_missing missing=[phone_ownership] — i.e. the
	// policy behaved as designed and the fixture simply no longer described a
	// masked prompt.
	//
	// NOTE (open product question, deliberately NOT papered over here): whether
	// "客户信息：手机号 X" SHOULD confirm ownership is a live coverage question
	// filed as B3-a in workflow/CI/review/20260813-合规检测-未决事项backlog.md.
	// This test proves the mask PLUMBING on CJK; it is not the adjudicator of
	// the FP calibration.
	const phone = "13800138000"
	body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":` +
		`"请帮我核对客户手机号 ` + phone + `，身份证号 ` + idCard + ` 是否正确"}]}`

	r := newReq(body)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "personal", "", "", "", "", "", discardLogger())

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
	if strings.Contains(forwarded, "7424") {
		t.Errorf("residual id-card tail '7424' leaked — mask span misaligned:\n%s", forwarded)
	}
	t.Logf("LIVE closed loop OK — masked body forwarded:\n%s", forwarded)
}

// TestApplyInboundFilter_LiveDetector_ASCII is the ASCII control for the live
// test: same path, pure-ASCII PII (no multibyte runes). Comparing its masked
// output against the CJK case isolates whether mask misalignment is triggered
// by UTF-8 multibyte offsets. Asserts the same P4 contract (raw PII removed).
func TestApplyInboundFilter_LiveDetector_ASCII(t *testing.T) {
	bin, sealed := liveDetectorBinary(t, "the live closed-loop test")

	hook := apphook.NewChildHook(&apphook.ChildHookConfig{
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
	sealed.AssertHeld(t, hook)

	p := &Proxy{filterHook: hook}

	// WHY NOT @example.com (fixture correction 2026-08-13)
	//
	// The production bundle's `non_live_value_ceiling` stage runs the
	// `reserved_email_domain` validator (actionpolicy/stage_v7.go) and caps any
	// RFC 2606 reserved address at warn: the .example/.invalid/.localhost/.test
	// TLDs plus example.com/.net/.org. Those domains can never hold a real
	// mailbox, so masking them is a guaranteed false positive — the stage is
	// correct, and the old fixture had merely picked a reserved domain to avoid
	// using a real address.
	//
	// Control experiment (2026-08-13): the SAME prompt and the SAME rule
	// (pii.cn.email) on a non-reserved domain evaluates to mask, so email
	// masking is fully alive; only the documentation-example class is exempt.
	// Keep this domain OUT of the RFC 2606 set or the assertion silently stops
	// testing the mask path.
	const email = "john.doe.test@aikey-fixture.cn"
	body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":` +
		`"Please verify the contact email ` + email + ` for the account"}]}`

	r := newReq(body)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatalf("expected proceed=true; got blocked. status=%d", w.Code)
	}
	forwarded := readReqBody(t, r)
	if strings.Contains(forwarded, email) {
		t.Errorf("raw email %q still present in forwarded body — not masked:\n%s", email, forwarded)
	}
	t.Logf("ASCII control — masked body forwarded:\n%s", forwarded)
}
