package proxy

// filter_restore_l3_test.go — P2 fences (方案 20260808 §3.2 L3 / §3.3):
// multi-token correctness on the request leg, fault-tolerant restore on the
// response leg, the "unknown id stays verbatim" invariant (§5.2), the
// one-token⇒one-restorable wire guard, and the 保真率 health signal.
//
// The B3 single-family behavior is fenced in filter_restore_test.go; this file
// only covers what P1's multi-entity output made reachable.

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// --- helpers -----------------------------------------------------------------

// captureLogger returns a WARN-level logger writing into a buffer, so a test can
// assert BOTH that the loud path fired and that it leaked no masked content.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

// restorableFor builds one family's wire metadata: the numberless token, its
// numbered form and the [start,end) spans of the values it replaced in head.
// Mirrors what the detector's buildMaskMeta emits per label token.
func restorableFor(head, token, prefix, suffix string, values ...string) apphook.RestorableMask {
	r := apphook.RestorableMask{Token: token, NumberedPrefix: prefix, NumberedSuffix: suffix}
	off := 0
	for _, v := range values {
		i := strings.Index(head[off:], v)
		if i < 0 {
			panic("test value not present in head: " + v)
		}
		start := off + i
		r.Spans = append(r.Spans, [2]int{start, start + len(v)})
		off = start + len(v)
	}
	return r
}

// canonicalRestorable is restorableFor for a shipped `{{CODE}}` family.
func canonicalRestorable(head, code string, values ...string) apphook.RestorableMask {
	return restorableFor(head, "{{"+code+"}}", "{{"+code+"_", "}}", values...)
}

// maskValues replaces each value in head with tok, once, left to right —
// the planner's own substitution, reproduced so the test's "masked" text is
// exactly what the proxy would receive.
func maskValues(head, tok string, values ...string) string {
	out := head
	for _, v := range values {
		out = strings.Replace(out, v, tok, 1)
	}
	return out
}

// --- ① multi-entity mixed request --------------------------------------------

// Address + phone + email in ONE request: numbers must run 1,2,3… in TEXT order
// across families (a request-scoped counter, not a per-family one), each label
// must carry its OWN numbered form, and each must map back to its own original.
//
// 能红 anchor: before P2 the numbered prefix/suffix came from a linear "first
// restorable whose Token matches" scan — with several families that hands one
// family another family's prefix (串味).
func TestRenumberRestorables_MultiEntityNumberingAndRestore(t *testing.T) {
	addr, phone, email := "北京市朝阳区建国路88号", "13800138000", "zhang@example.com"
	head := "地址" + addr + "，电话" + phone + "，邮箱" + email
	masked := maskValues(head, "{{ADDR}}", addr)
	masked = maskValues(masked, "{{PHONE}}", phone)
	masked = maskValues(masked, "{{EMAIL}}", email)

	st := newMaskRestore()
	got := renumberRestorables(head, masked, []apphook.RestorableMask{
		canonicalRestorable(head, "ADDR", addr),
		canonicalRestorable(head, "PHONE", phone),
		canonicalRestorable(head, "EMAIL", email),
	}, st, discardLogger())

	want := "地址{{ADDR_1}}，电话{{PHONE_2}}，邮箱{{EMAIL_3}}"
	if got != want {
		t.Fatalf("multi-entity renumber = %q, want %q", got, want)
	}
	for label, orig := range map[string]string{
		"{{ADDR_1}}": addr, "{{PHONE_2}}": phone, "{{EMAIL_3}}": email,
	} {
		if st.entries[label] != orig {
			t.Fatalf("mapping[%s] = %q, want %q (full map: %v)", label, st.entries[label], orig, st.entries)
		}
	}

	// Response leg: all three come back, all three restore, nothing bleeds.
	ctx := context.WithValue(context.Background(), ctxKeyMaskRestore, st)
	body := []byte(`{"content":[{"type":"text","text":"寄到{{ADDR_1}}，打{{PHONE_2}}，抄送{{EMAIL_3}}"}]}`)
	out := string(restoreMaskedResponseBody(ctx, body, discardLogger()))
	if !strings.Contains(out, addr) || !strings.Contains(out, phone) || !strings.Contains(out, email) {
		t.Fatalf("multi-entity restore incomplete: %s", out)
	}
	if strings.Contains(out, "{{") {
		t.Fatalf("placeholder survived restore: %s", out)
	}
}

// Interleaved occurrences of two families must still number by TEXT position,
// not by the order the families arrive on the wire.
func TestRenumberRestorables_MultiEntityNumbersFollowTextOrder(t *testing.T) {
	p1, a1, p2 := "13900139000", "上海市浦东新区世纪大道1号", "13700137000"
	head := "先打" + p1 + "，寄到" + a1 + "，或打" + p2
	masked := maskValues(maskValues(head, "{{ADDR}}", a1), "{{PHONE}}", p1, p2)

	st := newMaskRestore()
	// ADDR first on the wire even though its occurrence sits in the middle.
	got := renumberRestorables(head, masked, []apphook.RestorableMask{
		canonicalRestorable(head, "ADDR", a1),
		canonicalRestorable(head, "PHONE", p1, p2),
	}, st, discardLogger())

	want := "先打{{PHONE_1}}，寄到{{ADDR_2}}，或打{{PHONE_3}}"
	if got != want {
		t.Fatalf("interleaved renumber = %q, want %q", got, want)
	}
	if st.entries["{{PHONE_1}}"] != p1 || st.entries["{{ADDR_2}}"] != a1 || st.entries["{{PHONE_3}}"] != p2 {
		t.Fatalf("interleaved mapping wrong: %v", st.entries)
	}
}

// --- ② substring-trap tokens (能红 用例) --------------------------------------

// A custom label whose token is a SUBSTRING of another custom label's token.
// P1 proved the shipped `{{CODE}}` codes can never do this, so the live risk is
// operator-authored `mask_labels`; the detector rejects such a table at load
// time, and this is the proxy-side half of that defense (the proxy must stay
// correct against any child it is handed).
//
// 能红: with the pre-P2 per-token strings.Index scan, `<A>` is found INSIDE the
// two `<<A>>` occurrences as well. Its phantom count (3) does not equal its
// span count (1) there — but the SECOND assertion below is the silent-corruption
// shape: make the phantom count match, and the old code renumbers a position
// that lives inside another family's token.
func TestRenumberRestorables_SubstringTokenTrap(t *testing.T) {
	v1, v2, v3 := "值一", "值二", "值三"
	head := "甲" + v1 + "乙" + v2 + "丙" + v3
	// Family OUTER uses "<<A>>"; family INNER uses "<A>" — a strict substring.
	masked := "甲<<A>>乙<<A>>丙<A>"

	st := newMaskRestore()
	got := renumberRestorables(head, masked, []apphook.RestorableMask{
		restorableFor(head, "<<A>>", "<<A#", ">>", v1, v2),
		restorableFor(head, "<A>", "<A#", ">", v3),
	}, st, discardLogger())

	want := "甲<<A#1>>乙<<A#2>>丙<A#3>"
	if got != want {
		t.Fatalf("substring-trap renumber = %q, want %q", got, want)
	}
	if st.entries["<<A#1>>"] != v1 || st.entries["<<A#2>>"] != v2 || st.entries["<A#3>"] != v3 {
		t.Fatalf("substring-trap mapping wrong: %v", st.entries)
	}
	// The inner family must NOT have consumed bytes belonging to the outer one.
	if strings.Contains(got, "<<A#3") || strings.Count(got, "<A#3>") != 1 {
		t.Fatalf("inner token stole outer bytes: %q", got)
	}
}

// The counts-line-up variant: without longest-match-wins the inner family's
// phantom hits inside the outer token make the alignment check PASS and the
// renumberer writes into the middle of the outer token. That is the silent
// mis-restore §5.2 forbids, so it gets its own fence.
func TestRenumberRestorables_SubstringTokenTrapCountsAlign(t *testing.T) {
	outer, inner := "外层原文", "内层原文"
	head := "甲" + outer + "乙" + inner
	masked := "甲<<A>>乙<A>" // inner "<A>" also occurs inside "<<A>>" → 2 phantom-inclusive hits

	st := newMaskRestore()
	got := renumberRestorables(head, masked, []apphook.RestorableMask{
		restorableFor(head, "<<A>>", "<<A#", ">>", outer),
		restorableFor(head, "<A>", "<A#", ">", inner),
	}, st, discardLogger())

	if got != "甲<<A#1>>乙<A#2>" {
		t.Fatalf("counts-align trap corrupted the text: %q", got)
	}
	if st.entries["<<A#1>>"] != outer || st.entries["<A#2>"] != inner {
		t.Fatalf("counts-align trap mapping wrong: %v", st.entries)
	}
	// Response leg proof: each label restores to ITS OWN original.
	ctx := context.WithValue(context.Background(), ctxKeyMaskRestore, st)
	out := string(restoreMaskedResponseBody(ctx,
		[]byte(`{"t":"甲<<A#1>>乙<A#2>"}`), discardLogger()))
	if !strings.Contains(out, outer) || !strings.Contains(out, inner) {
		t.Fatalf("counts-align trap restore wrong: %s", out)
	}
}

// The `{{A}}` / `{{A_1}}` pair the plan calls out: an operator token that is
// spelled like another family's NUMBERED form. Neither may swallow the other,
// and the response leg must hand each label its own original.
func TestRenumberRestorables_TokenLooksLikeAnotherNumberedForm(t *testing.T) {
	v1, v2 := "第一段原文", "第二段原文"
	head := "甲" + v1 + "乙" + v2
	masked := "甲{{A}}乙{{A_1}}"

	st := newMaskRestore()
	got := renumberRestorables(head, masked, []apphook.RestorableMask{
		restorableFor(head, "{{A}}", "{{A_", "}}", v1),
		restorableFor(head, "{{A_1}}", "{{A_1_", "}}", v2),
	}, st, discardLogger())

	// Family one takes number 1 → "{{A_1}}"; family two takes number 2.
	if got != "甲{{A_1}}乙{{A_1_2}}" {
		t.Fatalf("numbered-form collision renumber = %q", got)
	}
	ctx := context.WithValue(context.Background(), ctxKeyMaskRestore, st)
	out := string(restoreMaskedResponseBody(ctx, []byte(`{"t":"甲{{A_1}}乙{{A_1_2}}"}`), discardLogger()))
	if !strings.Contains(out, v1) || !strings.Contains(out, v2) {
		t.Fatalf("numbered-form collision restore wrong: %s", out)
	}
}

// --- ③ unknown id stays verbatim (不变量 §5.2) --------------------------------

func TestRestore_UnknownIDStaysVerbatim(t *testing.T) {
	known := "北京市海淀区中关村1号"
	ctx := restoreStateCtx(map[string]string{"{{ADDR_1}}": known})

	cases := []struct {
		name string
		text string
	}{
		{"unknown number in a known family", "去 {{ADDR_7}} 看看"},
		{"unknown entity code", "去 {{PHONE_1}} 看看"},
		{"number zero", "去 {{ADDR_0}} 看看"},
		{"no number at all", "去 {{ADDR}} 看看"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := []byte(`{"t":` + strconv.Quote(c.text) + `}`)
			out := string(restoreMaskedResponseBody(ctx, body, discardLogger()))
			if strings.Contains(out, known) {
				t.Fatalf("unknown id was GUESSED onto a known original: %s", out)
			}
			if !strings.Contains(out, c.text) {
				t.Fatalf("unknown id must survive byte-for-byte, got: %s", out)
			}
		})
	}
}

// The single most dangerous fuzzy-mapping shape: exactly ONE mapping exists and
// the model returns a DIFFERENT id. "Nearest match" would be catastrophic here.
func TestRestore_SingleMappingDoesNotAbsorbOtherIDs(t *testing.T) {
	ctx := restoreStateCtx(map[string]string{"{{ADDR_1}}": "深圳市南山区科技园2号"})
	out := string(restoreMaskedResponseBody(ctx, []byte(`{"t":"A {{ADDR_2}} B {{ADDR_11}} C"}`), discardLogger()))
	if !strings.Contains(out, "{{ADDR_2}}") || !strings.Contains(out, "{{ADDR_11}}") {
		t.Fatalf("neighboring ids must not be absorbed: %s", out)
	}
	if strings.Contains(out, "深圳市") {
		t.Fatalf("a different id was mapped to the only original: %s", out)
	}
}

// --- ④ one token ⇒ one Restorable (wire contract guard) ----------------------

// Two Restorables carrying the SAME token (an un-merged alias pair such as
// CN_PHONE/PHONE from a child that regressed). Acting on them double-counts the
// occurrences and lays the second family's numbers over the first family's
// spans. Both must be dropped: mask KEPT, restore skipped, WARN.
func TestRenumberRestorables_DuplicateTokenIsDroppedNotDoubleCounted(t *testing.T) {
	p1, p2 := "13800138000", "13900139000"
	head := "甲" + p1 + "乙" + p2
	masked := maskValues(head, "{{PHONE}}", p1, p2)

	logger, buf := captureLogger()
	st := newMaskRestore()
	got := renumberRestorables(head, masked, []apphook.RestorableMask{
		restorableFor(head, "{{PHONE}}", "{{PHONE_", "}}", p1),
		restorableFor(head, "{{PHONE}}", "{{CNPHONE_", "}}", p2),
	}, st, logger)

	if got != masked {
		t.Fatalf("duplicate-token metadata must leave the numberless mask intact, got %q", got)
	}
	if len(st.entries) != 0 {
		t.Fatalf("duplicate-token metadata must record no mapping: %v", st.entries)
	}
	if !strings.Contains(got, "{{PHONE}}") || strings.Contains(got, p1) || strings.Contains(got, p2) {
		t.Fatalf("mask itself must survive the guard (fail-open, still masked): %q", got)
	}
	if !strings.Contains(buf.String(), "proxy.filter.restore_duplicate_token") {
		t.Fatalf("duplicate token must WARN loudly, log was: %s", buf.String())
	}
	// The WARN must not leak the values it protected.
	if strings.Contains(buf.String(), p1) || strings.Contains(buf.String(), p2) {
		t.Fatalf("WARN leaked masked content: %s", buf.String())
	}
}

// A duplicate in ONE family must not disarm an unrelated healthy family.
func TestRenumberRestorables_DuplicateTokenDoesNotDisarmOtherFamilies(t *testing.T) {
	addr, p1, p2 := "杭州市西湖区文一路3号", "13800138000", "13900139000"
	head := "址" + addr + "甲" + p1 + "乙" + p2
	masked := maskValues(maskValues(head, "{{ADDR}}", addr), "{{PHONE}}", p1, p2)

	st := newMaskRestore()
	got := renumberRestorables(head, masked, []apphook.RestorableMask{
		canonicalRestorable(head, "ADDR", addr),
		restorableFor(head, "{{PHONE}}", "{{PHONE_", "}}", p1),
		restorableFor(head, "{{PHONE}}", "{{CNPHONE_", "}}", p2),
	}, st, discardLogger())

	if !strings.Contains(got, "{{ADDR_1}}") {
		t.Fatalf("healthy family must still be renumbered: %q", got)
	}
	if !strings.Contains(got, "{{PHONE}}") {
		t.Fatalf("duplicated family must keep its numberless mask: %q", got)
	}
	if st.entries["{{ADDR_1}}"] != addr || len(st.entries) != 1 {
		t.Fatalf("only the healthy family may map: %v", st.entries)
	}
}

// --- ⑤ L3 tolerant variants --------------------------------------------------

func TestRestore_L3TolerantVariants(t *testing.T) {
	orig := "广州市天河区体育西路1号"
	ctx := restoreStateCtx(map[string]string{"{{ADDR_1}}": orig})

	cases := []struct {
		name string
		text string
	}{
		{"exact", "送到{{ADDR_1}}。"},
		{"inner spaces", "送到{{ ADDR_1 }}。"},
		{"space around underscore", "送到{{ ADDR _ 1 }}。"},
		{"single braces", "送到{ADDR_1}。"},
		{"lowercase", "送到{{addr_1}}。"},
		{"mixed case", "送到{{Addr_1}}。"},
		{"single braces lowercase spaced", "送到{ addr_1 }。"},
		{"double-quoted outside", `送到"{{ADDR_1}}"。`},
		{"backticked outside", "送到`{{ADDR_1}}`。"},
		{"quoted inside braces", `送到{{"ADDR_1"}}。`},
		{"curly quotes inside braces", "送到{{“ADDR_1”}}。"},
		{"leading zero in the number", "送到{{ADDR_01}}。"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := []byte(`{"t":` + strconv.Quote(c.text) + `}`)
			out := string(restoreMaskedResponseBody(ctx, body, discardLogger()))
			if !strings.Contains(out, orig) {
				t.Fatalf("tolerant variant not restored: %s", out)
			}
			if strings.Contains(out, "ADDR_1") || strings.Contains(out, "addr_1") {
				t.Fatalf("placeholder residue left behind: %s", out)
			}
		})
	}
}

// Tolerance must never reach a CUSTOM (non-`{{}}`) label: the proxy does not
// own that grammar, so only byte-exact restore applies there.
func TestRestore_CustomLabelIsExactOnly(t *testing.T) {
	orig := "南京市玄武区中山路9号"
	ctx := restoreStateCtx(map[string]string{"[ADDR#1-HIDDEN]": orig})

	exact := string(restoreMaskedResponseBody(ctx, []byte(`{"t":"寄到[ADDR#1-HIDDEN]"}`), discardLogger()))
	if !strings.Contains(exact, orig) {
		t.Fatalf("custom label must restore byte-exact: %s", exact)
	}
	loose := string(restoreMaskedResponseBody(ctx, []byte(`{"t":"寄到[ ADDR#1-HIDDEN ]"}`), discardLogger()))
	if strings.Contains(loose, orig) {
		t.Fatalf("custom label must NOT be matched loosely: %s", loose)
	}
}

// Tolerant matching over the streaming path, including a variant split across
// delta frames — the holdback window has to account for the extra bytes a
// spaced/quoted variant adds.
func TestSSERestore_L3TolerantVariants(t *testing.T) {
	orig := "成都市武侯区天府大道7号"
	frames := map[string][]string{
		"spaced in one frame":    {"寄到{{ ADDR_1 }}好了"},
		"single brace one frame": {"寄到{ADDR_1}好了"},
		"lowercase split":        {"寄到{{ad", "dr_1}}好了"},
		"spaced split":           {"寄到{{ AD", "DR_1 }}好了"},
	}
	for name, parts := range frames {
		t.Run(name, func(t *testing.T) {
			st := sseTestState(map[string]string{"{{ADDR_1}}": orig})
			var in string
			for _, p := range parts {
				in += anthropicTextFrame(p)
			}
			in += "data: [DONE]\n\n"
			out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 5}, st))
			if got := concatTextDeltas(t, out); got != "寄到"+orig+"好了" {
				t.Fatalf("tolerant SSE restore = %q, want %q", got, "寄到"+orig+"好了")
			}
		})
	}
}

// An unknown id inside a stream must come out whole and unchanged — no partial
// swallow by the holdback, no guess.
func TestSSERestore_UnknownIDPassesThroughWhole(t *testing.T) {
	st := sseTestState(map[string]string{"{{ADDR_1}}": "北京市朝阳区建国路88号"})
	in := anthropicTextFrame("参考{{ADDR_9") + anthropicTextFrame("}}即可") + "data: [DONE]\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 6}, st))
	if got := concatTextDeltas(t, out); got != "参考{{ADDR_9}}即可" {
		t.Fatalf("unknown id mangled by the stream restorer: %q", got)
	}
}

// A `{` that cannot grow into a placeholder (JSON / code the model streams back)
// must not be withheld — otherwise every code answer pays a re-encode and an
// extra frame of latency.
func TestSSERestore_NonPlaceholderBraceNotWithheld(t *testing.T) {
	st := sseTestState(map[string]string{"{{ADDR_1}}": "x"})
	in := anthropicTextFrame(`示例：{"a": 1}`) + "data: [DONE]\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: len(in)}, st))
	if out != in {
		t.Fatalf("a non-placeholder brace must leave the stream byte-identical:\n got %q\nwant %q", out, in)
	}
}

// The two regexes are hand-derived from one grammar, so they can drift apart.
// This is the fence that catches it: EVERY prefix of EVERY tolerant variant the
// matcher accepts must also be accepted by the holdback's prefix matcher —
// otherwise a placeholder split at that exact byte is emitted half-restored.
func TestMaskRestore_HoldbackTolerantCoversEveryMatcherVariant(t *testing.T) {
	variants := []string{
		"{{ADDR_1}}", "{{ ADDR_1 }}", "{{ ADDR _ 1 }}", "{ADDR_1}",
		"{{addr_1}}", "{{Addr_1}}", `{{"ADDR_1"}}`, "{{“ADDR_1”}}", "{{ADDR_01}}",
	}
	for _, v := range variants {
		if !tolerantPlaceholderRe.MatchString(v) {
			t.Fatalf("matcher does not accept declared variant %q", v)
		}
		// Every strict prefix must still look like "a placeholder in progress".
		// Prefixes are taken at RUNE boundaries: the holdback runs on the DECODED
		// text channel, where each SSE delta is a complete JSON string, so a split
		// can land between characters but never inside one.
		for i := range v {
			if i == 0 {
				continue
			}
			if !tolerantPlaceholderPrefixRe.MatchString(v[:i]) {
				t.Fatalf("holdback would release %q — the prefix matcher rejects it, so a stream split there loses the restore", v[:i])
			}
		}
	}
}

func TestMaskRestore_HoldbackTolerantIgnoresNonPlaceholderBraces(t *testing.T) {
	st := newMaskRestore()
	st.add("{{ADDR_1}}", "x")
	for _, s := range []string{
		`回答：{"a": 1}`,
		"代码：if (x) {\n",
		"公式 {中文}",
		"完整但未知的 {{FOO_9}}",
	} {
		if h := st.holdback(s); h != "" && !strings.HasPrefix(h, "{") {
			t.Fatalf("holdback(%q) = %q — must be empty or a brace-run candidate", s, h)
		}
		if h := st.holdback(s); len(h) > 0 && strings.ContainsAny(h, ":\n中") {
			t.Fatalf("holdback(%q) withheld non-placeholder text %q", s, h)
		}
	}
}

// --- ⑥ 保真率 health signal ---------------------------------------------------

func TestMaskFidelity_IssuedVsRestored(t *testing.T) {
	addr, phone := "北京市朝阳区建国路88号", "13800138000"
	head := "址" + addr + "话" + phone
	masked := maskValues(maskValues(head, "{{ADDR}}", addr), "{{PHONE}}", phone)

	p := &Proxy{}
	st := newMaskRestore()
	st.fid = &p.maskFidelity
	renumberRestorables(head, masked, []apphook.RestorableMask{
		canonicalRestorable(head, "ADDR", addr),
		canonicalRestorable(head, "PHONE", phone),
	}, st, discardLogger())

	if h := p.maskRestoreHealth(); h.Issued != 2 || h.Restored != 0 {
		t.Fatalf("after the request leg: issued/restored = %d/%d, want 2/0", h.Issued, h.Restored)
	}

	// The model returns ONE of the two, and repeats it — repeats must not inflate.
	ctx := context.WithValue(context.Background(), ctxKeyMaskRestore, st)
	restoreMaskedResponseBody(ctx, []byte(`{"t":"{{ADDR_1}} 和 {{ADDR_1}} 与 {{ ADDR_1 }}"}`), discardLogger())

	h := p.maskRestoreHealth()
	if h.Issued != 2 || h.Restored != 1 {
		t.Fatalf("issued/restored = %d/%d, want 2/1", h.Issued, h.Restored)
	}
	if h.FidelityPct != 50 {
		t.Fatalf("fidelity_pct = %d, want 50", h.FidelityPct)
	}
	// Below the minimum sample the verdict is WITHHELD: two data points are not
	// evidence that a model started rewriting placeholders — but they are not
	// evidence that everything is fine either. This used to assert `ok`, which
	// made the endpoint print "placeholders are being returned and restored" at
	// 50% (and at 0%, seen 2026-08-10) — a health signal contradicting its own
	// counters. "Not enough data" is the honest third answer.
	if h.Status != MaskRestoreInsufficientSample {
		t.Fatalf("status = %q, want %q at sample size 2", h.Status, MaskRestoreInsufficientSample)
	}
	if !strings.Contains(h.Reason, "not yet a verdict") {
		t.Fatalf("reason must say the verdict is pending, got %q", h.Reason)
	}
}

func TestMaskRestoreHealth_States(t *testing.T) {
	p := &Proxy{}
	if h := p.maskRestoreHealth(); h.Status != MaskRestoreInactive || h.Reason == "" {
		t.Fatalf("no traffic must read inactive with a reason, got %+v", h)
	}

	// One issued, none restored: the feature RAN and the ratio is 0% — but one
	// sample decides nothing. This must not read `inactive` (it ran) and must
	// not read `ok` (0% is not health); it is the state where the endpoint says
	// so. The `ok` reading here is what sent a real investigation down the wrong
	// path on 2026-08-10.
	p.maskFidelity.issued.Store(1)
	if h := p.maskRestoreHealth(); h.Status != MaskRestoreInsufficientSample || h.FidelityPct != 0 {
		t.Fatalf("issued=1 restored=0 must read insufficient_sample/0, got %+v", h)
	}

	// One below the floor is still withheld; the boundary is the floor itself.
	p.maskFidelity.issued.Store(maskFidelityMinSample - 1)
	p.maskFidelity.restored.Store(maskFidelityMinSample - 1)
	if h := p.maskRestoreHealth(); h.Status != MaskRestoreInsufficientSample {
		t.Fatalf("one sample below the floor must still withhold the verdict, got %+v", h)
	}

	p.maskFidelity.issued.Store(maskFidelityMinSample)
	p.maskFidelity.restored.Store(maskFidelityMinSample)
	if h := p.maskRestoreHealth(); h.Status != MaskRestoreOK || h.FidelityPct != 100 {
		t.Fatalf("full fidelity AT the floor must read ok/100, got %+v", h)
	}

	p.maskFidelity.restored.Store(maskFidelityMinSample / 2) // 50%
	h := p.maskRestoreHealth()
	if h.Status != MaskRestoreDegraded {
		t.Fatalf("half the placeholders lost must read degraded, got %+v", h)
	}

	// Recoverable, not latched: enough good traffic pulls the verdict back.
	p.maskFidelity.issued.Add(1000)
	p.maskFidelity.restored.Add(1000)
	if h := p.maskRestoreHealth(); h.Status != MaskRestoreOK {
		t.Fatalf("verdict must recover as fidelity recovers, got %+v", h)
	}
}

// The signal has to be readable from OUTSIDE the process, not just in memory —
// that is the whole point of health-signal-surface (a counter nobody can read
// is not a health signal).
func TestDiagnosticsPipeline_ExposesMaskRestoreHealth(t *testing.T) {
	p := &Proxy{}
	p.maskFidelity.issued.Store(4)
	p.maskFidelity.restored.Store(3)

	w := httptest.NewRecorder()
	p.handleDiagnosticsPipeline(w, httptest.NewRequest("GET", "/v1/diagnostics/pipeline", nil))
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`"mask_restore"`, `"placeholders_issued":4`, `"placeholders_restored":3`, `"fidelity_pct":75`, `"status":"ok"`,
		// P4:扫描角色策略必须**从进程外可读**。发版 E2E 靠这一项断言 assistant
		// 在扫描范围内 —— 否则 mask/restore 只在首轮有效(方案 §2.2),而看板/日志
		// 都判断不出来。默认(未配置)也必须显式吐出默认值,不能是空。
		`"scan_roles":["assistant","user"]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics body missing %s:\n%s", want, body)
		}
	}

	// 收窄后端点必须如实反映(不是硬编码常量),否则这个健康信号是假的。
	p.SetFilterScanRoles([]string{"user"})
	w2 := httptest.NewRecorder()
	p.handleDiagnosticsPipeline(w2, httptest.NewRequest("GET", "/v1/diagnostics/pipeline", nil))
	if !strings.Contains(w2.Body.String(), `"scan_roles":["user"]`) {
		t.Fatalf("scan_roles 未反映实际配置(健康信号必须是真值):\n%s", w2.Body.String())
	}
}

// --- ⑦ end-to-end through the dispatcher -------------------------------------

// stubMultiEntityHook masks two different families in one Detect call, the way
// P1's buildMaskMeta groups findings by label token.
type stubMultiEntityHook struct {
	addr  string
	phone string
}

func (h *stubMultiEntityHook) Name() string { return "stub-multi-entity" }
func (h *stubMultiEntityHook) Detect(_ context.Context, req *apphook.Request) *apphook.Response {
	head := string(req.Payload)
	hasAddr, hasPhone := strings.Contains(head, h.addr), strings.Contains(head, h.phone)
	if !hasAddr && !hasPhone {
		return &apphook.Response{Action: apphook.ActionAllow}
	}
	masked := head
	var rs []apphook.RestorableMask
	if hasAddr {
		rs = append(rs, canonicalRestorable(head, "ADDR", h.addr))
		masked = maskValues(masked, "{{ADDR}}", h.addr)
	}
	if hasPhone {
		rs = append(rs, canonicalRestorable(head, "PHONE", h.phone))
		masked = maskValues(masked, "{{PHONE}}", h.phone)
	}
	return &apphook.Response{Action: apphook.ActionMask, MutatedPayload: []byte(masked), Restorables: rs}
}
func (h *stubMultiEntityHook) Status() *apphook.Status { return &apphook.Status{Healthy: true} }

func TestApplyInboundFilter_MultiEntityEndToEndWithFidelity(t *testing.T) {
	addr, phone := "上海市浦东新区世纪大道100号", "13800138000"
	p := &Proxy{filterHook: &stubMultiEntityHook{addr: addr, phone: phone}}
	body := `{"model":"m","messages":[{"role":"user","content":"送到` + addr + `，电话` + phone + `"}]}`
	r := newReq(body)

	if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger()) {
		t.Fatal("expected proceed")
	}
	forwarded := readReqBody(t, r)
	if strings.Contains(forwarded, addr) || strings.Contains(forwarded, phone) {
		t.Fatalf("raw values leaked upstream: %s", forwarded)
	}
	if !strings.Contains(forwarded, "{{ADDR_1}}") || !strings.Contains(forwarded, "{{PHONE_2}}") {
		t.Fatalf("multi-entity labels missing/misnumbered: %s", forwarded)
	}
	if h := p.maskRestoreHealth(); h.Issued != 2 {
		t.Fatalf("issued should count both placeholders, got %+v", h)
	}

	// The model answers with cosmetic drift on both — L3 has to carry them.
	out := string(restoreMaskedResponseBody(r.Context(),
		[]byte(`{"content":[{"type":"text","text":"寄到{{ addr_1 }}，拨打{ PHONE_2 }"}]}`), discardLogger()))
	if !strings.Contains(out, addr) || !strings.Contains(out, phone) {
		t.Fatalf("tolerant end-to-end restore failed: %s", out)
	}
	if h := p.maskRestoreHealth(); h.Restored != 2 || h.FidelityPct != 100 {
		t.Fatalf("fidelity after a fully-restored answer = %+v, want 2/2", h)
	}
}
