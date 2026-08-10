//go:build integration

// filter_restore_integration_test.go — B5 (2026-08-08) mask-ladder true-binary
// E2E: the CN_ADDRESS 占位替换/还原 chain through the REAL ai-compliance-detector
// child over the production ChildHook/FilterPool v4 pipe — no stub hook.
//
// WHY (vs filter_restore_test.go's stub tests): the stub tests prove the proxy
// renumber/restore LOGIC; the detector-side unit tests prove the mask/meta
// logic with a synthetic rule. Neither proves the deployed chain: the REAL
// external policy override file (B5 运维升档路径, the exact file an operator
// edits) raising the lane to mask + the REAL embedded address recognizer + the
// REAL v4 IPC framing + the proxy renumbering + response restore, end to end.
// B3 shipped with this gap ("mask 档默认 audit 未走真二进制") — this closes it.
//
// The child is spawned with HOME (and USERPROFILE, for Windows parity) pointed
// at a temp dir holding .aikey/apps/ai-compliance-detector/policy.json — the
// production DefaultOverridePath resolution, not a test-only knob. The big
// dictionary layers are absent under that fake HOME; the recognizer degrades
// exactly as on a fresh install (fail-open), and the embedded minimal set
// detects the full addresses used here (verified empirically pre-B5).
//
// P2 (2026-08-08): the expected placeholders moved from the P1-retired
// Chinese/full-width label to the shipped "{{ADDR_1}}" (方案 §3.1 — 短代码表 in the P1
// 执行结论). This is a FORMAT expectation change, nothing else: the case still
// asserts the same five things (raw address never leaves, both families get a
// number, numbers follow occurrence order, ctx maps label→ORIGINAL, response
// leg restores and stays valid JSON). The custom-label case deliberately keeps
// the legacy `address_mask_label` override and its non-`{{}}` label — that is
// the backward-compatibility path P1 preserved, and it is also the ONLY
// coverage of the proxy's byte-exact (non-canonical) restore path over a real
// child.
//
// Run: make filter-integration  (builds the detector first). Skips if binary
// missing.
package proxy

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// Full-form addresses the EMBEDDED recognizer (rules + 4-level divisions +
// streets + seq model, big layers absent) reliably detects as two separate
// CN_ADDRESS findings — keep in sync with the B5 pre-implementation probe.
const (
	e2eAddr1 = "广东省深圳市宝安区西乡街道宝源路168号F518时尚创意园15栋301"
	e2eAddr2 = "浙江省杭州市西湖区文三路478号华星时代广场A座12楼"
)

// writeDetectorPolicyOverride materializes a fake HOME containing the external
// action-policy override at its production path and returns the HOME dir.
func writeDetectorPolicyOverride(t *testing.T, policyJSON string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".aikey", "apps", "ai-compliance-detector")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir override dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(policyJSON), 0o644); err != nil {
		t.Fatalf("write policy override: %v", err)
	}
	return home
}

// startRealDetectorPoolWithHome spawns the real detector child with HOME
// redirected, so it resolves the external policy override (and asset dir) from
// the test-controlled location. Mirrors startRealDetectorPool otherwise.
func startRealDetectorPoolWithHome(t *testing.T, home string) *apphook.FilterPool {
	t.Helper()
	ch := apphook.NewChildHook(&apphook.ChildHookConfig{
		Name:       "ai-compliance-detector-integ-mask",
		BinaryPath: integDetectorBinary(),
		BinaryArgs: nil, // real engine + embedded baseline pack + embedded address assets
		// exec.Cmd deduplicates Env keeping the LAST entry, so these override
		// the inherited values for the child only.
		ExtraEnv:     []string{"HOME=" + home, "USERPROFILE=" + home},
		Timeout:      5 * time.Second,  // address lane + NER scan ≫ the 1ms default
		ReadyTimeout: 20 * time.Second, // CRF model load takes a few seconds
	})
	pool := apphook.NewFilterPool("integ-mask", []*apphook.ChildHook{ch})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := pool.Start(ctx); err != nil {
		t.Skipf("detector binary unavailable (run 'make -C ../ai-compliance-detector build'): %v", err)
	}
	t.Cleanup(func() { _ = pool.Shutdown(context.Background()) })
	return pool
}

// TestFilterIntegration_AddressMaskLadderEndToEnd — B5 验收项 1: with the lane
// raised to mask through the external override file, a request holding two
// addresses is forwarded with per-request numbered placeholders (#1/#2, raw
// text gone), and a simulated LLM response echoing both placeholders restores
// to the original text.
func TestFilterIntegration_AddressMaskLadderEndToEnd(t *testing.T) {
	home := writeDetectorPolicyOverride(t, `{"schema_version":1,"entity_actions":{"CN_ADDRESS":"mask"}}`)
	pool := startRealDetectorPoolWithHome(t, home)

	p := &Proxy{}
	p.SetFilterHook(pool)
	body := `{"model":"m","messages":[{"role":"user","content":"送到` + e2eAddr1 + `，发票寄` + e2eAddr2 + `，谢谢"}]}`
	r := newReq(body)
	r.Header.Set("X-Claude-Code-Session-Id", "integ-mask")
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "claude-3", "personal", "", "", "", "", "", discardLogger()) {
		t.Fatal("mask request must proceed (mask ≠ block)")
	}

	// 请求侧: raw addresses gone, numbered labels #1/#2 in occurrence order.
	forwarded := readReqBody(t, r)
	if strings.Contains(forwarded, e2eAddr1) || strings.Contains(forwarded, e2eAddr2) {
		t.Fatalf("raw address leaked to upstream body: %s", forwarded)
	}
	if !strings.Contains(forwarded, "{{ADDR_1}}") || !strings.Contains(forwarded, "{{ADDR_2}}") {
		t.Fatalf("numbered labels missing (real detector mask/meta → proxy renumber broken): %s", forwarded)
	}
	if strings.Index(forwarded, "{{ADDR_1}}") > strings.Index(forwarded, "{{ADDR_2}}") {
		t.Fatalf("labels out of occurrence order: %s", forwarded)
	}

	// Context mapping: label → ORIGINAL text (per-request memory only).
	st := maskRestoreFromContext(r.Context())
	if st == nil {
		t.Fatal("restore state missing from request context")
	}
	if st.entries["{{ADDR_1}}"] != e2eAddr1 || st.entries["{{ADDR_2}}"] != e2eAddr2 {
		t.Fatalf("context mapping wrong: %v", st.entries)
	}

	// 响应侧 (non-streaming): the LLM echoes both placeholders → restored.
	respBody := []byte(`{"id":"msg_1","content":[{"type":"text","text":"好的，主件送到{{ADDR_1}}，发票寄{{ADDR_2}}。"}],"usage":{"input_tokens":10,"output_tokens":20}}`)
	restored := string(restoreMaskedResponseBody(r.Context(), respBody, discardLogger()))
	if !strings.Contains(restored, e2eAddr1) || !strings.Contains(restored, e2eAddr2) {
		t.Fatalf("response restore failed: %s", restored)
	}
	if strings.Contains(restored, "{{ADDR") {
		t.Fatalf("placeholder left in restored response: %s", restored)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(restored), &parsed); err != nil {
		t.Fatalf("restored body is not valid JSON: %v", err)
	}
}

// TestFilterIntegration_AddressMaskCustomLabel — B5 验收项 3 (E2E half): the
// SAME override file also customizes the placeholder label; the custom parts
// must ride the v4 wire and drive both the request-leg renumbering and the
// response-leg restore, with zero proxy-side configuration (label truth stays
// detector-side).
func TestFilterIntegration_AddressMaskCustomLabel(t *testing.T) {
	home := writeDetectorPolicyOverride(t, `{"schema_version":1,
		"entity_actions":{"CN_ADDRESS":"mask"},
		"address_mask_label":{"token":"[ADDR-HIDDEN]","numbered_prefix":"[ADDR#","numbered_suffix":"-HIDDEN]"}}`)
	pool := startRealDetectorPoolWithHome(t, home)

	p := &Proxy{}
	p.SetFilterHook(pool)
	body := `{"model":"m","messages":[{"role":"user","content":"寄到` + e2eAddr1 + `，多谢"}]}`
	r := newReq(body)
	r.Header.Set("X-Claude-Code-Session-Id", "integ-mask-label")
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "claude-3", "personal", "", "", "", "", "", discardLogger()) {
		t.Fatal("mask request must proceed")
	}
	forwarded := readReqBody(t, r)
	if strings.Contains(forwarded, e2eAddr1) {
		t.Fatalf("raw address leaked: %s", forwarded)
	}
	if !strings.Contains(forwarded, "[ADDR#1-HIDDEN]") {
		t.Fatalf("custom numbered label missing: %s", forwarded)
	}
	if strings.Contains(forwarded, "{{ADDR_") || strings.Contains(forwarded, "{{ADDR}}") {
		t.Fatalf("default label leaked despite custom override: %s", forwarded)
	}

	restored := string(restoreMaskedResponseBody(r.Context(),
		[]byte(`{"content":[{"type":"text","text":"收到，会寄到[ADDR#1-HIDDEN]。"}]}`), discardLogger()))
	if !strings.Contains(restored, e2eAddr1) || strings.Contains(restored, "[ADDR#") {
		t.Fatalf("custom-label response restore failed: %s", restored)
	}
}
