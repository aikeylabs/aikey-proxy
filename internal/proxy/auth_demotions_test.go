package proxy

// auth-demotions.json 围栏（远程诊断链，2026-09-01）。
// 守两件事：① 硬吊销入队时**必然**落本地环（不落 = doctor 收不到 = 又回到靠猜）
// ② 环里**不含任何密钥材料**（这份文件会被整个粘进工单）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnqueueAuthFailureLeavesALocalDemotionRecord(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	r := &signalReporter{
		authFailures: make(map[string]authFailureSample),
		authIn:       make(chan authFailureSample, 1),
		authWake:     make(chan struct{}, 1),
	}
	const fullFingerprint = "abcdef0123456789abcdef0123456789abcdef01"
	r.enqueueAuthFailure("cred-1", "grp-1", "seat-1", fullFingerprint, 401, "invalid_token")
	// 走真实链路：enqueue（热路径，O(1)）→ channel → ingest（loop 单写者，负责落盘）。
	// 落盘刻意不在 enqueue 里——第一版放错，被 PLANE-01 hotpath 围栏拦下。
	r.ingestAuthFailures([]authFailureSample{<-r.authIn})

	path, err := authDemotionsPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("硬吊销入队后本地没有留痕（%s 不存在）——doctor 将收不到任何降级证据，"+
			"「登录成功→一会儿变登录失效」重新变成不可诊断: %v", authDemotionsFilename, err)
	}
	var body authDemotionsBody
	if err := json.Unmarshal(raw, &body); err != nil || len(body.Entries) != 1 {
		t.Fatalf("demotion ring invalid: err=%v raw=%s", err, raw)
	}
	e := body.Entries[0]
	if e.UpstreamStatus != 401 || e.UpstreamErrorType != "invalid_token" {
		t.Fatalf("上游证据没进本地环: %+v", e)
	}
	// 保密纪律：完整指纹不落盘——只留 12 字符前缀。
	if strings.Contains(string(raw), fullFingerprint) {
		t.Fatal("完整 fingerprint 落进了 auth-demotions.json——这份文件会被粘进工单")
	}
	if e.FingerprintPrefix != fullFingerprint[:12] {
		t.Fatalf("fingerprint 前缀不对: %q", e.FingerprintPrefix)
	}
}

func TestDemotionRingIsCappedAndKeepsNewest(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	ring := &authDemotionsRing{nowMs: func() int64 { return time.Now().UnixMilli() }}
	for i := 0; i < maxAuthDemotions+5; i++ {
		ring.record(authDemotionEntry{AtMs: int64(i), CredentialID: "c", SeatID: "s"})
	}
	raw, err := os.ReadFile(filepath.Join(os.Getenv("AIKEY_RUN_DIR"), authDemotionsFilename))
	if err != nil {
		t.Fatal(err)
	}
	var body authDemotionsBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Entries) != maxAuthDemotions {
		t.Fatalf("环没有封顶: %d", len(body.Entries))
	}
	if body.Entries[len(body.Entries)-1].AtMs != int64(maxAuthDemotions+4) {
		t.Fatal("环丢的不是最旧的一批")
	}
}
