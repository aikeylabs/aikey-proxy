package proxy

// auth-demotions.json — 硬吊销判定的本地环形记录（远程诊断用，2026-09-01）。
//
// 🔴 为什么需要它：硬吊销的上报 outbox 在 Master 接受后即压缩清除——**成功上报
// 的记录在客户端一条不留**。于是「登录成功→一会儿变登录失效」这类现场（2026-08-31
// 客户实例）里，最关键的一手证据（proxy 什么时候、因为上游说了什么，把哪把 token
// 判了死刑）在客户机器上无处可查，远程诊断只能靠猜。
//
// 这个环把每次硬吊销判定连同**有界上游证据**留在本地，`aikey doctor` 一条命令
// 就能收走。与 last-errors.json 同一套形态（环形、原子写、best-effort）。
//
// 保密纪律（同 2026-08-19 Claude 分类器）：不含 token、不含响应体、不含消息原文。
// fingerprint 本身已是 SHA-256，仍只留前 12 字符——诊断只需要「同一把 / 不同把」。
//
// bugfix: workflow/CI/bugfix/2026-09-01-auth-failure-demotion-discards-upstream-evidence.md

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

const (
	authDemotionsFilename = "auth-demotions.json"
	maxAuthDemotions      = 20
)

type authDemotionEntry struct {
	AtMs              int64  `json:"at_ms"`
	CredentialID      string `json:"credential_id"`
	SeatID            string `json:"seat_id"`
	UpstreamStatus    int    `json:"upstream_status,omitempty"`
	UpstreamErrorType string `json:"upstream_error_type,omitempty"`
	// FingerprintPrefix 让远程诊断能回答「反复被吊销的是不是同一把 token」，
	// 又不足以反推任何材料。
	FingerprintPrefix string `json:"fingerprint_prefix,omitempty"`
}

type authDemotionsBody struct {
	Entries   []authDemotionEntry `json:"entries"`
	WrittenAt int64               `json:"written_at"`
}

type authDemotionsRing struct {
	mu      sync.Mutex
	entries []authDemotionEntry
	nowMs   func() int64
}

var authDemotions = &authDemotionsRing{nowMs: nowUnixMilli}

func authDemotionsPath() (string, error) {
	if dir := os.Getenv("AIKEY_RUN_DIR"); dir != "" {
		return filepath.Join(dir, authDemotionsFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aikey", "run", authDemotionsFilename), nil
}

func fingerprintPrefix(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}

func (r *authDemotionsRing) record(e authDemotionEntry) {
	r.mu.Lock()
	r.entries = append(r.entries, e)
	if len(r.entries) > maxAuthDemotions {
		r.entries = r.entries[len(r.entries)-maxAuthDemotions:]
	}
	snapshot := make([]authDemotionEntry, len(r.entries))
	copy(snapshot, r.entries)
	r.mu.Unlock()
	r.persist(snapshot)
}

func (r *authDemotionsRing) persist(entries []authDemotionEntry) {
	path, err := authDemotionsPath()
	if err != nil {
		return
	}
	data, err := json.Marshal(authDemotionsBody{Entries: entries, WrittenAt: r.nowMs()})
	if err != nil {
		return
	}
	if err := func() error {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return mkErr
		}
		tmp := path + ".tmp"
		if wErr := os.WriteFile(tmp, data, 0o600); wErr != nil {
			return wErr
		}
		return os.Rename(tmp, path)
	}(); err != nil {
		slog.Warn("auth-demotions state file update failed — `aikey doctor` may miss recent demotions",
			"event.name", "proxy.auth_demotions.file_failed", "error", err.Error())
	}
}
