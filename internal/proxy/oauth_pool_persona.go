// oauth_pool_persona.go — NP-1: AccountPersona identity normalization for
// seat_group POOL accounts (the §3.1 防封 floor for safe account pooling).
//
// THE PROBLEM (design 20260624-动态决策账号分配引擎-技术方案.md §3.1): Anthropic
// clusters abuse by account_uuid. Every inference request is forced to carry
// metadata.user_id = {device_id, account_uuid, session_id} plus X-Stainless-OS/
// Arch + a CLI User-Agent. If N employees share ONE pool account, their N real
// device_ids / N sessions / mixed OS-arch all reach Anthropic under one
// account_uuid → "一号多设备 + session 暴涨" → ban within days (exactly what the
// customer fears). The proxy is the only place that can collapse them.
//
// THE FIX: when the credential is a pool account (cred.Pooled), collapse the
// identity onto ONE per account — device_id = SHA256(accountID), one session,
// one OS/arch/UA — UNCONDITIONALLY (override the client's own values, vs
// injectClaudeOAuth's setIfAbsent which a real Claude Code client bypasses).
//
// SCOPE (NP-1): device + session collapse + OS/arch/UA lock. NP-2 replaces the
// constant per-account session with a 15-min rolling masked session (real
// sessions rotate; a forever-constant one is itself a weak signal). Per-account
// VARIATION of OS/arch/UA (anti-"千人一面" account-farm risk, §3.2.1) is
// deliberately NOT done here: this exact persona combo is the WAF-verified one
// (oauth_inject.go research), and shipping unverified header combos risks 429s.
// Cross-account differentiation needs its own WAF spike first — tracked as a
// follow-up, not silently skipped.
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
)

// poolPersonaCtx is the minimal pool-account identity the Director needs to
// disguise the OUTBOUND request. Stashed on the request context by a pool-
// routing site (e.g. handleSeatGroupRoute); consumed once in serveRoute's
// Director. Kept tiny so it carries no secret material.
type poolPersonaCtx struct {
	accountID  string
	externalID string
}

// stashPoolPersona marks a request as a pooled anthropic account so the Director
// applies the AccountPersona disguise to the OUTBOUND clone — NOT the original
// r. The original keeps the real employee identity (session / X-Stainless /
// metadata) so our usage events, conversation audit, and filter cache attribute
// the real conversation, while Anthropic sees the per-account normalized
// identity. Returns the request carrying the stash. (NP-4: the fix for the
// in-place collapse bleeding into our own session-keyed logic.)
func stashPoolPersona(r *http.Request, accountID, externalID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyPoolPersona,
		&poolPersonaCtx{accountID: accountID, externalID: externalID}))
}

// applyPoolPersonaFromContext applies the pool disguise to the outbound clone
// when the request was stashed as pooled. Called from the Director; a plain
// no-op (one type-assert) for every non-pool request.
func applyPoolPersonaFromContext(req *http.Request) {
	if pp, ok := req.Context().Value(ctxKeyPoolPersona).(*poolPersonaCtx); ok && pp != nil {
		applyPoolPersona(req, pp.accountID, pp.externalID)
	}
}

// poolPersona is one COHERENT, real-world Claude Code platform fingerprint. A
// pool account is pinned to exactly one of these (chosen by hash of accountID),
// so every employee on that account presents the SAME machine identity while
// DIFFERENT accounts present DIFFERENT machines — defeating the cross-account
// "千人一面" account-farm signal (§3.2.1 / 附录C: 归一字段以 SHA256(accountID)
// 派生保持账号间差异) without leaking any individual employee's real fingerprint.
//
// WAF SAFETY: every tuple is a genuine Claude Code platform — real Mac/Linux/
// Windows installs send these and pass the OAuth WAF daily — so per-account
// variation across them is safe: the WAF cannot reject by OS/arch/runtime/CLI
// version without blocking real users. The values pair Stainless-format OS/arch
// (MacOS/Linux/Windows × arm64/x64) with real node LTS + recent claude-cli/SDK
// versions. Keep these CURRENT as Claude Code releases move (stale versions are
// the only realistic drift risk; refresh on SDK/CLI bumps).
type poolPersona struct {
	os, arch       string // X-Stainless-OS / -Arch (Stainless casing)
	runtimeVersion string // X-Stainless-Runtime-Version (node LTS)
	cliVersion     string // claude-cli/<v> User-Agent
	pkgVersion     string // X-Stainless-Package-Version (@anthropic-ai/sdk)
}

var poolPersonas = []poolPersona{
	{"MacOS", "arm64", "v22.14.0", "2.1.22", "0.70.0"},
	{"MacOS", "x64", "v20.18.1", "2.1.20", "0.68.0"},
	{"Linux", "x64", "v24.13.0", "2.1.22", "0.70.0"},
	{"Linux", "arm64", "v22.11.0", "2.1.21", "0.69.0"},
	{"Windows", "x64", "v22.12.0", "2.1.22", "0.70.0"},
	{"MacOS", "arm64", "v20.18.2", "2.1.19", "0.67.0"},
	{"Linux", "x64", "v22.14.0", "2.1.21", "0.69.0"},
	{"MacOS", "x64", "v24.13.0", "2.1.22", "0.70.0"},
}

// personaForAccount deterministically pins an account to one persona. Stable for
// a given account (collapse) and spread across the table by accountID (per-
// account difference). A separate hash domain from device/session keeps the
// three derivations independent.
func personaForAccount(accountID string) poolPersona {
	h := sha256.Sum256([]byte("aikey-pool-persona:" + accountID))
	idx := binary.BigEndian.Uint32(h[:4]) % uint32(len(poolPersonas))
	return poolPersonas[idx]
}

// applyPoolPersona disguises ONE request as the pool account's normalized
// identity. It mutates the request it is given — in the NP-4 design that is the
// OUTBOUND clone inside serveRoute's Director, so the original r keeps the real
// employee identity. anthropic-only (it injects the Claude persona); Codex/Kimi
// never pool (封板 P10).
func applyPoolPersona(req *http.Request, accountID, externalID string) {
	// 1. Lock the FULL machine + CLI + SDK fingerprint to this account's pinned
	//    persona — UNCONDITIONAL (a real Claude Code client sets its own; leaving
	//    them would let each employee's real OS/arch/version leak as device
	//    variety). Per-account-derived so accounts differ (anti-千人一面).
	p := personaForAccount(accountID)
	req.Header.Set("User-Agent", "claude-cli/"+p.cliVersion+" (external, cli)")
	req.Header.Set("X-Stainless-OS", p.os)
	req.Header.Set("X-Stainless-Arch", p.arch)
	req.Header.Set("X-Stainless-Runtime", "node")
	req.Header.Set("X-Stainless-Runtime-Version", p.runtimeVersion)
	req.Header.Set("X-Stainless-Package-Version", p.pkgVersion)

	// 2. Collapse device + session to ONE per account. device_id reuses the
	//    existing per-account primitive (SHA256(accountID), stable across users +
	//    proxies); session is the rolling masked session (NP-2) so N employees'
	//    N sessions → 1 while still rotating like a real session.
	deviceHash := sha256.Sum256([]byte(accountID))
	deviceID := hex.EncodeToString(deviceHash[:])
	sessionID := defaultPoolSessions.sessionID(accountID)
	req.Header.Set("X-Claude-Code-Session-Id", sessionID)

	// 3. Override metadata.user_id UNCONDITIONALLY — it is the device_id +
	//    session carrier the upstream actually clusters on. A real Claude Code
	//    client sets its own, so leaving it would leak the employee's real device.
	userID := fmt.Sprintf("user_%s_account_%s_session_%s", deviceID, externalID, sessionID)
	setMetadataUserID(req, userID)
}

// poolSessionID derives a stable, account-scoped session id (UUID-shaped) from
// the account id. Since NP-2 it is the CSPRNG-failure FALLBACK for the rolling
// masked session (newMaskedSessionID) — deterministic so the account still
// collapses to one session even if the random source is unavailable.
func poolSessionID(accountID string) string {
	h := sha256.Sum256([]byte("aikey-pool-session:" + accountID))
	return uuidFromBytes(h[:])
}

// uuidFromBytes formats 16 bytes as a v4-shaped UUID string (deterministic — the
// caller supplies the entropy, here a hash, so the same account → same UUID).
func uuidFromBytes(b []byte) string {
	var u [16]byte
	copy(u[:], b)
	u[6] = (u[6] & 0x0f) | 0x40 // version 4 nibble
	u[8] = (u[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// setMetadataUserID unconditionally sets body.metadata.user_id (vs
// injectMetadataUserIDIfAbsent). Reuses mutateJSONBody for the same body-safety
// guarantees (Body + ContentLength stay in sync; original restored on error).
func setMetadataUserID(req *http.Request, userID string) {
	mutateJSONBody(req, func(body map[string]any) bool {
		metadata, ok := body["metadata"].(map[string]any)
		if !ok {
			metadata = make(map[string]any)
		}
		metadata["user_id"] = userID
		body["metadata"] = metadata
		return true
	})
}
