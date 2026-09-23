// group_resolve.go — N8a: oauth-group credential resolver (pure, no I/O).
//
// Given a resolved group VK route (route.OauthGroupID != ""), this picks one
// candidate account for the request and produces the credential to inject:
//
//	route.GroupAccounts  (candidate set, ranking inputs + identity, NO secrets)
//	route.GroupRuntime   (per-account encrypted material, written by N7c-2)
//	        │
//	        ├─ seatassign.Rank(route.SeatID, candidates)   ← byte-identical to master
//	        ├─ first usable candidate (has material, not expired/exhausted)
//	        ├─ base64-decode + vault.Decrypt the secret with the vault key
//	        └─ build *groupResolution (OAuthCredential | plaintext key)
//
// This function is deliberately side-effect free (no vault read, no HTTP, no
// header mutation) so it is fully unit-testable. The hot-path wiring that calls
// it + mutates the request lives in N8b (handle_dispatch), behind the
// oauth-group feature flag. Direct-bind / personal routes never reach here.
//
// SECURITY: the decrypted secret exists only in the returned struct's memory;
// it is never logged. Ranking MUST match master's snapshot.GroupAccountRef
// ordering (seatassign.Account{AccountID, Priority}, Weight unset = 1).
package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/seatassign"
)

// Credential types in the group material contract (match master + N7c-2 writer).
const (
	credTypeOAuth = "oauth_account"
	credTypeKey   = "api_key"
)

// Resolution failure codes (mapped to HTTP responses by the N8b caller).
const (
	groupErrNoCandidates = "GROUP_NO_CANDIDATES" // route has no parseable candidate set
	groupErrNoMaterial   = "GROUP_NO_MATERIAL"   // group_runtime empty/unparseable (not pulled yet)
	groupErrAllUnusable  = "GROUP_ALL_UNUSABLE"  // every candidate expired / exhausted / undecryptable
	// groupErrLoginRequired (RW2, per-member): NO candidate is serviceable and at
	// least one is waiting on a member login; the caller returns a structured
	// login prompt naming groupResolveError.Account so the member logs into THAT
	// account. Semantics are 2026-08-15 方案 b (supersedes the D2 "walk stops at
	// the routed account" rule): a needs_login candidate never blocks while a
	// healthy logged-in sibling can serve — this code surfaces only when the
	// whole pool is unserviceable for this member (see vkeys.PickRoutedAccount
	// + property fences P1–P6 + spec R27).
	groupErrLoginRequired = "OAUTH_GROUP_MEMBER_LOGIN_REQUIRED"
)

// pick_source values (方案 20260819 P0-2 S4): who decided the served account.
// Value enum lives next to its producer (sched_event_report.go origin precedent);
// it rides slog + scheduling-event detail only — NOT a filterable column (upgrade
// per the origin-column precedent if filtering is ever needed). A true "sticky"
// value is deliberately absent: engine binding_state does not cross routingwire,
// so the proxy cannot write it — declaring it would be a signal with no writer.
// needs_login is likewise absent: that outcome never settles a route (it is the
// distinct proxy.group.login_required error event instead).
const (
	pickSourceEngineOverride      = "engine_override"       // engine redirected off the local rank-0
	pickSourceOverrideConfirmsHRW = "override_confirms_hrw" // engine pick coincides with local rank-0
	pickSourceLocalHRW            = "local_hrw"             // no usable override — local floor served rank-0
	pickSourceLocalFallback       = "local_fallback"        // ranked walk advanced past override and rank-0
	// pickSourceDeviceLedger: the control plane's DEVICE LEDGER named the account
	// (device-routing token, 4.5's strict branch). It is not produced by
	// classifyPickSource above — that function only knows where the account sits
	// in this seat's local rank, which for a pinned account is an accident of
	// hashing and says nothing about who decided. Written once, at its source:
	// resolveGroupCredential (this file, :247) — Ruling-24, 2026-09-22.
	// noteSchedRouteSettled (sched_event_report.go) only READS it afterward; see
	// that function's own comment for why rewriting it there was removed.
	// spec: R-device-routing-token-dispatch-19.S5
	pickSourceDeviceLedger = "device_ledger"
)

// classifyPickSource labels the served account's decision provenance from the
// three values the resolver already holds. Pure so the fence test can pin the
// truth table.
func classifyPickSource(served, primary, override string) string {
	switch {
	case override != "" && served == override && served != primary:
		return pickSourceEngineOverride
	case override != "" && served == override:
		return pickSourceOverrideConfirmsHRW
	case served == primary:
		return pickSourceLocalHRW
	default:
		return pickSourceLocalFallback
	}
}

// groupResolveError is a typed resolver failure so the caller can map a precise
// HTTP status + error code without string matching.
type groupResolveError struct {
	Code   string
	Reason string
	// Account is set for groupErrLoginRequired: the account the member must log
	// into (the caller builds the login URL from it).
	Account string
}

func (e *groupResolveError) Error() string { return e.Code + ": " + e.Reason }

// groupResolution is the chosen account + its decrypted credential for one
// request. Exactly one of OAuth / PlaintextKey is meaningful, per CredentialType.
type groupResolution struct {
	AccountID      string
	CredentialID   string // real credential_id of the chosen account → route.CredentialID for I5 signal reporting (T2 uplink)
	CredentialType string // "oauth_account" | "api_key"
	ProviderCode   string // candidate's resolved provider code (oauthInject dispatch)
	ProtocolType   string // independent wire-protocol axis
	Identity       string // display / audit only — never sent upstream
	// Primary is the seat's rank-0 account (seatassign top pick). When it differs
	// from AccountID, a fallback happened (the primary was cooled / exhausted /
	// expired / has no material) — the caller audits the switch (N9 #8).
	Primary string
	// PickSource labels WHO decided AccountID (方案 20260819 P0-2 S4) — one of the
	// pickSource* constants below. Rides slog + scheduling-event detail so ops can
	// tell engine-authoritative routing from the local HRW floor after the fact.
	PickSource string

	// oauth_account: header injection via oauthInject(req, OAuth, ProviderCode).
	OAuth *OAuthCredential
	// api_key: realKey + optional per-account upstream base URL.
	PlaintextKey string
	BaseURL      string
	Revision     string
	// WindowMaxUtilPct is the legacy-compatible 5h cap (93-97);
	// Window7dMaxUtilPct is the independent weekly cap (87-89).
	WindowMaxUtilPct   *int
	Window7dMaxUtilPct *int
	// EgressProxyURL is the chosen account's optional per-account egress proxy
	// (§11.7, P7). "" → node-level egress applies. Non-secret; carried so the
	// caller can pin this account's outbound to its own exit IP.
	EgressProxyURL string
	// IdentityKey is the chosen account's Codex identity-rewrite key (32 raw
	// bytes) — either the one the control plane delivered or this node's
	// fallback derivation. Never empty on a resolved route, never logged.
	// spec: R-codex-identity-rewrite-4
	IdentityKey []byte
}

// resolveGroupCredential ranks the route's group candidates for route.SeatID and
// returns the first usable account's decrypted credential. `nowUnix` is the
// caller's clock (injected for deterministic tests); `derivedKey` is the vault
// key used to decrypt the at-rest material. `skip` (may be nil) names accounts
// the caller already tried this request — used by N8c fallback to advance past a
// candidate the upstream just rejected. `overrideAccountID` (may be "") is the
// allocation engine's seat→account routing override (I-side §6.5): when the
// engine has redirected this seat off an unhealthy default, the caller passes the
// engine's healthy pick here.
//
// A candidate is skipped when: it has no material in group_runtime (not pulled
// yet), its OAuth token is expired, its quota window is exhausted, or its secret
// fails to decrypt (corrupt). If every candidate is skipped → GROUP_ALL_UNUSABLE.
func resolveGroupCredential(route *vkeys.ResolvedRoute, derivedKey []byte, nowUnix int64, skip map[string]bool, overrideAccountID string) (*groupResolution, error) {
	refs, material, err := groupCandidates(route)
	if err != nil {
		return nil, err
	}

	// Rank exactly as master does: Account{AccountID, Priority}, Weight unset.
	accounts := make([]seatassign.Account, 0, len(refs))
	refByID := make(map[string]vkeys.GroupAccountRef, len(refs))
	for _, r := range refs {
		accounts = append(accounts, seatassign.Account{AccountID: r.AccountID, Priority: r.Priority})
		refByID[r.AccountID] = r
	}
	ordered := seatassign.Rank(route.SeatID, accounts)
	primary := ordered[0].AccountID // rank-0; audited when the actual pick differs
	assigned := primary
	if overrideAccountID != "" {
		if _, ok := refByID[overrideAccountID]; ok {
			assigned = overrideAccountID
		}
	}

	// SINGLE SOURCE OF TRUTH (2026-07-01): the pick — engine override first (§6.5,
	// member-validity re-checked), else the local ranked pick — is
	// vkeys.PickRoutedAccount, the SAME function the display stamp
	// (supervisor.computeRoutedAccountID → /user/vault current_routed) uses. Do
	// NOT re-derive routing here; forwarding and display must agree by construction.
	//
	// needs_login semantics (2026-08-15 方案 b, supersedes the 2026-07-01 owner rule
	// that HONORED a needs_login override immediately): a needs_login candidate —
	// override included — no longer blocks the request; healthy candidates serve
	// first and the needs_login target survives only as the login PROMPT when
	// nothing is serviceable. The rule lives inside PickRoutedAccount (see its
	// header + vkeys property fences P1–P6 + spec R27); this note exists because
	// the old wording here already misled one external review (2026-08-18).
	//
	// The only hot-path-extra gate is DECRYPT (needs the vault key, so it can't be in
	// the pure picker): a corrupt secret adds the account to the skip set and re-picks,
	// preserving the old "corrupt material never fails the request" resilience.
	localSkip, cloned := skip, false
	for {
		acc, oc := vkeys.PickRoutedAccount(route.SeatID, refs, material, overrideAccountID, localSkip, nowUnix)
		switch oc {
		case vkeys.PickNeedsLogin:
			// RW2/D2: the first non-skipped routed account has no member token. The
			// caller decides whether its skip set is durable/global (actionable login)
			// or only request-local (preserve the captured upstream error). Keeping that
			// policy out of this resolver lets display and forwarding share this pick.
			return nil, &groupResolveError{Code: groupErrLoginRequired,
				Reason: "member has no token for the routed account — login required", Account: acc}
		case vkeys.PickOK:
			mat := material[acc]
			secret, err := decryptGroupSecret(derivedKey, mat)
			if err != nil {
				// corrupt material — route around it, don't fail the request. Clone the
				// caller's skip set once (never mutate the shared cooldown view).
				if !cloned {
					clone := make(map[string]bool, len(skip)+1)
					for k, v := range skip {
						clone[k] = v
					}
					localSkip, cloned = clone, true
				}
				localSkip[acc] = true
				continue
			}
			res := buildGroupResolution(acc, refByID[acc], mat, secret)
			res.Primary = primary
			res.PickSource = classifyPickSource(acc, primary, overrideAccountID)
			// THE one place pick_source is written (Ruling-24, 2026-09-22). For a
			// device-routing token the override is not an engine decision at all —
			// it is the control plane's device ledger, arriving through the same
			// parameter. classifyPickSource above can only see WHERE the account
			// sits in this seat's hash order, which for a pinned account is an
			// accident and names the wrong decider. Overriding here (rather than
			// at each consumer) is what keeps the slog line, the off-rank-0 audit
			// and the scheduling event showing the same value for one request.
			// Reaching this point with this route kind implies the strict branch
			// admitted the request (the other device-routing modes refuse before
			// resolve), so no second discriminator is needed.
			// spec: R-device-routing-token-dispatch-19.S5
			if route.RouteKind == routeKindDeviceRoutingToken {
				res.PickSource = pickSourceDeviceLedger
			}
			// spec: R-codex-identity-rewrite-4 每个被选中的账号都必须带上一把改写
			// 密钥（下发的，或本机降级派生的）——resolve 成功后才派，因为它是「这次
			// 请求实际用哪个账号」的属性，不是候选集的属性。
			res.IdentityKey = resolveIdentityKey(derivedKey, acc, mat)
			return res, nil
		default: // PickNone
			// R36 (2026-07-04, codex pools): expiry is member-fixable, but only the
			// assigned account is an actionable re-login target. Never promote an
			// expired request-level fallback to LOGIN_REQUIRED.
			if !localSkip[assigned] {
				m, ok := material[assigned]
				if ok && vkeys.MaterialExpired(m, nowUnix) && !vkeys.MaterialWindowBlockedAt(m, nowUnix) {
					return nil, &groupResolveError{Code: groupErrLoginRequired,
						Reason: "member token for the routed account expired — re-login required", Account: assigned}
				}
			}
			return nil, &groupResolveError{Code: groupErrAllUnusable, Reason: "all group candidates expired, exhausted, or undecryptable"}
		}
	}
}

// (resolveCandidate / materialUsable were absorbed into vkeys.PickRoutedAccount /
// vkeys.MaterialUsable — the shared pure pick used by BOTH this hot path and the
// supervisor's display stamp. 2026-07-01 single-source-of-truth unification.)

// groupCandidates parses a group route into the candidate set + material view
// the pick ranks over. Extracted from resolveGroupCredential (zero behavior
// change) so the device-routing strict gate classifies the pinned account
// against the SAME merged view the picker will see: if the gate used the raw
// candidate snapshot instead, "is it even a candidate" could answer differently
// in the two places and the strict branch would either refuse a servable account
// or hand PickRoutedAccount an override it then walks past.
//
// Distinguish "not pulled yet" from "pulled → nothing for this seat" (2026-06-30):
//
//	""       → the channel-③ poll hasn't landed → NO_MATERIAL (retry DOES help).
//	bad JSON → treat as not-ready → NO_MATERIAL (retry).
//	"{}"     → the proxy DID pull and this seat's group delivered NO accounts:
//	           the member was unbound/removed (access gate wiped it to "{}"), or
//	           the group has no enabled accounts → NO_CANDIDATES: retrying will
//	           NOT help, the member must contact an admin. The candidate snapshot
//	           (group_accounts) may still be STALE with entries — the material rail
//	           (proxy 60s) is fresher than on-demand key sync, so trust "{}" over
//	           stale candidates here. WHY: a removed member was shown "credentials
//	           still syncing, retry shortly" forever — the message told them to
//	           retry when only an admin re-adding the seat can fix it.
func groupCandidates(route *vkeys.ResolvedRoute) ([]vkeys.GroupAccountRef, map[string]vkeys.GroupRuntimeAccount, error) {
	var refs []vkeys.GroupAccountRef
	if route.GroupAccounts != "" {
		_ = json.Unmarshal([]byte(route.GroupAccounts), &refs)
	}
	if route.GroupRuntime == "" {
		return nil, nil, &groupResolveError{Code: groupErrNoMaterial, Reason: "group_runtime not pulled yet"}
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(route.GroupRuntime), &material); err != nil {
		return nil, nil, &groupResolveError{Code: groupErrNoMaterial, Reason: "group_runtime unparseable — treat as not-ready"}
	}
	if len(material) == 0 {
		return nil, nil, &groupResolveError{Code: groupErrNoCandidates, Reason: "group_runtime delivered no accounts for this seat (unbound/removed member or empty group)"}
	}
	refs = vkeys.MergeLiveGroupAccountRefs(refs, material)
	if len(refs) == 0 {
		return nil, nil, &groupResolveError{Code: groupErrNoCandidates, Reason: "group_runtime contained no valid candidate accounts"}
	}
	return refs, material, nil
}

// ── device-routing token: the strict branch's decisions (pure) ──────────────

// deviceRoutingMode is what the (route kind, internal header) pair means for one
// request. Four cases, and three of them are refusals — the pair can disagree in
// both directions during a rolling upgrade, and BOTH directions have to fail
// loudly: the header-writing chain has already lost a hop once (the ingress
// cache-hit path, 4.4), and a request that silently takes the seat path is
// indistinguishable from a healthy one.
type deviceRoutingMode int

const (
	// deviceRoutingModeOff — an ordinary seat pool route with no internal
	// header: byte-identical to the behavior before this branch existed.
	deviceRoutingModeOff deviceRoutingMode = iota
	// deviceRoutingModeStrict — a device-routing route WITH a decision: serve
	// exactly that account or refuse.
	deviceRoutingModeStrict
	// deviceRoutingModeNoDecision — a device-routing route WITHOUT a decision
	// (old ingress). 503 NO_DECISION; never pick locally.
	deviceRoutingModeNoDecision
	// deviceRoutingModeKindMissing — a decision arrived for a route this worker
	// does not know to be a device-routing route (rolled-back cluster daemon, or
	// an inbound forgery on the unauthenticated cluster port).
	// 503 NODE_UNSUPPORTED; never ignore the header and serve normally.
	deviceRoutingModeKindMissing
)

// deviceRoutingClassifyRequest is the whole (kind, header) truth table in one
// place, so the serving path has no nested conditionals to get subtly wrong.
//
// spec: R-device-routing-token-dispatch-7.S3 类别是设备路由 ∧ 头缺失 → NO_DECISION
// spec: R-device-routing-token-dispatch-20.S2 头存在 ∧ 类别不是设备路由 → NODE_UNSUPPORTED
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
func deviceRoutingClassifyRequest(routeKind, pinnedAccount string) deviceRoutingMode {
	isDeviceRoute := routeKind == routeKindDeviceRoutingToken
	switch {
	case isDeviceRoute && pinnedAccount != "":
		return deviceRoutingModeStrict
	case isDeviceRoute:
		return deviceRoutingModeNoDecision
	case pinnedAccount != "":
		return deviceRoutingModeKindMissing
	default:
		return deviceRoutingModeOff
	}
}

// deviceRoutingPinnedState classifies the pinned account's own state for this
// request. Pure apart from parsing the route it is handed.
//
// `cooling` and `authRevoked` MUST arrive as the two SEPARATE skip sets: the
// serving path merges them for the picker, and a merged boolean set can no
// longer tell "the window is closed" (429, recovers by itself) from "the token
// was rejected" (503, the control plane must rebind).
//
// spec: R-device-routing-token-dispatch-7.S4
func deviceRoutingPinnedState(
	route *vkeys.ResolvedRoute, pinnedAccount string,
	cooling, authRevoked map[string]bool, nowUnix int64,
) vkeys.OverrideState {
	refs, material, err := groupCandidates(route)
	if err != nil {
		// No parseable material at all — from the pinned account's point of view
		// that is exactly "my material has not arrived", which is what the
		// not-ready 503 says. The seat path's NO_MATERIAL / NO_CANDIDATES split
		// is about whether an ADMIN must act for a member; a device-routing token
		// has no member to send anywhere.
		return vkeys.OverrideMaterialNotReady
	}
	return vkeys.ClassifyOverride(refs, material, pinnedAccount, cooling, authRevoked, nowUnix)
}

// groupWindowResetAt returns the earliest authoritative window reset among the
// account's exhausted windows, for the 429's retry horizon. (false) when the
// material names no reset — master snapshots may carry a legacy exhausted value
// with no deadline, and inventing one would promise a recovery time nothing
// backs.
func groupWindowResetAt(groupRuntime, accountID string) (int64, bool) {
	if groupRuntime == "" || accountID == "" {
		return 0, false
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(groupRuntime), &material); err != nil {
		return 0, false
	}
	mat, ok := material[accountID]
	if !ok {
		return 0, false
	}
	earliest := int64(0)
	consider := func(status string, resetAt *int64) {
		if !vkeys.WindowExhausted(status) || resetAt == nil || *resetAt <= 0 {
			return
		}
		if earliest == 0 || *resetAt < earliest {
			earliest = *resetAt
		}
	}
	consider(mat.WindowStatus, mat.WindowResetAt)
	consider(mat.Window7dStatus, mat.Window7dResetAt)
	return earliest, earliest > 0
}

// decryptGroupSecret base64-decodes the nonce + ciphertext and AES-GCM decrypts
// the secret with the vault key.
func decryptGroupSecret(derivedKey []byte, mat vkeys.GroupRuntimeAccount) (string, error) {
	nonce, err := base64.StdEncoding.DecodeString(mat.SecretNonce)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(mat.SecretCiphertext)
	if err != nil {
		return "", err
	}
	pt, err := vault.Decrypt(derivedKey, nonce, ct)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// ── per-account Codex identity-rewrite key (spec: R-codex-identity-rewrite-4) ──

// identityKeyNodeInfoPrefix is the fallback derivation's domain separator. It is
// deliberately DIFFERENT from the control plane's label
// ("aikey/codex-identity/v1/"): the two derivations use different key material
// (MASTER_KEY vs this node's vault key) and different ids (credential_id vs
// account_id), so distinct labels keep the two families from ever colliding.
const identityKeyNodeInfoPrefix = "aikey/codex-identity/v1/node/"

// identityKeyFallback tracks accounts currently served on a locally derived key.
//
// `active` is a SET of account ids, not a counter: it self-heals — an account
// drops out the moment its material arrives with a key again, so the CRIT
// clears with no proxy restart. `total` is the lifetime count and is for
// diagnosis only, never for alerting. Same split and the same semantics as
// cluster.DeviceRoutingTokenStats' route_kind_missing_active / _total.
var identityKeyFallback = struct {
	mu     sync.Mutex
	active map[string]struct{}
	total  int64
}{active: map[string]struct{}{}}

// IdentityKeyHealth is the externally readable identity-key degradation signal,
// reported under /status pool_routing (and forwarded to the hub inside the
// cluster heartbeat's pool_routing section — one surface, all four editions).
//
// MissingActive > 0 means CRIT, not WARN: every request for those accounts is
// being rewritten under a key that only THIS node can produce, so the same
// account presents a different identity on every other node — the linkage the
// rewrite exists to remove is partially back, and no request has failed to say
// so. Field names are the health-signal contract's dotted names verbatim.
type IdentityKeyHealth struct {
	MissingActive int64 `json:"identity_key_missing_active"`
	MissingTotal  int64 `json:"identity_key_missing_total"`
}

// IdentityKeyFallbackSnapshot reads the counters for the health surface.
func IdentityKeyFallbackSnapshot() IdentityKeyHealth {
	identityKeyFallback.mu.Lock()
	defer identityKeyFallback.mu.Unlock()
	return IdentityKeyHealth{
		MissingActive: int64(len(identityKeyFallback.active)),
		MissingTotal:  identityKeyFallback.total,
	}
}

func markIdentityKeyMissing(accountID string) {
	identityKeyFallback.mu.Lock()
	defer identityKeyFallback.mu.Unlock()
	identityKeyFallback.total++
	identityKeyFallback.active[accountID] = struct{}{}
}

func clearIdentityKeyMissing(accountID string) {
	identityKeyFallback.mu.Lock()
	defer identityKeyFallback.mu.Unlock()
	delete(identityKeyFallback.active, accountID)
}

// resolveIdentityKey returns the 32-byte rewrite key for one account.
//
// spec: R-codex-identity-rewrite-4 密钥缺失时用「本机密钥 + 账号编号」派生降级，
// 健康信号升 CRIT，MUST NOT 原样透传
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
//
// It NEVER returns empty. The rewrite must always have a seed: with no key the
// only remaining behaviors would be to pass the client's real identifiers
// upstream (the linkage this feature removes) or to fail the request (an outage
// caused by a side feature). Degrading to a node-local key keeps the request
// serving AND keeps the identifiers off the wire; the cost — this node's values
// differ from every other node's for that account — is what the CRIT reports.
//
// Undecryptable material is treated exactly like absent material: the account's
// token is still good, so a corrupt key must not take the route down.
func resolveIdentityKey(derivedKey []byte, accountID string, mat vkeys.GroupRuntimeAccount) []byte {
	if key, ok := decryptIdentityKey(derivedKey, mat); ok {
		clearIdentityKeyMissing(accountID)
		return key
	}
	markIdentityKeyMissing(accountID)
	return deriveNodeIdentityKey(derivedKey, accountID)
}

func decryptIdentityKey(derivedKey []byte, mat vkeys.GroupRuntimeAccount) ([]byte, bool) {
	if mat.IdentityKeyNonce == "" || mat.IdentityKeyCiphertext == "" {
		return nil, false
	}
	nonce, err := base64.StdEncoding.DecodeString(mat.IdentityKeyNonce)
	if err != nil {
		return nil, false
	}
	ct, err := base64.StdEncoding.DecodeString(mat.IdentityKeyCiphertext)
	if err != nil {
		return nil, false
	}
	pt, err := vault.Decrypt(derivedKey, nonce, ct)
	if err != nil || len(pt) == 0 {
		return nil, false
	}
	return pt, true
}

// deriveNodeIdentityKey is the fallback: HKDF-SHA256 over THIS node's vault key
// with the account id in the info label. Per-account (so two accounts on one
// node never share a value) and per-node (so it is not reproducible elsewhere,
// which is exactly why it is only a fallback). Same construction as the control
// plane's, different keying material — no second crypto scheme to review.
func deriveNodeIdentityKey(derivedKey []byte, accountID string) []byte {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, derivedKey, nil, []byte(identityKeyNodeInfoPrefix+accountID)), out); err != nil {
		// Unreachable with a healthy hash; a short read would be a weak key, so
		// fall back to the HMAC of the same label rather than returning zeros.
		mac := hmac.New(sha256.New, derivedKey)
		mac.Write([]byte(identityKeyNodeInfoPrefix + accountID))
		return mac.Sum(nil)
	}
	return out
}

// buildGroupResolution assembles the injectable credential for the chosen account.
func buildGroupResolution(accountID string, ref vkeys.GroupAccountRef, mat vkeys.GroupRuntimeAccount, secret string) *groupResolution {
	res := &groupResolution{
		AccountID:          accountID,
		CredentialID:       ref.CredentialID,
		CredentialType:     mat.CredentialType,
		ProviderCode:       ref.ProviderCode,
		ProtocolType:       ref.ProtocolType,
		Identity:           ref.Identity,
		WindowMaxUtilPct:   mat.WindowMaxUtilPct, // master's pre-cut cap (N10)
		Window7dMaxUtilPct: mat.Window7dMaxUtilPct,
		EgressProxyURL:     mat.EgressProxyURL, // per-account egress (§11.7, P7)
	}
	if res.CredentialID == "" {
		res.CredentialID = mat.CredentialID
	}
	if res.ProviderCode == "" {
		res.ProviderCode = mat.ProviderCode
	}
	if res.ProtocolType == "" {
		res.ProtocolType = mat.ProtocolType
	}
	// Runtime material is consumer-specific: a host member receives the public
	// URL while a cluster worker receives its internal URL. Prefer that fresh
	// rail over the structural candidate snapshot, which may still carry the
	// other environment's address during convergence.
	res.BaseURL = mat.BaseURL
	if res.BaseURL == "" {
		res.BaseURL = ref.BaseURL
	}
	if mat.CredentialType == credTypeKey {
		res.PlaintextKey = secret
		res.Revision = mat.Revision
		return res
	}
	// oauth_account → build the credential oauthInject consumes. The real client
	// identity flows upstream unchanged (transparent proxy); the former per-account
	// AccountPersona normalization was removed 2026-06-29 (see oauth_inject.go).
	res.OAuth = &OAuthCredential{
		AccessToken: secret,
		Provider:    res.ProviderCode,
		AccountID:   accountID,
		ExternalID:  mat.ExternalID, // Claude metadata.user_id (empty until master N7a fills it)
		Identity:    res.Identity,
		ExpiresAt:   mat.ExpiresAt,
	}
	return res
}

// groupAccountIdentity returns the human-facing identity (email / alias) of one
// account in the delivered group runtime material, or "" when the material is
// absent, unparseable, or carries no identity for that account.
//
// Why it exists (2026-09-03): every user-facing "you must sign in" surface named
// the account by UUID or not at all, while `identity` — explicitly documented as
// "display + audit only" — was sitting in the very material the resolver had just
// read. Returning "" rather than a placeholder keeps the caller honest: an older
// master that omits identity produces the previous generic wording instead of a
// confident-looking but useless UUID.
//
// bugfix: workflow/CI/bugfix/2026-09-03-登录提示不说是哪个账号.md
func groupAccountIdentity(groupRuntime, accountID string) string {
	if groupRuntime == "" || accountID == "" {
		return ""
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(groupRuntime), &material); err != nil {
		return ""
	}
	return strings.TrimSpace(material[accountID].Identity)
}
