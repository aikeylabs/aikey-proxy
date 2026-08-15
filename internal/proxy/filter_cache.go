// filter_cache.go — Per-session bounded content-hash cache for the inbound
// compliance filter (设计 20260616-AI合规检测-…-内容哈希缓存 §4, 用户 2026-06-16
// 改为 per-session 有界).
//
// WHY per-session-bounded (not one global LRU): the history-leak fix scans EVERY
// user message every turn, so a long conversation re-scans its history each turn.
// A cache memoizes per-message verdicts so identical content (history resent every
// turn) is scanned once. But a single GLOBAL LRU shared across all sessions lets a
// busy session/tenant evict a quiet one's entries (thrashing) and gives no
// per-session memory bound. So the cache is two levels:
//
//		{ sessionScope → LRU(window) of (version|contentHash → verdict) }
//
//	  - level 1: a session-LRU bounds the number of sessions (maxSessions).
//	  - level 2: per session, an LRU of the last `window` (default 5, env-tunable)
//	    piece verdicts — bounds per-session memory + matches "recent turns are what
//	    get resent". Older history beyond the window is re-scanned (≠ leaked: a
//	    re-scan still masks it), so correctness is unaffected; it just caches less.
//
// PLUGGABLE / ZERO-COST WHEN OFF (设计 §3.1, INV-6): lives behind the hook==nil
// early-return in applyInboundFilter; when the cache is off p.filterCache is nil
// and the dispatcher skips the hash entirely.
//
// ISOLATION / 不能串 (INV-3): the session scope is the level-1 key, so two
// sessions never share a bucket. scope = the resolved conversation session id where
// available (sessionid fingerprint table — cross-protocol, see cacheScope), else
// metadata.user_id, else the resolved virtual key.
//
// PACK FRESHNESS (INV-5): the level-2 key folds in BOTH the detector's binary
// version (a restart invalidates) and its live content-set epoch (an in-place
// pack swap invalidates), so a rule the admin just added or deleted takes effect
// on the next turn instead of waiting out a TTL. See cacheKey.
package proxy

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// maskVerdict is the cached outcome of scanning one content piece's head. Stores
// only the masked head + action — never the raw original. The v4 restorable
// metadata keeps that invariant: restorables carry OFFSETS into the piece head
// (plus the placeholder label parts), never the original span text — on a cache
// hit the dispatcher re-slices the CURRENT head, whose bytes are guaranteed
// identical by the content-hash key (B3 2026-08-08).
type maskVerdict struct {
	maskedHead string // present iff action == ActionMask (detector's NUMBERLESS token form)
	reason     string // for ActionBlock
	// event is the team-routed compliance audit event JSON the detector handed back
	// (apphook.Response.Event), replayed verbatim on a cache hit so a flagged piece
	// stays auditable on EVERY turn it is re-sent, not only the turn it was first
	// scanned (2026-08-08 审计缺口修复,用户拍板). Empty for personal routes (there the
	// detector uploads to its own local self-view and hands the proxy nothing) and for
	// clean pieces (the detector drops allow+0-findings events at source).
	//
	// Replaying the SAME bytes is what makes this safe to re-upload: the event_id
	// inside them is the detector's, minted once, and BOTH ingest paths are keyed on
	// it idempotently (control-master storage.IngestBatch: ON CONFLICT (event_id) DO
	// NOTHING; local user-local compliance ingest: ON CONFLICT(event_id) DO NOTHING).
	// So a replay reconciles a previously-FAILED upload instead of double-counting a
	// successful one — the 幂等对账读 for an event-driven write whose only other
	// outcome was a permanent audit gap. Content-free per DC5 (structural findings +
	// salted prompt_hash + planner-masked snippet), so caching it keeps maskVerdict's
	// "never store the raw original" invariant.
	event       []byte
	restorables []apphook.RestorableMask
	action      apphook.Action
}

// MaskCache memoizes per-piece scan verdicts, bucketed by session scope. Safe for
// concurrent use.
type MaskCache interface {
	Get(scope, key string) (maskVerdict, bool)
	Put(scope, key string, v maskVerdict)
}

// Defaults (window env-tunable; 用户 2026-06-16 全量存决策).
const (
	// defaultMaskCacheWindow — per-session cache size = how many piece verdicts to
	// retain per conversation. MUST be ≥ the user-message count in ONE request, else
	// LRU thrashes on the full-history re-scan: working-set > capacity + sequential
	// front-to-back access → ~0% hit (see TestFilterCache_PerfDetectCallReduction:
	// window=5 saved only 1% over 50 turns, window=50 saved 96%). 1000 is a generous
	// "store the whole conversation" bound (compaction caps real history well below
	// this) with a hard cap so a pathological session can't grow memory unbounded
	// (用户 2026-06-16: 上限 1000,非 unlimited). env-overridable.
	// NOT the loop count — the dispatch loop ALWAYS covers every user message (you
	// can't mask what you don't loop over); this only bounds verdict reuse.
	defaultMaskCacheWindow = 1000
	// defaultMaxSessions — level-1 bound: how many concurrent sessions/conversations
	// are cached. Beyond it the least-recently-used session is evicted — it just
	// re-scans next turn (safe, not a leak). 用户 2026-06-16: 200.
	defaultMaxSessions = 200
)

// defaultMaskCacheTTL — idle expiry for a cached verdict, SLIDING (refreshed on each Get,
// 用户 2026-06-17): an actively-used entry stays warm; only a gap > TTL since last use
// expires it. 1h = the widest mainstream LLM prompt-cache window, so our cache stays warm
// for any conversation a provider would still treat as "hot" (调研 2026-06-17: Claude 5min
// 默认/1h extended 滑动, OpenAI 5–10min, Gemini 1h 默认 → 取最宽的 1h 兼容全部).
//
// The TTL is now purely a MEMORY bound, not a correctness one. It used to double as the
// only limit on pack staleness, and it was a bad one: the swap does not bump the detector
// version, and the sliding refresh means a conversation that stays alive never lets its
// entries idle out — so "1h" was in practice "forever" for exactly the sessions that matter.
// That gap is closed at the key instead (contentVersion in cacheKey, 2026-08-13); see
// workflow/CI/bugfix/20260813-pack-swap-does-not-invalidate-proxy-cache.md.
var defaultMaskCacheTTL = 1 * time.Hour

// hashHead returns the sha256 hex of the scanned head bytes.
func hashHead(head string) string {
	sum := sha256.Sum256([]byte(head))
	return hex.EncodeToString(sum[:])
}

// cacheScope derives the level-1 isolation bucket (设计 §4.2). Priority: resolved
// session id → metadata.user_id → resolved virtual key → global. Never "".
//
// WHY sessionID is passed IN rather than extracted here (2026-08-08 跨 provider 会话
// 作用域,用户拍板): the pre-2026-08-08 implementation read ONE hard-coded header,
// X-Claude-Code-Session-Id — a Claude Code CLI-proprietary header. Every non-Claude
// client (kimi / codex / cursor / cline / 第三方 Agent, 30+ providers) therefore fell
// through to the metadata.user_id / vk / global buckets, so DIFFERENT conversations
// under one virtual key shared a single bucket: the "不能串" isolation (INV-3)
// degraded to tenant granularity, and the per-session LRU window was diluted by
// unrelated conversations' pieces.
//
// The single source of truth for "where does this client carry its session id" is
// internal/proxy/sessionid (session-fingerprint.yaml, protocol+provider → ordered
// header/body candidates; anthropic → X-Claude-Code-Session-Id, kimi →
// prompt_cache_key, openai → conversation_id, 通用 fallback → X-Aikey-Session-Id).
// serveRoute ALREADY resolves it via resolveSessionID() and hands it to
// applyInboundFilter (it also stamps the compliance event's session_id with it), so
// this function just reuses that value. Three reasons that beats re-extracting here:
//   - 单一真相源: session provenance stays declared once in the yaml; the cache does
//     not grow a second, divergent header ladder.
//   - 零额外 body 读: the body-backed candidates (kimi prompt_cache_key, openai
//     conversation_id) were already parsed — and the body already restored — by the
//     caller's resolveSessionID before applyInboundFilter reads it. Extracting again
//     here would mean a second read of a body the compliance chain must still be
//     able to consume verbatim.
//   - 作用域与审计一致: the cache bucket and the audit event's session_id are now the
//     same value, so a support engineer reading one can reason about the other.
//
// The "s:" prefix (was "h:" when the value could only come from a header) marks the
// session-scoped namespace; it only namespaces in-memory keys against the "u:"/"vk:"
// buckets, so renaming it costs nothing beyond a one-time all-miss on restart.
func cacheScope(sessionID string, parsed map[string]any, virtualKeyID string) string {
	if sessionID != "" {
		return "s:" + sessionID
	}
	if md, ok := parsed["metadata"].(map[string]any); ok {
		if uid, ok := md["user_id"].(string); ok && uid != "" {
			return "u:" + uid
		}
	}
	if virtualKeyID != "" {
		return "vk:" + virtualKeyID // fallback: per-tenant/VK (OpenClaw 等无 session id)
	}
	return "global"
}

// cacheKey is the level-2 (within-session) key. THREE parts, each answering a
// different "is this verdict still the answer?" question:
//
//	detectorVersion — WHICH BINARY decided. From the child's ready handshake, so
//	                  it moves on restart/upgrade. Covers changes in engine code
//	                  (NER models, policy evaluation) that no report can express.
//	contentVersion  — WHICH RULESET it decided against (apphook.CacheEpoch). This
//	                  is the part that moves WITHOUT a restart: the detector pulls
//	                  packs on a timer and hot-swaps its compiled ruleset in place,
//	                  so an admin deleting a rule on the console changes this and
//	                  nothing else. Empty for hooks with no hot-swappable content.
//	contentHash     — WHICH BYTES were decided about.
//
// WHY key-scoped invalidation rather than flushing the cache when the ruleset
// moves: the swap is observed asynchronously, per hook, while requests are
// in flight. A flush would need to be ordered against every concurrent Get/Put
// to be correct; a key that already carries the epoch makes every entry from the
// previous epoch unreachable the instant the new epoch is read, with no
// coordination at all. Stale entries are then evicted by the LRU as new ones
// arrive — they cost memory for a while, never correctness.
//
// 🔴 Do NOT reduce this to two parts again. The 2026-08-13 P0 was exactly the
// two-part key: a deleted rule kept masking because nothing in the key moved
// when the ruleset did. Fence: filter_cache_packswap_test.go.
func cacheKey(detectorVersion, contentVersion, contentHash string) string {
	return detectorVersion + "|" + contentVersion + "|" + contentHash
}

// ─────────────────────────────────────────────────────────────────────────────
// level 2: per-session LRU(window) of key→verdict (with per-entry TTL)
// ─────────────────────────────────────────────────────────────────────────────

type lruEntry struct {
	exp time.Time
	key string
	v   maskVerdict
}

type lruMaskCache struct {
	ll  *list.List
	m   map[string]*list.Element
	now func() time.Time
	cap int
	ttl time.Duration
	mu  sync.Mutex
}

func newLRUMaskCache(capacity int, ttl time.Duration) *lruMaskCache {
	if capacity < 1 {
		capacity = 1
	}
	return &lruMaskCache{cap: capacity, ttl: ttl, ll: list.New(), m: make(map[string]*list.Element, capacity), now: time.Now}
}

func (c *lruMaskCache) Get(key string) (maskVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return maskVerdict{}, false
	}
	ent, _ := el.Value.(*lruEntry)
	if c.now().After(ent.exp) {
		c.ll.Remove(el)
		delete(c.m, key)
		return maskVerdict{}, false
	}
	ent.exp = c.now().Add(c.ttl) // sliding: refresh idle timer on use (Claude-style 命中续期)
	c.ll.MoveToFront(el)
	return ent.v, true
}

func (c *lruMaskCache) Put(key string, v maskVerdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := c.now().Add(c.ttl)
	if el, ok := c.m[key]; ok {
		ent, _ := el.Value.(*lruEntry)
		ent.v, ent.exp = v, exp
		c.ll.MoveToFront(el)
		return
	}
	c.m[key] = c.ll.PushFront(&lruEntry{key: key, v: v, exp: exp})
	for c.ll.Len() > c.cap {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.ll.Remove(back)
		if ent, ok := back.Value.(*lruEntry); ok {
			delete(c.m, ent.key)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// level 1: session-LRU of per-session caches
// ─────────────────────────────────────────────────────────────────────────────

type sessionBucket struct {
	cache *lruMaskCache
	el    *list.Element // position in the session LRU
	scope string
}

// sessionMaskCache is the two-level cache: a bounded LRU of sessions, each holding
// a bounded LRU(window) of piece verdicts.
type sessionMaskCache struct {
	sessions    map[string]*sessionBucket
	ll          *list.List // session LRU (front = MRU)
	now         func() time.Time
	maxSessions int
	window      int
	ttl         time.Duration
	mu          sync.Mutex
}

func newSessionMaskCache(maxSessions, window int, ttl time.Duration) *sessionMaskCache {
	if maxSessions < 1 {
		maxSessions = 1
	}
	if window < 1 {
		window = 1
	}
	return &sessionMaskCache{
		maxSessions: maxSessions, window: window, ttl: ttl,
		sessions: make(map[string]*sessionBucket, maxSessions),
		ll:       list.New(), now: time.Now,
	}
}

func (c *sessionMaskCache) Get(scope, key string) (maskVerdict, bool) {
	c.mu.Lock()
	b, ok := c.sessions[scope]
	if ok {
		c.ll.MoveToFront(b.el)
	}
	c.mu.Unlock()
	if !ok {
		return maskVerdict{}, false
	}
	return b.cache.Get(key) // inner cache has its own lock
}

func (c *sessionMaskCache) Put(scope, key string, v maskVerdict) {
	c.mu.Lock()
	b, ok := c.sessions[scope]
	if !ok {
		b = &sessionBucket{scope: scope, cache: newLRUMaskCache(c.window, c.ttl)}
		b.cache.now = c.now
		b.el = c.ll.PushFront(b)
		c.sessions[scope] = b
		for c.ll.Len() > c.maxSessions { // evict least-recently-used session
			back := c.ll.Back()
			if back == nil {
				break
			}
			c.ll.Remove(back)
			if sb, ok := back.Value.(*sessionBucket); ok {
				delete(c.sessions, sb.scope)
			}
		}
	} else {
		c.ll.MoveToFront(b.el)
	}
	c.mu.Unlock()
	b.cache.Put(key, v)
}
