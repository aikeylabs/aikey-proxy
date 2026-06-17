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
//	{ sessionScope → LRU(window) of (version|contentHash → verdict) }
//
//   - level 1: a session-LRU bounds the number of sessions (maxSessions).
//   - level 2: per session, an LRU of the last `window` (default 5, env-tunable)
//     piece verdicts — bounds per-session memory + matches "recent turns are what
//     get resent". Older history beyond the window is re-scanned (≠ leaked: a
//     re-scan still masks it), so correctness is unaffected; it just caches less.
//
// PLUGGABLE / ZERO-COST WHEN OFF (设计 §3.1, INV-6): lives behind the hook==nil
// early-return in applyInboundFilter; when the cache is off p.filterCache is nil
// and the dispatcher skips the hash entirely.
//
// ISOLATION / 不能串 (INV-3): the session scope is the level-1 key, so two
// sessions never share a bucket. scope = client session id where available (Claude
// X-Claude-Code-Session-Id / metadata.user_id), else the resolved virtual key.
//
// PACK FRESHNESS (INV-5): detector-version is folded into the level-2 key (restart
// invalidates) + a per-entry TTL bounds stale-clean after an in-place pack pull.
package proxy

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// maskVerdict is the cached outcome of scanning one content piece's head. Stores
// only the masked head + action — never the raw original.
type maskVerdict struct {
	action     apphook.Action
	maskedHead string // present iff action == ActionMask
	reason     string // for ActionBlock
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
// SAFETY CAVEAT: this also bounds stale-clean after an in-place pack swap — which does NOT
// bump the detector version (childhook.go:215) — so a continuously-active session could reuse
// a cached "clean" verdict for content a NEWLY-added pack word now flags, until the entry
// idles out. New content is always scanned immediately; only already-cached-clean history is
// at risk, and pack updates are rare. PROPER FIX (TODO, see 设计 §4.2): put the live pack
// cursor in the cache key → a swap auto-invalidates → 1h fully safe regardless of activity.
var defaultMaskCacheTTL = 1 * time.Hour

// hashHead returns the sha256 hex of the scanned head bytes.
func hashHead(head string) string {
	sum := sha256.Sum256([]byte(head))
	return hex.EncodeToString(sum[:])
}

// cacheScope derives the level-1 isolation bucket (设计 §4.2). Priority: session id
// header → metadata.user_id → resolved virtual key → global. Never "".
func cacheScope(r *http.Request, parsed map[string]any, virtualKeyID string) string {
	if r != nil {
		if s := r.Header.Get("X-Claude-Code-Session-Id"); s != "" {
			return "h:" + s
		}
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

// cacheKey is the level-2 (within-session) key = detector version + content hash.
func cacheKey(detectorVersion, contentHash string) string {
	return detectorVersion + "|" + contentHash
}

// --- no-op (cache explicitly disabled while compliance is on) ---

type noopMaskCache struct{}

func (noopMaskCache) Get(string, string) (maskVerdict, bool) { return maskVerdict{}, false }
func (noopMaskCache) Put(string, string, maskVerdict)        {}

// ─────────────────────────────────────────────────────────────────────────────
// level 2: per-session LRU(window) of key→verdict (with per-entry TTL)
// ─────────────────────────────────────────────────────────────────────────────

type lruEntry struct {
	key string
	v   maskVerdict
	exp time.Time
}

type lruMaskCache struct {
	mu  sync.Mutex
	cap int
	ttl time.Duration
	ll  *list.List
	m   map[string]*list.Element
	now func() time.Time
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
	ent := el.Value.(*lruEntry)
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
		ent := el.Value.(*lruEntry)
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
		delete(c.m, back.Value.(*lruEntry).key)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// level 1: session-LRU of per-session caches
// ─────────────────────────────────────────────────────────────────────────────

type sessionBucket struct {
	scope string
	cache *lruMaskCache
	el    *list.Element // position in the session LRU
}

// sessionMaskCache is the two-level cache: a bounded LRU of sessions, each holding
// a bounded LRU(window) of piece verdicts.
type sessionMaskCache struct {
	mu          sync.Mutex
	maxSessions int
	window      int
	ttl         time.Duration
	sessions    map[string]*sessionBucket
	ll          *list.List // session LRU (front = MRU)
	now         func() time.Time
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
			delete(c.sessions, back.Value.(*sessionBucket).scope)
		}
	} else {
		c.ll.MoveToFront(b.el)
	}
	c.mu.Unlock()
	b.cache.Put(key, v)
}
