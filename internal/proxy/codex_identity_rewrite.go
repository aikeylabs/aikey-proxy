// codex_identity_rewrite.go — per-account rewrite of the identifiers a Codex
// client stamps on every request.
//
// WHY THIS EXISTS. The Codex CLI mints an installation id once per machine and a
// session / thread / turn / context-window id per conversation, then repeats them
// on every request no matter which upstream account serves it. Two accounts in
// one pool therefore share one device fingerprint upstream, and a ban on one
// account reaches its neighbors. This function gives every account its own
// stable alias set: one machine still looks like ONE steady device per account,
// while the alias sets of two accounts are unrelated.
//
// Requirement package: roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/
// (design §5.5 "worker 按账号改写标识").
//
// spec: R-codex-identity-rewrite-2.S1 consistency — field groups that were equal
// stay equal, UUID v4/v7 versions are preserved, window_id = new thread id +
// original suffix, and parent_turn_id / forked_from_thread_id agree with the
// alias of the field they reference.
// spec: R-codex-identity-rewrite-3.S1 after a device is rebound to another
// account — the millisecond times the two accounts see differ, while the 1 ms
// gap between the turn id and turn_started_at_unix_ms holds on both sides.
//
// THE THREE RULES THAT KEEP THE RESULT SELF-CONSISTENT
//
//  1. Map by ORIGINAL VALUE, not per field. Codex's identifiers are independent
//     random UUIDs (installation_id = Uuid::new_v4, the rest = Uuid::now_v7)
//     with only REFERENCE relations between them: window_id is
//     "{thread_id}:{counter}", root_turn_id / parent_turn_id /
//     forked_from_thread_id quote other turns and threads. Deriving each FIELD
//     separately would hand the upstream a metadata blob that contradicts
//     itself, so one original value is derived exactly once per request and
//     filled into every carrier it appears in — ten session spots in the shape
//     experiment 5 recorded. Reference relations then hold for free, including
//     across requests: a fork quoting an older thread id gets the same alias
//     back.
//
//  2. Keep the shape. A v4 stays a syntactically valid v4, a v7 stays a valid
//     v7, window_id keeps "{uuid}:{counter}". The upstream parses these values;
//     a shape change would be both a new fingerprint and a 400 risk.
//
//  3. Move time with ONE per-account offset. A v7 carries its creation
//     millisecond in the clear, so after a device is rebound the old and the new
//     account would otherwise show the same conversation minted in the same
//     millisecond. Every v7 timestamp AND turn_started_at_unix_ms move by the
//     same per-account offset — 0 to 60 s BACKWARDS, never forwards, so an alias
//     never looks like it was minted in the future — which keeps absolute times
//     different between accounts while every relative distance survives,
//     notably the 1 ms between the turn id and turn_started_at_unix_ms.
//
// WHAT THIS FUNCTION DELIBERATELY DOES NOT DO (owned by the wiring, task 2.2 /
// 2.4; keeping it out keeps this function pure and replayable):
//   - no logging: a pure function has no request id to log with, so the caller
//     WARNs from rewriteReport.Dropped. Nothing here falls back silently.
//   - no X-Aikey-* stripping: stripAikeyRequestHeaders owns that with no
//     exception. This function only ever rewrites or removes a header, never
//     adds one, so it cannot produce an X-Aikey-* header.
//   - no x-codex-turn-state guard, no credential injection, and no decision on
//     whether a request whose carriers were dropped may still be sent.
package proxy

import (
	"bytes"
	"container/list"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// rewriteReport tells the caller what one rewrite pass did.
type rewriteReport struct {
	// Kinds counts the distinct original identifier values that received an
	// alias in this request. Every occurrence of one original value shares one
	// derivation ("按类别算一次"), so this is also the number of identifier
	// categories the request carried: 4 for the experiment-5 shape —
	// installation id, session/thread id, turn id, context window id. window_id
	// is composed from the session alias and is not derived on its own.
	Kinds int
	// Dropped names the identifier carriers this pass could NOT rewrite, in a
	// stable order, for the caller to WARN about:
	//
	//	"session-id", "x-codex-turn-metadata", …   a request header, REMOVED
	//	"prompt_cache_key"                         a body key, REMOVED
	//	"client_metadata.turn_id", …               a nested JSON key, REMOVED
	//	"body"                                     the body is not a JSON object,
	//	                                           handed back untouched
	//	"key"                                      no account key was supplied,
	//	                                           nothing was rewritten at all
	//
	// Headers and JSON keys are removed rather than passed through, because an
	// identifier that cannot be aliased is exactly the linkage this function
	// exists to cut (design §5.5: the original value must never reach the
	// upstream). A body that cannot be parsed cannot be removed, so the caller
	// owns that decision — refusing a request is not a pure function's call.
	Dropped []string
}

// rewriteCodexIdentity returns a rewritten copy of the request's headers and
// body for one account. It never mutates its arguments: the caller keeps the
// original request intact for retries and for the other lanes.
//
// key is the account's own derived key — the seed that makes two accounts
// unrelated. It is never logged, never stored and never travels upstream.
func rewriteCodexIdentity(h http.Header, body, key []byte) (http.Header, []byte, rewriteReport) {
	out := h.Clone()
	if len(key) == 0 {
		// Fail closed. With no account key nothing can be derived, and shipping
		// the ORIGINAL identifiers would restore the very linkage this cuts, so
		// the request comes back unchanged and flagged for the caller to refuse.
		return out, body, rewriteReport{Dropped: []string{codexIdentityDropKey}}
	}
	rw := newCodexIdentityRewriter(key)
	rw.rewriteHeaders(out)
	return out, rw.rewriteBody(body), rewriteReport{Kinds: len(rw.alias), Dropped: rw.dropped}
}

const (
	// HMAC domain separators. The kind keeps two categories from ever colliding
	// on a crafted value, and the time offset gets its own kind so it cannot be
	// confused with an identifier derivation.
	codexIdentityKindUUIDPrefix = "uuid-v"
	codexIdentityKindTimeOffset = "time-offset"

	// design §5.5: shift an account's clock backwards by 0-60 s.
	codexIdentityMaxBackshiftMillis = 60_000

	// Codex nests identifier blobs two levels deep at most (body →
	// client_metadata → x-codex-turn-metadata). The cap stops a crafted body
	// from recursing without bound; anything deeper is dropped, not walked.
	codexIdentityMaxNesting = 3

	codexIdentityDropKey  = "key"
	codexIdentityDropBody = "body"
)

// codexIdentityFormat says how one carrier has to be read and written back.
type codexIdentityFormat uint8

const (
	// codexIdentityUUID is a canonical UUID; its version nibble is preserved.
	codexIdentityUUID codexIdentityFormat = iota + 1
	// codexIdentityWindowID is "{uuid}:{counter}" (Codex client_tests.rs:1168).
	codexIdentityWindowID
	// codexIdentityMillis is a unix millisecond integer that moves with the
	// account's time offset.
	codexIdentityMillis
	// codexIdentityObject is a nested JSON object (client_metadata).
	codexIdentityObject
	// codexIdentityObjectText is a JSON object that travels inside a JSON
	// string (client_metadata["x-codex-turn-metadata"]).
	codexIdentityObjectText
	// codexIdentityHeaderObject is a JSON object that travels as a raw header
	// value (the x-codex-turn-metadata header itself).
	codexIdentityHeaderObject
)

type codexIdentityField struct {
	name   string
	format codexIdentityFormat
}

// The three tables below are the single source of truth for what gets
// rewritten. They are exhaustive lists, not pattern matching: a field nobody
// listed travels untouched, which is what keeps the client's own payload —
// instructions, input, sandbox mode, client version info — byte for byte.
// Slices, not maps, so the Dropped order is deterministic.
var (
	// codexIdentityHeaderFields are the standalone request headers, in the
	// shape experiment 5 recorded.
	codexIdentityHeaderFields = []codexIdentityField{
		{"X-Codex-Installation-Id", codexIdentityUUID},
		{"Session-Id", codexIdentityUUID},
		{"Thread-Id", codexIdentityUUID},
		// A forked thread quotes the thread it branched from. Named field by
		// field in R-codex-identity-rewrite-2, and experiment 5 never branched a
		// conversation so it is NOT in the recorded shape — the rule is the
		// source of truth here, not the experiment. Because the map is keyed by
		// ORIGINAL value, the parent's alias is the one it received back when it
		// was the current thread, so the fork link still holds upstream while
		// the client's own thread id does not travel (R-codex-identity-rewrite-1).
		{"X-Codex-Parent-Thread-Id", codexIdentityUUID},
		{"X-Client-Request-Id", codexIdentityUUID},
		{"X-Codex-Window-Id", codexIdentityWindowID},
		{"X-Codex-Turn-Metadata", codexIdentityHeaderObject},
	}

	// codexIdentityBodyFields are the top-level body keys. client_metadata is
	// walked with the table below; nothing else at this level is an identifier.
	codexIdentityBodyFields = []codexIdentityField{
		{"prompt_cache_key", codexIdentityUUID},
		{"client_metadata", codexIdentityObject},
	}

	// codexIdentityJSONFields are the keys inside the turn-metadata blob and
	// inside client_metadata. One table for both: the two carry the same
	// identifiers under the same names, and a second table would drift.
	codexIdentityJSONFields = []codexIdentityField{
		{"installation_id", codexIdentityUUID},
		{"x-codex-installation-id", codexIdentityUUID},
		{"session_id", codexIdentityUUID},
		{"thread_id", codexIdentityUUID},
		{"turn_id", codexIdentityUUID},
		{"root_turn_id", codexIdentityUUID},
		// Only present on a forked turn/thread. Listed so the fork keeps
		// pointing at the alias of the value it references (R-codex-identity-rewrite-2.S1).
		// x-codex-parent-thread-id is the header-style MIRROR of
		// forked_from_thread_id, listed for the same reason the two
		// x-codex-* names above it are: client_metadata carries the header
		// spellings as well (experiment 5 recorded x-codex-installation-id and
		// x-codex-window-id there), and R-codex-identity-rewrite-2 replaces one
		// original value at EVERY spot it appears — a mirror left off this table
		// would ship the client's own thread id while the header beside it was
		// aliased.
		{"parent_turn_id", codexIdentityUUID},
		{"forked_from_thread_id", codexIdentityUUID},
		{"x-codex-parent-thread-id", codexIdentityUUID},
		{"context_window_id", codexIdentityUUID},
		{"window_id", codexIdentityWindowID},
		{"x-codex-window-id", codexIdentityWindowID},
		{"turn_started_at_unix_ms", codexIdentityMillis},
		{"x-codex-turn-metadata", codexIdentityObjectText},
	}
)

// codexIdentityRewriter holds one request's derivations. Its alias map is what
// makes "compute once per category, fill everywhere" true.
type codexIdentityRewriter struct {
	key          []byte
	offsetMillis int64
	alias        map[string]string
	dropped      []string
}

func newCodexIdentityRewriter(key []byte) *codexIdentityRewriter {
	rw := &codexIdentityRewriter{key: key, alias: make(map[string]string, 4)}
	// The modulo bounds the back-shift to [0, codexIdentityMaxBackshiftMillis],
	// so the uint64 -> int64 conversion below cannot overflow.
	backshift := binary.BigEndian.Uint64(rw.mac(codexIdentityKindTimeOffset, "")[:8]) % (codexIdentityMaxBackshiftMillis + 1)
	rw.offsetMillis = -int64(backshift) //nolint:gosec // G115: backshift <= codexIdentityMaxBackshiftMillis, bounded by the modulo above
	return rw
}

// mac = HMAC-SHA256(account key, kind ‖ 0x00 ‖ original). The 0x00 separator
// keeps two kinds from colliding on a crafted value.
func (rw *codexIdentityRewriter) mac(kind, original string) []byte {
	m := hmac.New(sha256.New, rw.key)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(original))
	return m.Sum(nil)
}

func (rw *codexIdentityRewriter) drop(name string) {
	rw.dropped = append(rw.dropped, name)
}

// aliasOf returns this account's alias for one identifier value, deriving it at
// most once per request. Reporting false means the value is not a UUID we can
// reshape — the caller then removes the carrier instead of leaking the original.
func (rw *codexIdentityRewriter) aliasOf(original string) (string, bool) {
	if alias, ok := rw.alias[original]; ok {
		return alias, true
	}
	src, ok := parseCanonicalUUID(original)
	if !ok {
		return "", false
	}
	alias := rw.deriveUUID(original, src)
	rw.alias[original] = alias
	return alias, true
}

// windowAliasOf rewrites "{thread uuid}:{counter}". Only the prefix is an
// identifier; the counter is kept so the upstream still sees a consistent
// window sequence.
func (rw *codexIdentityRewriter) windowAliasOf(original string) (string, bool) {
	cut := strings.LastIndex(original, ":")
	if cut < 0 {
		return "", false
	}
	prefix, ok := rw.aliasOf(original[:cut])
	if !ok {
		return "", false
	}
	return prefix + original[cut:], true
}

// deriveUUID mints the alias: HMAC bytes reshaped into the original's own
// version, with a v7's timestamp carried over and shifted by the account offset.
func (rw *codexIdentityRewriter) deriveUUID(original string, src [16]byte) string {
	version := src[6] >> 4
	var out [16]byte
	copy(out[:], rw.mac(codexIdentityKindUUIDPrefix+strconv.Itoa(int(version)), original))
	if version == 7 {
		ms := rw.shiftMillis(uuidV7Millis(src))
		out[0], out[1], out[2] = byte(ms>>40), byte(ms>>32), byte(ms>>24)
		out[3], out[4], out[5] = byte(ms>>16), byte(ms>>8), byte(ms)
	}
	out[6] = out[6]&0x0f | version<<4 // keep the version: v4 stays v4, v7 stays v7
	out[8] = out[8]&0x3f | 0x80       // RFC 4122 variant
	return formatCanonicalUUID(out)
}

// shiftMillis moves one unix millisecond by the account offset. It clamps at 0
// because a negative timestamp is neither a valid v7 nor a sane start time; the
// clamp is unreachable for any clock later than 1970 plus a minute.
func (rw *codexIdentityRewriter) shiftMillis(ms int64) int64 {
	if shifted := ms + rw.offsetMillis; shifted >= 0 {
		return shifted
	}
	return 0
}

// rewriteHeaders rewrites the standalone identifier headers in place on the
// caller's COPY of the header set.
func (rw *codexIdentityRewriter) rewriteHeaders(dst http.Header) {
	for _, field := range codexIdentityHeaderFields {
		values := dst.Values(field.name)
		if len(values) == 0 {
			continue
		}
		path := strings.ToLower(field.name)
		rewritten, readable := make([]string, 0, len(values)), true
		for _, value := range values {
			next, ok := rw.rewriteHeaderValue(field.format, value, path)
			if !ok {
				readable = false
				break
			}
			rewritten = append(rewritten, next)
		}
		if !readable {
			dst.Del(field.name)
			rw.drop(path)
			continue
		}
		dst[textproto.CanonicalMIMEHeaderKey(field.name)] = rewritten
	}
}

func (rw *codexIdentityRewriter) rewriteHeaderValue(format codexIdentityFormat, value, path string) (string, bool) {
	switch format {
	case codexIdentityUUID:
		return rw.aliasOf(value)
	case codexIdentityWindowID:
		return rw.windowAliasOf(value)
	case codexIdentityHeaderObject:
		blob := []byte(value)
		if !gjson.ValidBytes(blob) || !gjson.ParseBytes(blob).IsObject() {
			// design §5.5: an unparsable turn-metadata header is dropped whole.
			return "", false
		}
		next, changed := rw.rewriteDocument(blob, codexIdentityJSONFields, path+".", 1)
		if !changed {
			return value, true // never re-serialize a blob we did not touch
		}
		return string(next), true
	case codexIdentityMillis, codexIdentityObject, codexIdentityObjectText:
		// Header carriers only use UUID / WindowID / HeaderObject
		// (codexIdentityHeaderFields); these formats live inside JSON bodies.
		// A header declared with one of them cannot be rewritten faithfully,
		// so it is dropped like any unreadable value.
		return "", false
	default:
		return "", false
	}
}

// rewriteBody returns the rewritten body, or the original bytes when there was
// nothing to change. The body is never mutated in place.
//
// The document is validated before any splice: sjson's own doc says it "expects
// that the json is well-formed, and does not validate … it may return back
// unexpected results", so a malformed body has to be caught here rather than
// spliced blindly.
func (rw *codexIdentityRewriter) rewriteBody(raw []byte) []byte {
	if len(bytes.TrimSpace(raw)) == 0 {
		return raw
	}
	if !gjson.ValidBytes(raw) || !gjson.ParseBytes(raw).IsObject() {
		rw.drop(codexIdentityDropBody)
		return raw
	}
	next, _ := rw.rewriteDocument(raw, codexIdentityBodyFields, "", 0)
	return next
}

// rewriteDocument rewrites one JSON document VALUE BY VALUE and reports whether
// anything changed. Every byte that is not a rewritten value keeps its exact
// position, so key order, spacing and untouched fields reach the upstream
// exactly as the Codex client wrote them — a re-serialized document would be
// the first thing in this chain to reorder a Codex body, and neither the S0
// live-upstream round nor today's normalizeCodexRequest does that.
//
// Iteration follows the table, not the document, so a payload cannot steer the
// work and Dropped stays deterministic. Paths are single table names and every
// nested container is rewritten as its own document, so no path ever carries a
// gjson metacharacter — a table row whose name contains '.', '*', '?', '#',
// '|' or '@' would break that and must not be added.
func (rw *codexIdentityRewriter) rewriteDocument(doc []byte, table []codexIdentityField, reportPrefix string, depth int) ([]byte, bool) {
	changed := false
	for _, field := range table {
		found := gjson.GetBytes(doc, field.name)
		if !found.Exists() {
			continue
		}
		name := reportPrefix + field.name
		replacement, ok := rw.replacementFor(found, field.format, name+".", depth)
		if ok && replacement == nil {
			continue // readable, but there was nothing to change
		}
		if ok {
			if next, err := sjson.SetRawBytes(doc, field.name, replacement); err == nil {
				doc, changed = next, true
				continue
			}
		}
		// Fail closed: an identifier we could not alias — or could not splice —
		// must not travel upstream as it came in.
		if next, err := sjson.DeleteBytes(doc, field.name); err == nil {
			doc, changed = next, true
		}
		rw.drop(name)
	}
	return doc, changed
}

// replacementFor computes the raw JSON that has to take the place of one
// carrier's value. ok=false means the value could not be rewritten and the
// carrier has to go; a nil replacement with ok=true means "leave it alone".
func (rw *codexIdentityRewriter) replacementFor(found gjson.Result, format codexIdentityFormat, reportPrefix string, depth int) ([]byte, bool) {
	switch format {
	case codexIdentityUUID, codexIdentityWindowID:
		if found.Type != gjson.String {
			return nil, false
		}
		var alias string
		var ok bool
		if format == codexIdentityUUID {
			alias, ok = rw.aliasOf(found.Str)
		} else {
			alias, ok = rw.windowAliasOf(found.Str)
		}
		if !ok {
			return nil, false
		}
		return jsonStringLiteral(alias)
	case codexIdentityMillis:
		// A float or exponent form is not a millisecond stamp Codex writes, and
		// reshaping it would silently change the number's format.
		if found.Type != gjson.Number || strings.ContainsAny(found.Raw, ".eE") {
			return nil, false
		}
		return []byte(strconv.FormatInt(rw.shiftMillis(found.Int()), 10)), true
	case codexIdentityObject, codexIdentityObjectText:
		return rw.rewriteNested(found, format, reportPrefix, depth)
	case codexIdentityHeaderObject:
		// Only the X-Codex-Turn-Metadata header uses this format
		// (codexIdentityHeaderFields); it never appears as a JSON body carrier,
		// so a body field declared with it cannot be rewritten and is dropped.
		return nil, false
	default:
		return nil, false
	}
}

// rewriteNested walks a nested identifier blob, whether it arrives as a JSON
// object or as a JSON string holding one, and hands back the raw JSON to splice
// in its place.
func (rw *codexIdentityRewriter) rewriteNested(found gjson.Result, format codexIdentityFormat, reportPrefix string, depth int) ([]byte, bool) {
	if depth+1 >= codexIdentityMaxNesting {
		return nil, false
	}
	if format == codexIdentityObject {
		if found.Type == gjson.Null {
			return nil, true // no identifier to rewrite, nothing to drop
		}
		if !found.IsObject() {
			return nil, false
		}
		next, changed := rw.rewriteDocument([]byte(found.Raw), codexIdentityJSONFields, reportPrefix, depth+1)
		if !changed {
			return nil, true
		}
		return next, true
	}
	// design §5.5: an unparsable turn-metadata blob is dropped whole.
	if found.Type != gjson.String {
		return nil, false
	}
	inner := []byte(found.Str)
	if !gjson.ValidBytes(inner) || !gjson.ParseBytes(inner).IsObject() {
		return nil, false
	}
	next, changed := rw.rewriteDocument(inner, codexIdentityJSONFields, reportPrefix, depth+1)
	if !changed {
		return nil, true
	}
	return jsonStringLiteral(string(next))
}

// jsonStringLiteral quotes one string as a JSON value. It goes through an
// Encoder with HTML escaping OFF deliberately: encoding/json.Marshal — and
// sjson's own string path, which falls back to it (sjson.go:124-128) — would
// turn an untouched '&', '<' or '>' inside a nested blob into & and
// friends, changing bytes this function never rewrote.
func jsonStringLiteral(value string) ([]byte, bool) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, false
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true
}

// parseCanonicalUUID accepts the 8-4-4-4-12 hex form Codex emits and returns the
// 16 bytes behind it.
func parseCanonicalUUID(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return out, false
	}
	digits := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			digits = append(digits, s[i])
		}
	}
	if len(digits) != 32 {
		return out, false
	}
	if _, err := hex.Decode(out[:], digits); err != nil {
		return [16]byte{}, false
	}
	return out, true
}

func formatCanonicalUUID(b [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}

// uuidV7Millis reads the creation time a v7 carries in its leading 48 bits.
func uuidV7Millis(b [16]byte) int64 {
	return int64(b[0])<<40 | int64(b[1])<<32 | int64(b[2])<<24 |
		int64(b[3])<<16 | int64(b[4])<<8 | int64(b[5])
}

// ── wiring: the account-pool serving path (task 2.2) ───────────────────────
//
// Everything below is the CALLER side of the pure function above: the per-pool
// switch, and the one step group_serve.go runs after it has chosen an account
// and before it injects that account's credential.

// groupIdentityRewritePolicy is the slice of routing_config this reader owns.
// A pointer so "the key is absent" stays distinguishable from "the key says
// false" — an absent key must read as OFF for a pool nobody has opted in yet,
// and a rewrite that turned itself on by accident would change what every
// Codex request looks like upstream.
type groupIdentityRewritePolicy struct {
	CodexIdentityRewrite *bool `json:"codex_identity_rewrite"`
}

// groupCodexIdentityRewrite reports whether ONE pool has the Codex identity
// rewrite switched on. It reads the routing_config string the group runtime
// already carries to the worker on both rails (member rail:
// internal/supervisor/group_runtime_policy.go; cluster rail: aikey-cli
// vault_op.rs), so the switch needs no relay hop of its own — the same place
// groupTemporaryRateLimitCooldown reads its own key from
// (oauth_pool_cooldown.go).
//
// Unreadable config returns (false, err): the caller keeps serving with the
// rewrite OFF and logs the drift. Defaulting to ON would be a silent,
// pool-wide behavior change decided by a typo.
func groupCodexIdentityRewrite(routingConfig string) (bool, error) {
	raw := strings.TrimSpace(routingConfig)
	if raw == "" {
		return false, nil
	}
	var policy groupIdentityRewritePolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return false, err
	}
	if policy.CodexIdentityRewrite == nil {
		return false, nil
	}
	return *policy.CodexIdentityRewrite, nil
}

// applyCodexIdentityRewrite rewrites ONE account-pool request for the account
// that is about to serve it, and reports whether it did.
//
// Placement (design §5.5): after the account is chosen and BEFORE its
// credential is injected — the rewrite needs to know WHICH account's key to
// derive from, and the injection needs to know the rewrite ran (it owns
// ChatGPT-Account-Id on this lane). The caller is group_serve.go's
// serveGroupAttempt, one line above oauthInjectForLane.
//
// Scope, in the order the gates run:
//
//	oauthCode != "openai"  → nothing happens. Claude / Kimi / generic personas
//	                         and every api_key account leave byte-identical
//	                         (R-codex-identity-rewrite-6).
//	switch off / unreadable → nothing happens. The rewrite is off by default
//	                         and is opened per pool (design 7.4); an unreadable
//	                         routing_config must not turn it on, and the WARN
//	                         keeps that drift visible.
//
// Failure handling is "drop, don't block" (R-codex-identity-rewrite-7): the
// pure function already removed every carrier it could not rewrite, so the
// request proceeds with one header/key fewer and ONE WARN names them. A side
// feature must not fail the main path — and the values it could not alias must
// not travel either, which is why dropping (not forwarding) is the failure
// mode.
func applyCodexIdentityRewrite(
	r *http.Request, oauthCode string, route *vkeys.ResolvedRoute,
	accountID string, logger *slog.Logger,
) bool {
	// "openai" is the OAuth PERSONA code oauthInject dispatches Codex on (see
	// its switch), so this is exactly the set of requests injectCodexOAuth
	// serves — including a Mock Provider emulating the Codex protocol.
	if oauthCode != "openai" || r == nil {
		return false
	}
	on, err := groupCodexIdentityRewrite(route.RoutingConfig)
	if err != nil {
		logger.Warn("pool routing config is invalid; the Codex identity rewrite stays off",
			"event.name", observability.EventProxyGroupRoutingConfigInvalid,
			"oauth_group_id", route.OauthGroupID,
			"error", err.Error())
		return false
	}
	if !on {
		return false
	}
	if len(route.IdentityKey) == 0 {
		// The resolver promises a non-empty key — it degrades to a node-local
		// derivation plus a CRIT rather than handing out none (group_resolve.go
		// resolveIdentityKey, spec R-codex-identity-rewrite-4). So this is a
		// broken promise, not a state to serve through: with no seed there is
		// nothing to derive aliases FROM, and reporting "rewritten" would also
		// hand ChatGPT-Account-Id to a request still carrying the client's own
		// identifiers. Answer honestly instead — the request behaves exactly as
		// it does with the switch off — and say so once.
		logger.Warn("codex identity rewrite has no per-account key; the request is served unrewritten",
			"event.name", observability.EventProxyCodexIdentityCarrierDropped,
			"oauth_group_id", route.OauthGroupID,
			"account_id", accountID,
			"dropped", []string{codexIdentityDropKey})
		return false
	}

	// The one carrier that is dropped rather than aliased: upstream state that
	// belongs to whichever account minted it (R-codex-identity-rewrite-5). It sits
	// here, inside the lane's own gates, because "which account is serving" is
	// exactly what this function already knows — and because a pool nobody opted
	// in must stay byte-identical, switch included.
	if dropForeignCodexTurnState(r, accountID) {
		logger.Warn("dropped a codex turn-state minted while another account was serving",
			"event.name", observability.EventProxyCodexIdentityCarrierDropped,
			"oauth_group_id", route.OauthGroupID,
			"account_id", accountID,
			"dropped", []string{codexTurnStateHeader},
			"reason", codexTurnStateReasonForeign)
	}

	var raw []byte
	if r.Body != nil && r.Body != http.NoBody {
		body, readErr := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if readErr != nil {
			// Fail closed. A body read half-way cannot be rewritten, and
			// forwarding the prefix would ship exactly the identifiers this
			// step exists to replace. The request dies on the next read instead,
			// loudly, with this WARN as the explanation. Unreachable in
			// practice: by here the body is an in-memory reader (the failover
			// replay buffer, or the copy the shape gate installed).
			logger.Warn("codex identity rewrite could not read the request body",
				"event.name", observability.EventProxyCodexIdentityCarrierDropped,
				"oauth_group_id", route.OauthGroupID,
				"account_id", accountID,
				"dropped", []string{codexIdentityDropBody},
				"error", readErr.Error())
			return false
		}
		raw = body
	}

	header, rewritten, report := rewriteCodexIdentity(r.Header, raw, route.IdentityKey)
	r.Header = header
	if r.Body != nil && r.Body != http.NoBody {
		// setRequestBody, not a bare r.Body assignment: it is the one place that
		// keeps Body, ContentLength AND GetBody in sync. GetBody is what net/http
		// replays on an HTTP/2 stream error — the group lane deliberately makes
		// those retryable (bugfix 2026-09-03) — so leaving it pointing at the
		// original buffer would send the PRE-rewrite identifiers on the retry.
		setRequestBody(r, rewritten)
	}
	if len(report.Dropped) > 0 {
		logger.Warn("codex identity rewrite dropped carriers it could not rewrite",
			"event.name", observability.EventProxyCodexIdentityCarrierDropped,
			"oauth_group_id", route.OauthGroupID,
			"account_id", accountID,
			"dropped", report.Dropped,
			"kinds", report.Kinds)
	}
	return true
}

// ── the turn-state guard (task 2.4) ─────────────────────────────────────────
//
// x-codex-turn-state is the ONE carrier the rewrite above cannot alias: it is
// opaque UPSTREAM state, minted by the account that served an earlier request
// of the same turn, and only the upstream can read it. Aliasing it would be
// meaningless; FORWARDING it on another account's credential hands the upstream
// a value it can only have issued to a different account — which re-links the
// two accounts with one header, however well every identifier around it was
// rewritten.
//
// So it is DROPPED when the account changed, and dropping it is safe by
// MEASUREMENT rather than assumption: S0 attempt 2 (2026-09-21, real ChatGPT
// Codex backend) sent a turn carrying no turn-state; the upstream answered 200,
// re-issued one on the spot, and reported unchanged cache hits (11520 = 11520).
// See tasks.md §1 出口门. The cost of a drop is therefore one re-issue, never
// the request.
//
// spec: R-codex-identity-rewrite-5 丢弃不是当前账号签发的 x-codex-turn-state
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md

// codexTurnStateHeader is the header the Codex CLI echoes back on later
// requests of one turn. net/http canonicalises header keys, so Get/Del below
// match whatever casing the client used.
const codexTurnStateHeader = "x-codex-turn-state"

// codexTurnStateMemoryCap is how many turn-states ONE worker remembers the
// owner of. The map is fed by a client-supplied header, so an unbounded one
// would be a memory leak any client could drive; 4096 is several thousand
// concurrent turns, while the whole table costs well under a megabyte (a
// 32-char digest plus an account id per entry). Eviction is least-recently-
// used and completely benign: an evicted turn-state is simply learned again on
// its next sighting.
const codexTurnStateMemoryCap = 4096

// turnStateOwners remembers which account each turn-state was first seen with.
//
// Deliberately a plain LRU with a mutex: no goroutine and no timer, because a
// side feature must not add a lifecycle the main path can outlive (a ticker
// that dies leaves a table that grows forever, and this worker already has
// enough moving parts). Entries need no TTL either — a turn-state nobody
// mentions again is evicted by pressure alone.
type turnStateOwners struct {
	mu    sync.Mutex
	limit int
	// order front = most recently used; elements hold *turnStateEntry.
	order *list.List
	index map[string]*list.Element
}

type turnStateEntry struct {
	digest    string
	accountID string
}

func newTurnStateOwners(limit int) *turnStateOwners {
	if limit < 1 {
		limit = 1
	}
	return &turnStateOwners{
		limit: limit,
		order: list.New(),
		index: make(map[string]*list.Element, limit),
	}
}

// codexTurnStateOwners is the worker-wide memory. Process-scoped on purpose:
// "which account did this turn-state come from" is a property of THIS worker's
// own traffic, and applyCodexIdentityRewrite is a free function on the serving
// path with no per-request place to hang it. Two workers therefore learn
// independently — see the known bound in the task report.
var codexTurnStateOwners = newTurnStateOwners(codexTurnStateMemoryCap)

// owner returns the account this turn-state already belongs to on this worker,
// binding it to accountID the first time it is seen.
//
// The value is keyed by a digest, not stored verbatim: it is upstream state
// worth no more exposure than it needs, and a fixed-width key keeps the memory
// bound exact. A digest collision could only ever cause a DROP of a header
// that would have been kept (one upstream re-issue), never a leak.
func (o *turnStateOwners) owner(value, accountID string) string {
	sum := sha256.Sum256([]byte(value))
	digest := hex.EncodeToString(sum[:16])

	o.mu.Lock()
	defer o.mu.Unlock()
	if element, ok := o.index[digest]; ok {
		if entry, isEntry := element.Value.(*turnStateEntry); isEntry {
			o.order.MoveToFront(element)
			return entry.accountID
		}
		// Unreachable: the list only ever holds *turnStateEntry (PushFront
		// below). Drop the malformed element and re-record it rather than
		// panic on the request path.
		o.order.Remove(element)
		delete(o.index, digest)
	}
	o.index[digest] = o.order.PushFront(&turnStateEntry{digest: digest, accountID: accountID})
	for o.order.Len() > o.limit {
		oldest := o.order.Back()
		if oldest == nil {
			break
		}
		o.order.Remove(oldest)
		if entry, isEntry := oldest.Value.(*turnStateEntry); isEntry {
			delete(o.index, entry.digest)
		}
	}
	return accountID
}

func (o *turnStateOwners) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.order.Len()
}

// dropForeignCodexTurnState removes an x-codex-turn-state that was minted while
// a DIFFERENT account was serving, and reports whether it dropped one.
//
// The first sighting of a turn-state binds it to the account serving that
// request: the header is issued by the upstream mid-turn, so the first request
// that carries it is the only place a request-direction guard can learn the
// owner from, and refusing it there would drop every turn-state forever (the
// re-issued one is just as unknown). What this cannot see is a turn-state
// minted through ANOTHER worker — that one is kept once. Closing that window
// means learning from the response direction; out of scope here and recorded as
// a concern.
//
// An empty accountID is treated as "cannot prove ownership" and drops: on this
// lane the serving account is always known, so an empty one is a broken caller,
// and failing closed costs one re-issue instead of a cross-account leak.
//
// It does not log: the caller owns the WARN, the way 2.1's pure function hands
// its Dropped list up instead of logging it — only the caller has the request's
// logger and the pool id the line needs.
func dropForeignCodexTurnState(r *http.Request, accountID string) bool {
	state := r.Header.Get(codexTurnStateHeader)
	if state == "" {
		return false
	}
	if accountID != "" && codexTurnStateOwners.owner(state, accountID) == accountID {
		return false
	}
	r.Header.Del(codexTurnStateHeader)
	return true
}

// codexTurnStateReasonForeign distinguishes this drop from the malformed-carrier
// drops above: nothing is wrong with the request, the account simply changed.
const codexTurnStateReasonForeign = "minted_for_another_account"
