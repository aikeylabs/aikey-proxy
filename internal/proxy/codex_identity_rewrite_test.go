package proxy

// Fences for the per-account Codex identifier rewrite (codex_identity_rewrite.go).
//
// spec: R-codex-identity-rewrite-2.S1 consistency — field groups that were equal
// before the rewrite are still equal after it, UUID v4/v7 versions survive, and
// window_id stays "{new thread id}:{original suffix}".
// spec: R-codex-identity-rewrite-3.S1 after a device is rebound to another account
// — the two accounts see different millisecond times, while the 1 ms gap between
// the turn id and turn_started_at_unix_ms holds on both sides.
// Requirement package: roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/
// (design §5.5 "worker 按账号改写标识").
//
// The input is experiment 5's RECORDED SHAPE — field names and equality relations
// only, because the experiment deliberately stored no values:
// workflow/CI/research/codex-installation-id-2026-09/results/exp5_shapes.jsonl.
// Its equality groups are reproduced one for one:
//
//   - 10 direct session spots (session-id / thread-id / x-client-request-id headers,
//     session_id + thread_id in the turn-metadata header, the same two in
//     client_metadata, the same two in the turn metadata nested inside
//     client_metadata, and the body's prompt_cache_key) plus 4 window_id prefixes
//   - 6 turn spots (turn_id == root_turn_id in a root turn)
//   - 4 installation spots, 2 context-window spots
//   - derived relation: turn_id's embedded timestamp − turn_started_at_unix_ms == −1 ms
//
// Keys are fixed fake bytes. No real key material ever enters a test.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/tidwall/gjson"
)

const (
	codexIdentityTestKeyA = "fence-account-key-A"
	codexIdentityTestKeyB = "fence-account-key-B"

	// A fixed wall clock keeps the fence deterministic; only the millisecond
	// RELATIONS between the values matter, and those are experiment 5's.
	codexIdentityTestTurnStartedMs = int64(1758000000000)
	codexIdentityTestTurnMs        = codexIdentityTestTurnStartedMs - 1 // derived: −1 ms
	codexIdentityTestSessionMs     = codexIdentityTestTurnStartedMs - 7000
	codexIdentityTestContextMs     = codexIdentityTestTurnStartedMs - 5000

	// installation_id is the only v4 in the shape (Codex: Uuid::new_v4);
	// session / thread / turn / context window are v7 (Uuid::now_v7).
	codexIdentityTestInstallation = "6f1c2d3e-4a5b-4c7d-8e9f-0a1b2c3d4e5f"
	codexIdentityTestWindowSuffix = ":3"
)

var (
	codexIdentityTestSession = codexIdentityTestV7(codexIdentityTestSessionMs, "a01-8b02-c03d04e05f06")
	codexIdentityTestTurn    = codexIdentityTestV7(codexIdentityTestTurnMs, "b11-9c12-d13e14f15061")
	codexIdentityTestContext = codexIdentityTestV7(codexIdentityTestContextMs, "c21-a022-e23f24051627")
	codexIdentityTestWindow  = codexIdentityTestSession + codexIdentityTestWindowSuffix
	// A second window counter, used by the key-order fixture.
	codexIdentityTestWindow7 = codexIdentityTestSession + ":7"

	// Canonical UUID with an RFC 4122 variant nibble — the shape the upstream
	// must keep seeing. Mirrors the regex experiment 5's recorder used.
	codexIdentityTestUUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// codexIdentityTestV7 builds a syntactically valid UUIDv7 carrying ms in its
// leading 48 bits, so the fence can state the millisecond relations experiment 5
// measured instead of hard-coding opaque literals.
func codexIdentityTestV7(ms int64, tail string) string {
	return fmt.Sprintf("%08x-%04x-7%s", uint64(ms)>>16, uint64(ms)&0xffff, tail)
}

// codexIdentityTestV7Millis reads the embedded creation time the same way the
// experiment-5 recorder did: first 12 hex digits, base 16.
func codexIdentityTestV7Millis(t *testing.T, id string) int64 {
	t.Helper()
	digits := strings.ReplaceAll(id, "-", "")
	if len(digits) != 32 {
		t.Fatalf("not a UUID: %q", id)
	}
	ms, err := strconv.ParseInt(digits[:12], 16, 64)
	if err != nil {
		t.Fatalf("UUID %q has no readable timestamp: %v", id, err)
	}
	return ms
}

func codexIdentityTestUUIDVersion(t *testing.T, id string) int {
	t.Helper()
	if !codexIdentityTestUUIDRE.MatchString(id) {
		t.Fatalf("%q is not a canonical RFC 4122 UUID any more", id)
	}
	return int(id[14] - '0')
}

func codexIdentityTestTurnMetadata() string {
	return `{` +
		`"agent_name":"/root",` +
		`"auto_review_enabled":false,` +
		`"context_window_id":"` + codexIdentityTestContext + `",` +
		`"installation_id":"` + codexIdentityTestInstallation + `",` +
		`"node_repl_auto_review_required":false,` +
		`"node_repl_disabled":true,` +
		`"request_kind":"turn",` +
		`"root_turn_id":"` + codexIdentityTestTurn + `",` +
		`"sandbox":"seatbelt",` +
		`"sandbox_mode":"read-only",` +
		`"session_id":"` + codexIdentityTestSession + `",` +
		`"thread_id":"` + codexIdentityTestSession + `",` +
		`"thread_source":"user",` +
		`"turn_id":"` + codexIdentityTestTurn + `",` +
		`"turn_started_at_unix_ms":` + strconv.FormatInt(codexIdentityTestTurnStartedMs, 10) + `,` +
		`"window_id":"` + codexIdentityTestWindow + `",` +
		`"window_number":3}`
}

// codexIdentityTestInput returns a fresh copy of the experiment-5 request shape
// on every call, so a test can compare the inputs it passed in against what the
// rewrite gave back.
func codexIdentityTestInput() (http.Header, []byte) {
	turnMetadata := codexIdentityTestTurnMetadata()

	h := http.Header{}
	h.Set("x-codex-installation-id", codexIdentityTestInstallation)
	h.Set("session-id", codexIdentityTestSession)
	h.Set("thread-id", codexIdentityTestSession)
	h.Set("x-client-request-id", codexIdentityTestSession)
	h.Set("x-codex-window-id", codexIdentityTestWindow)
	h.Set("x-codex-turn-metadata", turnMetadata)
	h.Set("originator", "codex_cli_rs") // not an identifier: must survive untouched

	// strconv.Quote is a valid JSON string escape for this ASCII-only fixture.
	body := []byte(`{"model":"gpt-5-codex","input":[],"store":false,"stream":true,` +
		`"prompt_cache_key":"` + codexIdentityTestSession + `",` +
		`"client_metadata":{` +
		`"root_turn_id":"` + codexIdentityTestTurn + `",` +
		`"session_id":"` + codexIdentityTestSession + `",` +
		`"thread_id":"` + codexIdentityTestSession + `",` +
		`"turn_id":"` + codexIdentityTestTurn + `",` +
		`"x-codex-installation-id":"` + codexIdentityTestInstallation + `",` +
		`"x-codex-turn-metadata":` + strconv.Quote(turnMetadata) + `,` +
		`"x-codex-window-id":"` + codexIdentityTestWindow + `"}}`)
	return h, body
}

func codexIdentityTestObject(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		t.Fatalf("not a JSON object (%v): %s", err, raw)
	}
	return obj
}

func codexIdentityTestString(t *testing.T, obj map[string]json.RawMessage, key string) string {
	t.Helper()
	raw, ok := obj[key]
	if !ok {
		t.Fatalf("key %q is gone — the rewrite dropped a carrier it had to fill", key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("key %q is not a string any more: %v", key, err)
	}
	return s
}

func codexIdentityTestInt(t *testing.T, obj map[string]json.RawMessage, key string) int64 {
	t.Helper()
	raw, ok := obj[key]
	if !ok {
		t.Fatalf("key %q is gone — the rewrite dropped a carrier it had to fill", key)
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatalf("key %q is not an integer any more: %v", key, err)
	}
	return n
}

// codexIdentityTestChild reads a nested JSON object (client_metadata).
func codexIdentityTestChild(t *testing.T, obj map[string]json.RawMessage, key string) map[string]json.RawMessage {
	t.Helper()
	raw, ok := obj[key]
	if !ok {
		t.Fatalf("key %q is gone — the rewrite dropped a carrier it had to fill", key)
	}
	return codexIdentityTestObject(t, raw)
}

// codexIdentityTestChildText reads a nested JSON object that travels as a JSON
// STRING (client_metadata["x-codex-turn-metadata"]).
func codexIdentityTestChildText(t *testing.T, obj map[string]json.RawMessage, key string) map[string]json.RawMessage {
	t.Helper()
	return codexIdentityTestObject(t, []byte(codexIdentityTestString(t, obj, key)))
}

// codexIdentityTestAllEqual asserts that every carrier of one identifier holds
// the same new value, and that none of them still holds the original.
func codexIdentityTestAllEqual(t *testing.T, group string, spots map[string]string, original string) string {
	t.Helper()
	names := make([]string, 0, len(spots))
	for name := range spots {
		names = append(names, name)
	}
	sort.Strings(names)

	first, firstName := "", ""
	for _, name := range names {
		got := spots[name]
		switch {
		case got == "":
			t.Fatalf("%s group: %s is empty — a carrier lost its identifier", group, name)
		case got == original:
			t.Fatalf("%s group: %s still carries the ORIGINAL value — the alias never reached this carrier", group, name)
		case firstName == "":
			first, firstName = got, name
		case got != first:
			t.Fatalf("%s group broke: %s = %s but %s = %s", group, name, got, firstName, first)
		}
	}
	return first
}

// codexIdentityTestAssertNoAikeyHeaders guards the red line: nothing bound for
// the LLM upstream may carry an X-Aikey-* header.
func codexIdentityTestAssertNoAikeyHeaders(t *testing.T, h http.Header) {
	t.Helper()
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-aikey-") {
			t.Fatalf("red line: the rewrite produced upstream-bound header %q", name)
		}
	}
}

// codexIdentityTestView is what one account's upstream request looks like after
// the rewrite, reduced to the four identifier categories plus the turn clock.
type codexIdentityTestView struct {
	header                                             http.Header
	body                                               []byte
	installation, session, turn, contextWindow, window string
	turnStartedMs                                      int64
}

func codexIdentityTestRewrite(t *testing.T, key string) codexIdentityTestView {
	t.Helper()
	h, body := codexIdentityTestInput()
	outH, outBody, rep := rewriteCodexIdentity(h, body, []byte(key))
	if len(rep.Dropped) != 0 {
		t.Fatalf("key %q: nothing in the experiment-5 shape may be dropped, got %v", key, rep.Dropped)
	}
	codexIdentityTestAssertNoAikeyHeaders(t, outH)
	turnMetadata := codexIdentityTestObject(t, []byte(outH.Get("x-codex-turn-metadata")))
	return codexIdentityTestView{
		header:        outH,
		body:          outBody,
		installation:  codexIdentityTestString(t, turnMetadata, "installation_id"),
		session:       codexIdentityTestString(t, turnMetadata, "session_id"),
		turn:          codexIdentityTestString(t, turnMetadata, "turn_id"),
		contextWindow: codexIdentityTestString(t, turnMetadata, "context_window_id"),
		window:        codexIdentityTestString(t, turnMetadata, "window_id"),
		turnStartedMs: codexIdentityTestInt(t, turnMetadata, "turn_started_at_unix_ms"),
	}
}

// 2.A1 — the experiment-5 shape keeps every equality group, every UUID version
// and the window_id structure after one account's rewrite.
func TestRewriteCodexIdentity_KeepsEqualityGroupsAndUUIDVersions(t *testing.T) {
	h, body := codexIdentityTestInput()
	headerBefore, bodyBefore := h.Clone(), bytes.Clone(body)

	outH, outBody, rep := rewriteCodexIdentity(h, body, []byte(codexIdentityTestKeyA))

	// Pure function: the caller must still be able to replay the original request.
	if !reflect.DeepEqual(h, headerBefore) {
		t.Fatalf("the inbound header was mutated in place:\n got %v\nwant %v", h, headerBefore)
	}
	if !bytes.Equal(body, bodyBefore) {
		t.Fatalf("the inbound body was mutated in place:\n got %s\nwant %s", body, bodyBefore)
	}
	if len(rep.Dropped) != 0 {
		t.Fatalf("nothing in the experiment-5 shape may be dropped, got %v", rep.Dropped)
	}

	headerTM := codexIdentityTestObject(t, []byte(outH.Get("x-codex-turn-metadata")))
	bodyObj := codexIdentityTestObject(t, outBody)
	clientMetadata := codexIdentityTestChild(t, bodyObj, "client_metadata")
	nestedTM := codexIdentityTestChildText(t, clientMetadata, "x-codex-turn-metadata")

	sessionSpots := map[string]string{
		"hdr:session-id":          outH.Get("session-id"),
		"hdr:thread-id":           outH.Get("thread-id"),
		"hdr:x-client-request-id": outH.Get("x-client-request-id"),
		"tm:session_id":           codexIdentityTestString(t, headerTM, "session_id"),
		"tm:thread_id":            codexIdentityTestString(t, headerTM, "thread_id"),
		"cm:session_id":           codexIdentityTestString(t, clientMetadata, "session_id"),
		"cm:thread_id":            codexIdentityTestString(t, clientMetadata, "thread_id"),
		"cm.tm:session_id":        codexIdentityTestString(t, nestedTM, "session_id"),
		"cm.tm:thread_id":         codexIdentityTestString(t, nestedTM, "thread_id"),
		"body:prompt_cache_key":   codexIdentityTestString(t, bodyObj, "prompt_cache_key"),
	}
	if len(sessionSpots) != 10 {
		t.Fatalf("the fence itself is wrong: experiment 5 has 10 direct session spots, this checks %d", len(sessionSpots))
	}
	session := codexIdentityTestAllEqual(t, "session", sessionSpots, codexIdentityTestSession)

	turn := codexIdentityTestAllEqual(t, "turn", map[string]string{
		"tm:turn_id":         codexIdentityTestString(t, headerTM, "turn_id"),
		"tm:root_turn_id":    codexIdentityTestString(t, headerTM, "root_turn_id"),
		"cm:turn_id":         codexIdentityTestString(t, clientMetadata, "turn_id"),
		"cm:root_turn_id":    codexIdentityTestString(t, clientMetadata, "root_turn_id"),
		"cm.tm:turn_id":      codexIdentityTestString(t, nestedTM, "turn_id"),
		"cm.tm:root_turn_id": codexIdentityTestString(t, nestedTM, "root_turn_id"),
	}, codexIdentityTestTurn)

	installation := codexIdentityTestAllEqual(t, "installation", map[string]string{
		"hdr:x-codex-installation-id": outH.Get("x-codex-installation-id"),
		"tm:installation_id":          codexIdentityTestString(t, headerTM, "installation_id"),
		"cm:x-codex-installation-id":  codexIdentityTestString(t, clientMetadata, "x-codex-installation-id"),
		"cm.tm:installation_id":       codexIdentityTestString(t, nestedTM, "installation_id"),
	}, codexIdentityTestInstallation)

	contextWindow := codexIdentityTestAllEqual(t, "context window", map[string]string{
		"tm:context_window_id":    codexIdentityTestString(t, headerTM, "context_window_id"),
		"cm.tm:context_window_id": codexIdentityTestString(t, nestedTM, "context_window_id"),
	}, codexIdentityTestContext)

	window := codexIdentityTestAllEqual(t, "window", map[string]string{
		"hdr:x-codex-window-id": outH.Get("x-codex-window-id"),
		"cm:x-codex-window-id":  codexIdentityTestString(t, clientMetadata, "x-codex-window-id"),
		"tm:window_id":          codexIdentityTestString(t, headerTM, "window_id"),
		"cm.tm:window_id":       codexIdentityTestString(t, nestedTM, "window_id"),
	}, codexIdentityTestWindow)

	if want := session + codexIdentityTestWindowSuffix; window != want {
		t.Fatalf("window_id = %q, want %q: the prefix must be the NEW session id and the counter must be kept", window, want)
	}

	for _, c := range []struct {
		name        string
		got         string
		wantVersion int
	}{
		{"installation_id", installation, 4},
		{"session_id", session, 7},
		{"turn_id", turn, 7},
		{"context_window_id", contextWindow, 7},
	} {
		if got := codexIdentityTestUUIDVersion(t, c.got); got != c.wantVersion {
			t.Fatalf("%s = %s is a v%d, want v%d: the upstream must keep seeing the shape Codex mints", c.name, c.got, got, c.wantVersion)
		}
	}

	// One derivation per category: installation, session, turn, context window.
	// window_id is composed from the session alias, not derived on its own.
	if rep.Kinds != 4 {
		t.Fatalf("Kinds = %d, want 4 (installation / session / turn / context window)", rep.Kinds)
	}

	// The account's time offset: one value, applied to every v7 timestamp and to
	// turn_started_at_unix_ms, moving backwards by at most 60 s (design §5.5).
	started := codexIdentityTestInt(t, headerTM, "turn_started_at_unix_ms")
	offset := started - codexIdentityTestTurnStartedMs
	t.Logf("account offset %d ms; installation %s; session %s; turn %s; context %s",
		offset, installation, session, turn, contextWindow)
	if offset > 0 || offset < -60000 {
		t.Fatalf("time offset = %d ms, want within [-60000, 0]", offset)
	}
	for _, c := range []struct {
		name  string
		got   string
		wasMs int64
	}{
		{"session_id", session, codexIdentityTestSessionMs},
		{"turn_id", turn, codexIdentityTestTurnMs},
		{"context_window_id", contextWindow, codexIdentityTestContextMs},
	} {
		if got := codexIdentityTestV7Millis(t, c.got) - c.wasMs; got != offset {
			t.Fatalf("%s moved by %d ms but turn_started_at_unix_ms moved by %d: one offset per account, or the relative distances break", c.name, got, offset)
		}
	}
	if got := codexIdentityTestV7Millis(t, turn) - started; got != -1 {
		t.Fatalf("turn id timestamp - turn_started_at_unix_ms = %d ms, want -1 (experiment 5's derived relation)", got)
	}
	if got := codexIdentityTestInt(t, nestedTM, "turn_started_at_unix_ms"); got != started {
		t.Fatalf("nested turn_started_at_unix_ms = %d, header says %d: the same original value must be filled identically everywhere", got, started)
	}

	// Everything that is not an identifier travels untouched, version info included.
	for _, c := range []struct {
		where string
		obj   map[string]json.RawMessage
		key   string
		want  string
	}{
		{"tm", headerTM, "agent_name", "/root"},
		{"tm", headerTM, "sandbox", "seatbelt"},
		{"tm", headerTM, "sandbox_mode", "read-only"},
		{"tm", headerTM, "request_kind", "turn"},
		{"tm", headerTM, "thread_source", "user"},
		{"cm.tm", nestedTM, "agent_name", "/root"},
		{"body", bodyObj, "model", "gpt-5-codex"},
	} {
		if got := codexIdentityTestString(t, c.obj, c.key); got != c.want {
			t.Fatalf("%s.%s = %q, want %q: only identifiers may change", c.where, c.key, got, c.want)
		}
	}
	if got := codexIdentityTestInt(t, headerTM, "window_number"); got != 3 {
		t.Fatalf("tm.window_number = %d, want 3", got)
	}
	if got := outH.Get("originator"); got != "codex_cli_rs" {
		t.Fatalf("originator header = %q, want codex_cli_rs: only identifier headers may change", got)
	}
	if got := string(bodyObj["store"]); got != "false" {
		t.Fatalf("body.store = %s, want false", got)
	}

	codexIdentityTestAssertNoAikeyHeaders(t, outH)

	// Deterministic: the same account key must mint the same aliases, or a
	// follow-up request would look like a brand new device.
	h2, body2 := codexIdentityTestInput()
	outH2, outBody2, rep2 := rewriteCodexIdentity(h2, body2, []byte(codexIdentityTestKeyA))
	if !reflect.DeepEqual(outH, outH2) || !bytes.Equal(outBody, outBody2) || rep2.Kinds != rep.Kinds {
		t.Fatalf("the rewrite is not deterministic for one key:\n first %v %s\nsecond %v %s", outH, outBody, outH2, outBody2)
	}
}

// 2.A2 — two account keys mint unrelated identifiers and unrelated times, while
// each side stays internally consistent (R-codex-identity-rewrite-3.S1).
func TestRewriteCodexIdentity_DifferentKeysUnrelated(t *testing.T) {
	a := codexIdentityTestRewrite(t, codexIdentityTestKeyA)
	b := codexIdentityTestRewrite(t, codexIdentityTestKeyB)

	for _, c := range []struct {
		name string
		x, y string
	}{
		{"installation_id", a.installation, b.installation},
		{"session_id", a.session, b.session},
		{"turn_id", a.turn, b.turn},
		{"context_window_id", a.contextWindow, b.contextWindow},
		{"window_id", a.window, b.window},
	} {
		if c.x == c.y {
			t.Fatalf("%s is identical under two account keys (%s): the two accounts stay linked", c.name, c.x)
		}
	}

	t.Logf("A: started %d, session %s, installation %s", a.turnStartedMs, a.session, a.installation)
	t.Logf("B: started %d, session %s, installation %s", b.turnStartedMs, b.session, b.installation)
	if a.turnStartedMs == b.turnStartedMs {
		t.Fatalf("turn_started_at_unix_ms is %d under both account keys: the millisecond time must differ", a.turnStartedMs)
	}
	if codexIdentityTestV7Millis(t, a.turn) == codexIdentityTestV7Millis(t, b.turn) {
		t.Fatalf("the turn id carries the same embedded millisecond under both account keys")
	}

	// The 1 ms gap experiment 5 measured survives on BOTH sides.
	for _, side := range []struct {
		name string
		view codexIdentityTestView
	}{{"A", a}, {"B", b}} {
		if got := codexIdentityTestV7Millis(t, side.view.turn) - side.view.turnStartedMs; got != -1 {
			t.Fatalf("account %s: turn id timestamp - turn_started_at_unix_ms = %d ms, want -1", side.name, got)
		}
		if side.view.session == codexIdentityTestSession || side.view.installation == codexIdentityTestInstallation {
			t.Fatalf("account %s still ships an original identifier upstream", side.name)
		}
		codexIdentityTestAssertNoAikeyHeaders(t, side.view.header)
	}
}

// ── R-codex-identity-rewrite-2 · a forked thread's parent references ────────

// A fork quotes the conversation it branched from: the parent THREAD id rides in
// the x-codex-parent-thread-id header and in forked_from_thread_id inside the
// metadata blobs, and the turn it branched at rides in parent_turn_id. These are
// the only carriers whose original value belongs to an EARLIER request, which is
// what earns them their own fence:
//
//   - They must be rewritten. x-codex-parent-thread-id is named field by field in
//     R-codex-identity-rewrite-2, and a thread id reaching the upstream verbatim
//     re-links whichever account served the parent conversation — exactly what
//     R-codex-identity-rewrite-1 forbids (原始值 MUST NOT 到达上游).
//   - They must be rewritten to the SAME alias the parent value received when it
//     was the CURRENT thread / turn. That falls out of mapping by original value
//     (rule 1 in codex_identity_rewrite.go) and is why the fork link still holds
//     upstream: an alias depends only on the account key and the original value,
//     never on which request the value appears in.
//
// Experiment 5 recorded no fork, so this shape is the exp-5 shape plus the three
// fork carriers, and its equality relations are the ones
// R-codex-identity-rewrite-2.S1 states rather than ones the experiment measured.
const (
	codexIdentityTestParentThreadMs = codexIdentityTestTurnStartedMs - 90_000
	codexIdentityTestParentTurnMs   = codexIdentityTestTurnStartedMs - 61_000
)

var (
	codexIdentityTestParentThread = codexIdentityTestV7(codexIdentityTestParentThreadMs, "d31-8e32-f33041526374")
	codexIdentityTestParentTurn   = codexIdentityTestV7(codexIdentityTestParentTurnMs, "e41-9f42-031415926535")
)

// codexIdentityTestForkMetadata is a forked thread's turn-metadata blob: the
// exp-5 identifier keys plus the two fork references.
func codexIdentityTestForkMetadata() string {
	return `{"forked_from_thread_id":"` + codexIdentityTestParentThread + `",` +
		`"installation_id":"` + codexIdentityTestInstallation + `",` +
		`"parent_turn_id":"` + codexIdentityTestParentTurn + `",` +
		`"root_turn_id":"` + codexIdentityTestTurn + `",` +
		`"session_id":"` + codexIdentityTestSession + `",` +
		`"thread_id":"` + codexIdentityTestSession + `",` +
		`"thread_source":"fork",` +
		`"turn_id":"` + codexIdentityTestTurn + `",` +
		`"turn_started_at_unix_ms":` + strconv.FormatInt(codexIdentityTestTurnStartedMs, 10) + `}`
}

// codexIdentityTestForkInput carries the three fork carriers in every carrier
// kind the rewrite knows: a standalone header, the turn-metadata header blob,
// client_metadata, and the blob nested inside client_metadata.
func codexIdentityTestForkInput() (http.Header, []byte) {
	metadata := codexIdentityTestForkMetadata()

	h := http.Header{}
	h.Set("x-codex-installation-id", codexIdentityTestInstallation)
	h.Set("session-id", codexIdentityTestSession)
	h.Set("thread-id", codexIdentityTestSession)
	h.Set("x-codex-parent-thread-id", codexIdentityTestParentThread)
	h.Set("x-codex-turn-metadata", metadata)

	body := []byte(`{"model":"gpt-5-codex","input":[],"store":false,"stream":true,` +
		`"prompt_cache_key":"` + codexIdentityTestSession + `",` +
		`"client_metadata":{` +
		`"forked_from_thread_id":"` + codexIdentityTestParentThread + `",` +
		`"parent_turn_id":"` + codexIdentityTestParentTurn + `",` +
		`"session_id":"` + codexIdentityTestSession + `",` +
		`"thread_id":"` + codexIdentityTestSession + `",` +
		`"turn_id":"` + codexIdentityTestTurn + `",` +
		// client_metadata mirrors the header-style names too — exp 5 recorded
		// x-codex-installation-id and x-codex-window-id there — so the parent
		// thread id has a mirror spot as well, and R-codex-identity-rewrite-2
		// wants every occurrence of one original value replaced (Ruling-23).
		`"x-codex-parent-thread-id":"` + codexIdentityTestParentThread + `",` +
		`"x-codex-turn-metadata":` + strconv.Quote(metadata) + `}}`)
	return h, body
}

// spec: R-codex-identity-rewrite-2 按原值映射改写（含 x-codex-parent-thread-id /
// parent_turn_id / forked_from_thread_id）
// spec: R-codex-identity-rewrite-2.S1 parent_turn_id / forked_from_thread_id 若
// 出现，与对应字段的别名一致
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
func TestRewriteCodexIdentity_ForkedThreadKeepsParentReferences(t *testing.T) {
	h, body := codexIdentityTestForkInput()

	outH, outBody, rep := rewriteCodexIdentity(h, body, []byte(codexIdentityTestKeyA))
	if len(rep.Dropped) != 0 {
		t.Fatalf("nothing in a well-formed fork request may be dropped, got %v", rep.Dropped)
	}

	headerTM := codexIdentityTestObject(t, []byte(outH.Get("x-codex-turn-metadata")))
	bodyObj := codexIdentityTestObject(t, outBody)
	clientMetadata := codexIdentityTestChild(t, bodyObj, "client_metadata")
	nestedTM := codexIdentityTestChildText(t, clientMetadata, "x-codex-turn-metadata")

	// Every carrier of the parent THREAD id holds one alias, and none of them
	// holds the client's own value.
	parentThread := codexIdentityTestAllEqual(t, "parent thread", map[string]string{
		"hdr:x-codex-parent-thread-id": outH.Get("x-codex-parent-thread-id"),
		"cm:x-codex-parent-thread-id":  codexIdentityTestString(t, clientMetadata, "x-codex-parent-thread-id"),
		"tm:forked_from_thread_id":     codexIdentityTestString(t, headerTM, "forked_from_thread_id"),
		"cm:forked_from_thread_id":     codexIdentityTestString(t, clientMetadata, "forked_from_thread_id"),
		"cm.tm:forked_from_thread_id":  codexIdentityTestString(t, nestedTM, "forked_from_thread_id"),
	}, codexIdentityTestParentThread)

	parentTurn := codexIdentityTestAllEqual(t, "parent turn", map[string]string{
		"tm:parent_turn_id":    codexIdentityTestString(t, headerTM, "parent_turn_id"),
		"cm:parent_turn_id":    codexIdentityTestString(t, clientMetadata, "parent_turn_id"),
		"cm.tm:parent_turn_id": codexIdentityTestString(t, nestedTM, "parent_turn_id"),
	}, codexIdentityTestParentTurn)

	// Both stay UUIDv7: the upstream parses these the same way it parses the
	// current thread and turn.
	for _, c := range []struct {
		name string
		got  string
	}{{"x-codex-parent-thread-id / forked_from_thread_id", parentThread}, {"parent_turn_id", parentTurn}} {
		if got := codexIdentityTestUUIDVersion(t, c.got); got != 7 {
			t.Fatalf("%s = %s is a v%d, want v7", c.name, c.got, got)
		}
	}

	// Distinct originals must stay distinct: a fork whose parent thread collapsed
	// onto the current thread's alias would tell the upstream this conversation
	// branched from itself.
	currentThread := codexIdentityTestString(t, headerTM, "thread_id")
	currentTurn := codexIdentityTestString(t, headerTM, "turn_id")
	if parentThread == currentThread {
		t.Fatalf("the fork parent and the current thread share one alias (%s): two different original values must map to two different aliases", parentThread)
	}
	if parentTurn == currentTurn {
		t.Fatalf("the parent turn and the current turn share one alias (%s)", parentTurn)
	}
	// installation + session/thread + turn + parent thread + parent turn.
	if rep.Kinds != 5 {
		t.Fatalf("Kinds = %d, want 5 (installation / session / turn / parent thread / parent turn) — a missing derivation means a carrier traveled untouched", rep.Kinds)
	}

	// The alias of a parent value must not depend on WHERE it appears. An earlier
	// request, where those same two values were the CURRENT thread and turn, has
	// to produce the very same aliases — otherwise the fork points at a
	// conversation the upstream never saw under that name.
	earlierH := http.Header{}
	earlierH.Set("thread-id", codexIdentityTestParentThread)
	earlierH.Set("x-codex-turn-metadata",
		`{"thread_id":"`+codexIdentityTestParentThread+`","turn_id":"`+codexIdentityTestParentTurn+`"}`)
	earlierOutH, _, earlierRep := rewriteCodexIdentity(earlierH, nil, []byte(codexIdentityTestKeyA))
	if len(earlierRep.Dropped) != 0 {
		t.Fatalf("the earlier request may not drop anything either, got %v", earlierRep.Dropped)
	}
	earlierTM := codexIdentityTestObject(t, []byte(earlierOutH.Get("x-codex-turn-metadata")))
	if got := earlierOutH.Get("thread-id"); got != parentThread {
		t.Fatalf("the parent thread's alias changed with its position: %q as the current thread vs %q as the fork parent — the fork would point at a conversation the upstream never saw under that name", got, parentThread)
	}
	if got := codexIdentityTestString(t, earlierTM, "turn_id"); got != parentTurn {
		t.Fatalf("the parent turn's alias changed with its position: %q as the current turn vs %q as parent_turn_id", got, parentTurn)
	}

	codexIdentityTestAssertNoAikeyHeaders(t, outH)
	codexIdentityTestAssertNoAikeyHeaders(t, earlierOutH)
}

// Malformed carriers must never panic; they are removed from the outbound
// request (an identifier we cannot alias must not travel upstream as-is) and
// named in rewriteReport.Dropped, which is what the caller WARNs from.
func TestRewriteCodexIdentity_MalformedCarriersAreDropped(t *testing.T) {
	h, body := codexIdentityTestInput()
	h.Set("x-codex-turn-metadata", `{"session_id": not json`)
	h.Set("session-id", "not-a-uuid")

	outH, outBody, rep := rewriteCodexIdentity(h, body, []byte(codexIdentityTestKeyA))

	if got := outH.Get("x-codex-turn-metadata"); got != "" {
		t.Fatalf("an unparsable turn-metadata header must not travel upstream, got %q", got)
	}
	if got := outH.Get("session-id"); got != "" {
		t.Fatalf("an unparsable session-id must not travel upstream, got %q", got)
	}
	if want := []string{"session-id", "x-codex-turn-metadata"}; !reflect.DeepEqual(rep.Dropped, want) {
		t.Fatalf("Dropped = %v, want %v", rep.Dropped, want)
	}

	// The carriers that were still readable are rewritten as usual.
	bodyObj := codexIdentityTestObject(t, outBody)
	if got := codexIdentityTestString(t, bodyObj, "prompt_cache_key"); got == codexIdentityTestSession {
		t.Fatal("one bad header must not switch the rest of the rewrite off")
	}
	if got := outH.Get("thread-id"); got == "" || got == codexIdentityTestSession {
		t.Fatalf("thread-id = %q: it was well-formed and must still be rewritten", got)
	}

	// A body that is not JSON cannot be rewritten and cannot be removed either:
	// it is handed back untouched and reported, so the caller decides.
	h2, _ := codexIdentityTestInput()
	_, outBody2, rep2 := rewriteCodexIdentity(h2, []byte("not json at all"), []byte(codexIdentityTestKeyA))
	if string(outBody2) != "not json at all" {
		t.Fatalf("an unparsable body must come back untouched, got %s", outBody2)
	}
	if !slices.Contains(rep2.Dropped, "body") {
		t.Fatalf("Dropped = %v, want it to name the body", rep2.Dropped)
	}

	// Without an account key nothing can be derived: fail closed, rewrite nothing.
	h3, body3 := codexIdentityTestInput()
	outH3, outBody3, rep3 := rewriteCodexIdentity(h3, body3, nil)
	if outH3.Get("session-id") != codexIdentityTestSession || !bytes.Equal(outBody3, body3) {
		t.Fatal("with no account key the request must come back unchanged for the caller to refuse")
	}
	if !slices.Contains(rep3.Dropped, "key") || rep3.Kinds != 0 {
		t.Fatalf("report = %+v, want Kinds 0 and the missing key named", rep3)
	}
}

// codexIdentityTestOrderedInput is the experiment-5 shape again, but with the
// keys in deliberately NON-alphabetical order at every level, insignificant
// whitespace between them, and an untouched nested object. A rewrite that
// decodes and re-encodes the document cannot reproduce this byte layout, which
// is exactly what this fixture is for.
func codexIdentityTestOrderedInput() (http.Header, []byte) {
	turnMetadata := `{"window_id":"` + codexIdentityTestWindow7 + `",` +
		`"installation_id":"` + codexIdentityTestInstallation + `",` +
		`"turn_started_at_unix_ms":` + strconv.FormatInt(codexIdentityTestTurnStartedMs, 10) + `,` +
		`"agent_name":"/root",` +
		`"session_id":"` + codexIdentityTestSession + `",` +
		`"context_window_id":"` + codexIdentityTestContext + `",` +
		`"thread_id":"` + codexIdentityTestSession + `",` +
		`"turn_id":"` + codexIdentityTestTurn + `",` +
		`"root_turn_id":"` + codexIdentityTestTurn + `",` +
		`"sandbox_mode":"read-only","window_number":7,"auto_review_enabled":false}`

	h := http.Header{}
	h.Set("x-codex-turn-metadata", turnMetadata)
	h.Set("session-id", codexIdentityTestSession)
	h.Set("x-codex-window-id", codexIdentityTestWindow7)

	body := []byte(`{"stream":true, "model":"gpt-5-codex",` + "\n" +
		` "client_metadata":{"x-codex-window-id":"` + codexIdentityTestWindow7 + `",` +
		`"turn_id":"` + codexIdentityTestTurn + `",` +
		`"x-codex-turn-metadata":` + strconv.Quote(turnMetadata) + `,` +
		`"session_id":"` + codexIdentityTestSession + `",` +
		`"x-codex-installation-id":"` + codexIdentityTestInstallation + `",` +
		`"originator":"codex_cli_rs","nested":{"z":1,"a":[2,3],"m":{"deep":"keep"}}},` +
		`"prompt_cache_key":"` + codexIdentityTestSession + `","store":false,` +
		`"input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}`)
	return h, body
}

// codexIdentityTestPlaceholders swaps one account's four identifier values and
// its shifted start time for fixed placeholders, so an inbound and an outbound
// document can be compared byte for byte everywhere else.
func codexIdentityTestPlaceholders(doc, session, turn, installation, contextWindow string, startedMs int64) string {
	return strings.NewReplacer(
		session, "<SESSION>",
		turn, "<TURN>",
		installation, "<INSTALLATION>",
		contextWindow, "<CONTEXT>",
		strconv.FormatInt(startedMs, 10), "<STARTED>",
	).Replace(doc)
}

// The rewrite must be a value-for-value splice: key order, spacing and every
// untouched field have to reach the upstream exactly as the Codex client sent
// them. Codex-bound bodies travel byte-identical today (normalizeCodexRequest
// returns them untouched when it changes nothing, codex_shape_normalize.go:89-112)
// and the S0 live-upstream round was validated with an order-preserving shim, so
// re-serializing here would be the first thing in the chain to reorder keys.
func TestRewriteCodexIdentity_PreservesKeyOrderAndUntouchedFields(t *testing.T) {
	h, body := codexIdentityTestOrderedInput()
	inboundTM := h.Get("x-codex-turn-metadata")

	outH, outBody, rep := rewriteCodexIdentity(h, body, []byte(codexIdentityTestKeyA))
	if len(rep.Dropped) != 0 {
		t.Fatalf("nothing may be dropped from a well-formed request, got %v", rep.Dropped)
	}

	outboundTM := outH.Get("x-codex-turn-metadata")
	tm := codexIdentityTestObject(t, []byte(outboundTM))
	session := codexIdentityTestString(t, tm, "session_id")
	turn := codexIdentityTestString(t, tm, "turn_id")
	installation := codexIdentityTestString(t, tm, "installation_id")
	contextWindow := codexIdentityTestString(t, tm, "context_window_id")
	started := codexIdentityTestInt(t, tm, "turn_started_at_unix_ms")

	// The fence must not be able to pass by doing nothing.
	if session == codexIdentityTestSession || rep.Kinds != 4 {
		t.Fatalf("the rewrite did not happen: session %s, Kinds %d", session, rep.Kinds)
	}

	inbound := codexIdentityTestPlaceholders(string(body),
		codexIdentityTestSession, codexIdentityTestTurn, codexIdentityTestInstallation,
		codexIdentityTestContext, codexIdentityTestTurnStartedMs)
	outbound := codexIdentityTestPlaceholders(string(outBody),
		session, turn, installation, contextWindow, started)
	if inbound != outbound {
		t.Fatalf("the body changed outside the rewritten values:\ninbound  %s\noutbound %s", inbound, outbound)
	}

	inboundHeader := codexIdentityTestPlaceholders(inboundTM,
		codexIdentityTestSession, codexIdentityTestTurn, codexIdentityTestInstallation,
		codexIdentityTestContext, codexIdentityTestTurnStartedMs)
	outboundHeader := codexIdentityTestPlaceholders(outboundTM,
		session, turn, installation, contextWindow, started)
	if inboundHeader != outboundHeader {
		t.Fatalf("the turn-metadata header changed outside the rewritten values:\ninbound  %s\noutbound %s",
			inboundHeader, outboundHeader)
	}

	// Every field nobody listed in the tables must come back as the same raw JSON.
	for _, path := range []string{
		"stream", "model", "store", "input", "input.0.content.0.text",
		"client_metadata.originator", "client_metadata.nested",
		"client_metadata.nested.a", "client_metadata.nested.m.deep",
	} {
		in := gjson.GetBytes(body, path).Raw
		out := gjson.GetBytes(outBody, path).Raw
		if in == "" {
			t.Fatalf("the fence itself is wrong: %s is not in the fixture", path)
		}
		if in != out {
			t.Fatalf("untouched field %s changed: %s -> %s", path, in, out)
		}
	}
	for _, path := range []string{"agent_name", "sandbox_mode", "window_number", "auto_review_enabled"} {
		in := gjson.Get(inboundTM, path).Raw
		out := gjson.Get(outboundTM, path).Raw
		if in == "" || in != out {
			t.Fatalf("untouched turn-metadata field %s changed: %s -> %s", path, in, out)
		}
	}
}

// ── R-codex-identity-rewrite-5 · the turn-state guard ───────────────────────
//
// x-codex-turn-state is opaque UPSTREAM state, minted by the account that served
// an earlier request of the same turn. Rewriting it is meaningless (only the
// upstream can read it); forwarding it on another account's credential hands the
// upstream a value it can only have issued to a different account — exactly the
// linkage the rewrite exists to cut, restored by one header.
//
// UD-96 (2026-09-24, option C, user-confirmed): the worker keeps its own ledger,
// and the RESPONSE direction is its only writer — "the upstream issued this value
// on a response to the account that served" is a fact a client cannot forge. The
// request direction only reads it: a turn-state rides along when this worker
// recorded it for the serving account, and is dropped otherwise, including one
// this worker has never seen. The accepted cost: a worker restart, a full ledger
// or a move to another node costs an in-flight turn one drop, re-issued on the
// spot.
//
// Dropping is safe by MEASUREMENT: S0 attempt 2 (2026-09-21, real ChatGPT Codex
// backend) sent a turn carrying no turn-state; the upstream answered 200,
// re-issued one, and reported unchanged cache hits (11520 = 11520) — tasks.md §1
// 出口门.
//
// The fixture is a TWO-account Codex pool behind a device-routing token, driven
// through the real handler chain. The internal account header plays the control
// plane's decision, so "the device was rebound" is simply the next request naming
// the other account. Its upstream stand-in answers the way S0 measured the real
// backend: a response issues a turn-state only when its request arrived without
// one.
//
// spec: R-codex-identity-rewrite-5 丢弃不是当前账号签发的 x-codex-turn-state
// spec: R-codex-identity-rewrite-5.S1 换账号后上游 B 收到的请求不含该头
// spec: R-codex-identity-rewrite-5.S2 设备重绑后，发往新账号的第一个请求不带旧 turn-state（跨节点、同节点首次出现）
// spec: R-codex-identity-rewrite-5.S3 本 worker 没记过账的 turn-state 一律丢弃
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md

const (
	turnStateVK       = "aikey_team_turnstate"
	turnStateAccountA = "acc-turn-state-a"
	turnStateAccountB = "acc-turn-state-b"
	// turnStateTokenPrefix + account id is each account's delivered access
	// token, so the upstream stand-in can tell from the injected bearer which
	// account's credential made an attempt.
	turnStateTokenPrefix = "pool-oauth-token-"
)

// turnStateAttempt is one request that left the worker, and how the upstream
// answered it.
type turnStateAttempt struct {
	codexRewriteSeen
	// account is the pool account whose credential made this attempt.
	account string
	status  int
	// issued is the turn-state the upstream issued on this response ("" = none).
	issued string
}

// turnStateUpstream records every request that left the worker and answers the
// way S0 measured the real Codex backend (attempt 2, rows 5 and 7): a response
// issues a fresh x-codex-turn-state only when its request arrived WITHOUT one.
// That makes "the upstream re-issued one after the worker dropped it" observable,
// and keeps the ledger's contents predictable leg by leg.
//
// statuses scripts the answers in order (200 once it runs out), so a leg can
// make one attempt fail and watch the seat lane fail over.
//
// Separate from codexRewriteTransport (which never issues a turn-state) so the
// fences already sharing that transport keep exercising exactly what they did.
type turnStateUpstream struct {
	mu       sync.Mutex
	attempts []turnStateAttempt
	issued   int
	statuses []int
}

func (u *turnStateUpstream) RoundTrip(req *http.Request) (*http.Response, error) {
	attempt := turnStateAttempt{
		codexRewriteSeen: codexRewriteSeen{header: req.Header.Clone(), url: req.URL.String()},
		account:          strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "+turnStateTokenPrefix),
		status:           http.StatusOK,
	}
	if req.Body != nil {
		attempt.body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	carried := false
	for _, value := range req.Header.Values(codexTurnStateHeader) {
		carried = carried || value != ""
	}
	header := http.Header{"Content-Type": []string{"application/json"}}
	u.mu.Lock()
	if len(u.statuses) > 0 {
		attempt.status, u.statuses = u.statuses[0], u.statuses[1:]
	}
	if !carried {
		u.issued++
		attempt.issued = "turn-state-issued-upstream-" + strconv.Itoa(u.issued)
		header.Set(codexTurnStateHeader, attempt.issued)
	}
	u.attempts = append(u.attempts, attempt)
	u.mu.Unlock()
	body := `{"id":"resp_1","object":"response","model":"gpt-5-codex","output":[],` +
		`"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`
	if attempt.status >= http.StatusBadRequest {
		body = `{"error":{"type":"server_error","message":"scripted upstream failure"}}`
	}
	return &http.Response{
		StatusCode: attempt.status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func (u *turnStateUpstream) all() []turnStateAttempt {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]turnStateAttempt(nil), u.attempts...)
}

type turnStatePool struct {
	p        *Proxy
	upstream *turnStateUpstream
}

// newTurnStatePool builds a hermetic two-account Codex pool. Each account carries
// its OWN delivered identity key, as in production, so the rewrite lane — and the
// guard inside it — runs for both.
func newTurnStatePool(t *testing.T, routingConfig string) *turnStatePool {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	key := grKey()
	refs := make([]vkeys.GroupAccountRef, 0, 2)
	mat := map[string]vkeys.GroupRuntimeAccount{}
	for i, id := range []string{turnStateAccountA, turnStateAccountB} {
		refs = append(refs, vkeys.GroupAccountRef{
			AccountID: id, ProviderCode: "openai", ProtocolType: "openai_compatible",
			CredentialID: "cred-" + id,
		})
		mat[id] = encIdentityKey(t, key, encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ProviderCode:   "openai",
			ProtocolType:   "openai_compatible",
			CredentialID:   "cred-" + id,
			ExternalID:     "chatgpt-acct-" + id,
			ExpiresAt:      9_000_000_000,
		}, turnStateTokenPrefix+id), bytes.Repeat([]byte{byte(0x51 + i)}, 32))
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-turn-state", ProtocolType: "openai_compatible", RouteSource: "team",
		SeatID: "seat-turn-state", OauthGroupID: "grp-turn-state",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
		RoutingConfig: routingConfig,
		RouteKind:     routeKindDeviceRoutingToken,
	}
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{turnStateVK: route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	upstream := &turnStateUpstream{}
	p.SetTransport(upstream)
	return &turnStatePool{p: p, upstream: upstream}
}

// newTurnStateSeatPool is the same pool behind an ordinary SEAT route: the
// worker picks the account itself and fails over to another one when an
// attempt fails, which a device-routing token never does. Mirrors
// newCodexRewriteSeatPool (group_serve_rewrite_test.go).
func newTurnStateSeatPool(t *testing.T, routingConfig string) *turnStatePool {
	t.Helper()
	pool := newTurnStatePool(t, routingConfig)
	registered := pool.p.registry.Resolve(turnStateVK)
	if registered == nil {
		t.Fatal("the fixture's virtual key is not registered")
	}
	seat := *registered
	seat.RouteKind = "" // an ordinary seat pool route carries no kind
	pool.p.registry.Merge(map[string]*vkeys.ResolvedRoute{turnStateVK: &seat})
	return pool
}

// turnStateServed is one request seen from both ends of the worker.
type turnStateServed struct {
	status int
	// source is X-Aikey-Error-Source: set only when aikey itself refused.
	source string
	// attempts is every request this one made upstream, in order; upstream is
	// the last of them, nil when the worker refused before dialing.
	attempts []turnStateAttempt
	upstream *turnStateAttempt
	// issued is the turn-state the client received back ("" = none).
	issued string
}

// serve sends one Codex request for the device the control plane currently has
// on accountID, carrying one x-codex-turn-state value per non-empty turnState
// ("" = none).
func (f *turnStatePool) serve(t *testing.T, accountID string, turnStates ...string) turnStateServed {
	t.Helper()
	var values []string
	for _, turnState := range turnStates {
		if turnState != "" {
			values = append(values, turnState)
		}
	}
	return f.serveValues(t, accountID, values...)
}

// serveValues sends one Codex request carrying x-codex-turn-state values
// exactly as given — an empty value included, which a malformed or
// non-official client can send. pinned names the account the control plane
// decided (the device-routing token lane); "" sends no account header, so the
// worker picks on the seat lane.
func (f *turnStatePool) serveValues(t *testing.T, pinned string, values ...string) turnStateServed {
	t.Helper()
	header, body := codexIdentityTestInput()
	for _, value := range values {
		header.Add(codexTurnStateHeader, value)
	}
	req := httptest.NewRequest(http.MethodPost, codexRewriteResponsesPath, bytes.NewReader(body))
	for name, headerValues := range header {
		for _, v := range headerValues {
			req.Header.Add(name, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+turnStateVK)
	if pinned != "" {
		req.Header.Set(headerRouteAccount, pinned)
	}
	before := len(f.upstream.all())
	w := httptest.NewRecorder()
	f.p.Handle(w, req)

	served := turnStateServed{
		status:   w.Code,
		source:   w.Header().Get(HeaderAikeyErrorSource),
		attempts: f.upstream.all()[before:],
		issued:   w.Header().Get(codexTurnStateHeader),
	}
	if pinned != "" && len(served.attempts) > 1 {
		t.Fatalf("one request dialed the upstream %d times — a device-routing token never retries on another account", len(served.attempts))
	}
	for i := range served.attempts {
		// 🔴 RED LINE, on every attempt of every leg. On the device-routing lane
		// the request came in carrying X-Aikey-Route-Account, so the check is
		// never vacuous there.
		codexIdentityTestAssertNoAikeyHeaders(t, served.attempts[i].header)
	}
	if n := len(served.attempts); n > 0 {
		served.upstream = &served.attempts[n-1]
	}
	return served
}

// reached fails the leg unless it was served by the upstream: a leg that never
// got there proves nothing about the guard.
func (s turnStateServed) reached(t *testing.T, leg string) {
	t.Helper()
	if s.status != http.StatusOK || s.upstream == nil {
		t.Fatalf("%s: status %d, reached the upstream = %t — the leg must be served for its claim to mean anything",
			leg, s.status, s.upstream != nil)
	}
}

// forwarded is the turn-state the upstream received on this leg ("" = none).
func (s turnStateServed) forwarded(t *testing.T, leg string) string {
	t.Helper()
	s.reached(t, leg)
	return s.upstream.header.Get(codexTurnStateHeader)
}

// reissued is the turn-state the upstream issued on this leg's response. The
// legs that follow a drop depend on it, so its absence fails loudly instead of
// turning them vacuous.
func (s turnStateServed) reissued(t *testing.T, leg string) string {
	t.Helper()
	s.reached(t, leg)
	if s.issued == "" {
		t.Fatalf("%s: the upstream issued no turn-state on this response — the fixture no longer models S0's re-issue, so the next leg would test nothing", leg)
	}
	return s.issued
}

// useFreshTurnStateMemory gives the caller an empty ledger — what a freshly
// started worker has, since the ledger is deliberately not persisted (UD-96) —
// and puts the process-wide one back afterwards, so legs never see each other's
// records.
func useFreshTurnStateMemory(t *testing.T, limit int) *turnStateOwners {
	t.Helper()
	previous := codexTurnStateOwners
	fresh := newTurnStateOwners(limit)
	codexTurnStateOwners = fresh
	t.Cleanup(func() { codexTurnStateOwners = previous })
	return fresh
}

// assertTurnStateDropLogged checks a drop left its WARN with the reason an
// operator reads: minted_for_another_account (the device moved to another
// account: the linkage guard firing) vs not_recorded_by_this_worker (expected
// after a restart, an eviction or a move from another node). The values are
// pinned literally because they are the log contract.
func assertTurnStateDropLogged(t *testing.T, logs *codexRewriteLogBuffer, reason string) {
	t.Helper()
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `"event.name":"proxy.codex_identity.carrier_dropped"`) &&
			strings.Contains(line, `"x-codex-turn-state"`) &&
			strings.Contains(line, `"reason":"`+reason+`"`) {
			return
		}
	}
	t.Fatalf("no carrier_dropped WARN for x-codex-turn-state with reason %q. logs:\n%s", reason, logs.String())
}

// TestTurnStateGuard_DropsAcrossAccounts: a turn-state rides along only when this
// worker recorded it, from a response, for the account now serving. One leg per
// case the ledger has to get right.
func TestTurnStateGuard_DropsAcrossAccounts(t *testing.T) {
	const (
		a = turnStateAccountA
		b = turnStateAccountB
	)

	t.Run("cross-node rebind: a turn-state this worker never recorded is dropped", func(t *testing.T) {
		// spec: R-codex-identity-rewrite-5.S2 (THEN) / R-codex-identity-rewrite-5.S3
		// The device sat on A behind ANOTHER worker, A's upstream issued T there,
		// and the control plane rebound it to B on this worker. Nothing here ever
		// recorded T — which is exactly what "issued elsewhere" looks like from
		// this worker, so no second node is needed to model it.
		useFreshTurnStateMemory(t, codexTurnStateMemoryCap)
		logs := codexRewriteLogs(t)
		pool := newTurnStatePool(t, codexRewriteSwitchOn)

		first := pool.serve(t, b, "turn-state-issued-through-another-worker")
		if got := first.forwarded(t, "B's first request after the rebind"); got != "" {
			t.Fatalf("B forwarded %q, a turn-state this worker never recorded — it can only have been issued to another account or through another node, so it re-links the accounts", got)
		}
		assertTurnStateDropLogged(t, logs, "not_recorded_by_this_worker")
		// THEN: B's own upstream re-issues one on that same response, the worker
		// records it for B, and the turn carries it from here on.
		reissued := first.reissued(t, "B's first request after the rebind")
		for i := 0; i < 2; i++ {
			if got := pool.serve(t, b, reissued).forwarded(t, "B continuing the turn"); got != reissued {
				t.Fatalf("request %d: B lost the turn-state its own upstream re-issued (%q vs %q) — a drop must cost one re-issue, not the rest of the turn", i, got, reissued)
			}
		}
	})

	t.Run("same-node first sighting after a cooldown refusal is dropped", func(t *testing.T) {
		// spec: R-codex-identity-rewrite-5.S2 (AND) — A and B on ONE worker, and T
		// never seen in a request: while A cooled, the request carrying T was
		// refused BEFORE the rewrite. The only record of T is the response that
		// issued it; a guard that learned from requests has nothing on T and
		// would take it as B's. The ledger does have T — under A — so B drops it
		// as another account's (minted_for_another_account), not as unrecorded.
		useFreshTurnStateMemory(t, codexTurnStateMemoryCap)
		logs := codexRewriteLogs(t)
		pool := newTurnStatePool(t, codexRewriteSwitchOn)

		issuedToA := pool.serve(t, a, "").reissued(t, "A's first request of the turn")
		until := time.Now().Add(90 * time.Second)
		pool.p.poolCooldown.markWithState(a, until, PoolAccountRouteState{Status: poolRouteRateLimited, RetryAt: until.Unix()})
		refused := pool.serve(t, a, issuedToA)
		if refused.status != http.StatusTooManyRequests || refused.upstream != nil ||
			refused.source != observability.ErrCodeDeviceRoutingTokenAccountExhausted {
			t.Fatalf("while A cools, the request carrying T must be refused before the rewrite: status=%d source=%q reached the upstream=%t",
				refused.status, refused.source, refused.upstream != nil)
		}

		// The control plane rebinds the device to B — on this same worker.
		moved := pool.serve(t, b, issuedToA)
		if got := moved.forwarded(t, "B's first request after the rebind"); got != "" {
			t.Fatalf("B forwarded %q, the turn-state A's upstream issued on this worker — it had never been seen in a request (the one carrying it was refused while A cooled), and B took it as its own", got)
		}
		assertTurnStateDropLogged(t, logs, "minted_for_another_account")
		reissued := moved.reissued(t, "B's first request after the rebind")
		if got := pool.serve(t, b, reissued).forwarded(t, "B continuing the turn"); got != reissued {
			t.Fatalf("B lost the turn-state its own upstream re-issued (%q vs %q)", got, reissued)
		}
	})

	t.Run("the serving account keeps what its own upstream issued, and nothing else", func(t *testing.T) {
		// spec: R-codex-identity-rewrite-5.S3 (AND) — consecutive requests of one
		// turn keep the turn-state the serving account's upstream issued, or
		// every hop of a turn would pay for a re-issue.
		//
		// REVERSED 2026-09-24 (UD-96, user-confirmed): this leg used to send a
		// value the client made up and expect it kept, because the worker learned
		// ownership from the FIRST REQUEST carrying a value — so any unseen value
		// was kept once. Under the response-direction ledger, being the serving
		// account is not proof the upstream issued a value to it.
		// spec: R-codex-identity-rewrite-5.S3 本 worker 没记过账的 turn-state 一律丢弃
		useFreshTurnStateMemory(t, codexTurnStateMemoryCap)
		pool := newTurnStatePool(t, codexRewriteSwitchOn)

		issued := pool.serve(t, a, "").reissued(t, "A's first request of the turn")
		for i := 0; i < 2; i++ {
			next := pool.serve(t, a, issued)
			if got := next.forwarded(t, "A continuing the turn"); got != issued {
				t.Fatalf("request %d: upstream turn-state = %q, want %q — the guard dropped a header the serving account's own upstream issued", i, got, issued)
			}
			// The rewrite still happened around it: this is the pool lane.
			codexRewriteAssertNoOriginals(t, "A continuing the turn", next.upstream.codexRewriteSeen)
		}
		madeUp := pool.serve(t, a, "turn-state-the-client-made-up")
		if got := madeUp.forwarded(t, "A carrying a value no upstream issued"); got != "" {
			t.Fatalf("A forwarded %q, a turn-state this worker never recorded for A", got)
		}
		// EVERY value has to qualify, not just the first: a genuine value in front
		// must not carry an unrecorded one past the guard.
		mixed := pool.serve(t, a, issued, "turn-state-riding-behind-a-genuine-one")
		mixed.reached(t, "A carrying its own turn-state plus an unrecorded one")
		if got := mixed.upstream.header.Values(codexTurnStateHeader); len(got) != 0 {
			t.Fatalf("upstream turn-state values = %q — an unrecorded value rode along behind a recorded one", got)
		}
		// Nor may an EMPTY value in front wave the rest through: the guard skips
		// an empty value (it carries no upstream state) and still judges the next
		// one — here A's turn-state, arriving on B's request. Review M1: with the
		// skip turned into "an empty value means keep", A's value left on B's
		// credential and nothing else went red.
		blankFirst := pool.serveValues(t, b, "", issued)
		blankFirst.reached(t, "B carrying an empty value in front of A's turn-state")
		if got := blankFirst.upstream.header.Values(codexTurnStateHeader); len(got) != 0 {
			t.Fatalf("upstream turn-state values = %q — A's turn-state rode along on B's credential behind an empty value", got)
		}
	})

	t.Run("each failover attempt's turn-state is recorded for that attempt's account, error responses included", func(t *testing.T) {
		// spec: R-codex-identity-rewrite-5.S3 当前账号的响应签发新的 turn-state，worker 把它记在当前账号名下
		//
		// The seat lane, where one client request can reach the upstream twice:
		// the first attempt fails, the worker fails over to the other account.
		// Two properties nothing else pins (review M2):
		//  (a) a turn-state issued on an ERROR response is recorded too — it was
		//      issued to the account whose credential made that attempt, whatever
		//      the status. The hook sits before every early return in
		//      ModifyResponse; moving it behind a status check must go red here.
		//  (b) each attempt's turn-state is recorded for THAT attempt's account.
		//      Every attempt starts from a fresh clone of the base request and
		//      only the attempt carries the mark, so a mark that leaked onto the
		//      base request, or named the seat's first-choice account, would file
		//      the failover's turn-state under the wrong account.
		ledger := useFreshTurnStateMemory(t, codexTurnStateMemoryCap)
		pool := newTurnStateSeatPool(t, codexRewriteSwitchOn)
		pool.upstream.statuses = []int{http.StatusInternalServerError}

		served := pool.serveValues(t, "") // no account header: the worker picks
		if served.status != http.StatusOK || len(served.attempts) != 2 {
			t.Fatalf("status %d after %d upstream attempt(s), want 200 after exactly 2 (a 500, then the failover) — otherwise this leg exercises nothing",
				served.status, len(served.attempts))
		}
		failed, recovered := served.attempts[0], served.attempts[1]
		if failed.status != http.StatusInternalServerError || recovered.status != http.StatusOK ||
			failed.account == recovered.account || failed.issued == "" || recovered.issued == "" {
			t.Fatalf("fixture: want a 500 then a 200 from two different accounts, each issuing a turn-state; got %s %d %q, then %s %d %q",
				failed.account, failed.status, failed.issued, recovered.account, recovered.status, recovered.issued)
		}
		// Errorf, not Fatalf: a broken mark usually breaks both, and the report
		// should name every property that failed.
		if issuer, ok := ledger.issuer(failed.issued); !ok || issuer != failed.account {
			t.Errorf("(a) the turn-state issued on the %d from %s is recorded as (%q, %t), want (%q, true) — an error response's turn-state was issued to that account all the same",
				failed.status, failed.account, issuer, ok, failed.account)
		}
		if issuer, ok := ledger.issuer(recovered.issued); !ok || issuer != recovered.account {
			t.Errorf("(b) the failover attempt's turn-state is recorded as (%q, %t), want (%q, true) — it belongs to the account that served THAT attempt",
				issuer, ok, recovered.account)
		}
		if served.issued != recovered.issued {
			t.Errorf("the client received %q, want the failover attempt's %q — the failed attempt's response never reaches the client",
				served.issued, recovered.issued)
		}
	})

	t.Run("another account's turn-state is dropped", func(t *testing.T) {
		// spec: R-codex-identity-rewrite-5.S1
		//
		// CHANGED 2026-09-24 (UD-96, user-confirmed): the four outcomes below are
		// unchanged, but this leg used to let the worker learn that A owns the
		// value from A's first REQUEST carrying it. It now learns it from the
		// RESPONSE that issued it — the only direction the ledger is written in.
		// spec: R-codex-identity-rewrite-5.S3 记账只来自当前账号的上游响应
		useFreshTurnStateMemory(t, codexTurnStateMemoryCap)
		logs := codexRewriteLogs(t)
		pool := newTurnStatePool(t, codexRewriteSwitchOn)

		issuedToA := pool.serve(t, a, "").reissued(t, "A's first request of the turn")
		if got := pool.serve(t, a, issuedToA).forwarded(t, "A continuing its turn"); got != issuedToA {
			t.Fatalf("A lost its OWN turn-state: %q", got)
		}
		// The device is rebound; the client still echoes A's turn-state.
		onB := pool.serve(t, b, issuedToA)
		if got := onB.forwarded(t, "B carrying A's turn-state"); got != "" {
			t.Fatalf("B forwarded a turn-state A's upstream issued (%q) — the upstream can only have issued it to A, so this request re-links the two accounts", got)
		}
		assertTurnStateDropLogged(t, logs, "minted_for_another_account")
		// Refusing it for B must not erase A's record: A may still use what it was
		// issued (a rebind can move back).
		if got := pool.serve(t, a, issuedToA).forwarded(t, "A again"); got != issuedToA {
			t.Fatalf("after B was refused, A lost its own turn-state too: %q", got)
		}
		// B's own upstream re-issued one on the refused leg; B keeps that.
		issuedToB := onB.reissued(t, "B carrying A's turn-state")
		if got := pool.serve(t, b, issuedToB).forwarded(t, "B continuing its turn"); got != issuedToB {
			t.Fatalf("B lost the turn-state its own upstream issued: %q", got)
		}
	})

	t.Run("a restart empties the ledger: one drop, then the re-issue rides along", func(t *testing.T) {
		// spec: R-codex-identity-rewrite-5.S2 (BUT NOT) — the cost UD-96 accepted:
		// the ledger is not persisted, so after a worker restart a turn in flight
		// loses its turn-state once and the upstream re-issues it on the spot.
		useFreshTurnStateMemory(t, codexTurnStateMemoryCap)
		logs := codexRewriteLogs(t)
		pool := newTurnStatePool(t, codexRewriteSwitchOn)

		issued := pool.serve(t, a, "").reissued(t, "A's first request of the turn")
		if got := pool.serve(t, a, issued).forwarded(t, "A before the restart"); got != issued {
			t.Fatalf("A lost its own turn-state before any restart: %q", got)
		}
		useFreshTurnStateMemory(t, codexTurnStateMemoryCap) // the worker restarts
		afterRestart := pool.serve(t, a, issued)
		if got := afterRestart.forwarded(t, "A's first request after the restart"); got != "" {
			t.Fatalf("A forwarded %q after a restart emptied the ledger — nothing proves anymore which account it was issued to", got)
		}
		assertTurnStateDropLogged(t, logs, "not_recorded_by_this_worker")
		reissued := afterRestart.reissued(t, "A's first request after the restart")
		if got := pool.serve(t, a, reissued).forwarded(t, "A continuing after the restart"); got != reissued {
			t.Fatalf("the turn did not recover after the re-issue: %q vs %q", got, reissued)
		}
	})

	t.Run("the ledger is bounded and evicts the least recently used", func(t *testing.T) {
		// spec: R-codex-identity-rewrite-5.S2 (BUT NOT) — a full ledger evicts, and
		// an evicted turn-state costs its turn one re-issue. UD-96 changed WHO
		// writes the ledger, not its cap (4096) or its eviction (least recently
		// used, where continuing a turn counts as a use).
		ledger := useFreshTurnStateMemory(t, 2)
		pool := newTurnStatePool(t, codexRewriteSwitchOn)

		turn1 := pool.serve(t, a, "").reissued(t, "turn 1 starts")
		turn2 := pool.serve(t, a, "").reissued(t, "turn 2 starts")
		if got := ledger.len(); got != 2 {
			t.Fatalf("the ledger holds %d turn-states after two responses issued one each, want 2 — responses are its only writer", got)
		}
		// Turn 1 continues: a USE, which leaves turn 2 as the least recently used.
		if got := pool.serve(t, a, turn1).forwarded(t, "turn 1 continues"); got != turn1 {
			t.Fatalf("turn 1 lost its turn-state: %q", got)
		}
		pool.serve(t, a, "").reissued(t, "turn 3 starts")
		if got := ledger.len(); got != 2 {
			t.Fatalf("the ledger holds %d turn-states, want its cap 2 — unbounded, it grows with upstream traffic", got)
		}
		if got := pool.serve(t, a, turn1).forwarded(t, "turn 1 after turn 3 started"); got != turn1 {
			t.Fatalf("turn 1's turn-state was evicted although turn 2's was used less recently (%q) — eviction must be least-recently-used, not oldest-first", got)
		}
		evicted := pool.serve(t, a, turn2)
		if got := evicted.forwarded(t, "turn 2 after eviction"); got != "" {
			t.Fatalf("turn 2's turn-state %q survived eviction", got)
		}
		reissued := evicted.reissued(t, "turn 2 after eviction")
		if got := pool.serve(t, a, reissued).forwarded(t, "turn 2 after the re-issue"); got != reissued {
			t.Fatalf("turn 2 did not recover after the re-issue: %q vs %q", got, reissued)
		}
		if codexTurnStateMemoryCap != 4096 {
			t.Fatalf("codexTurnStateMemoryCap = %d, want 4096 — the ledger's bound is not part of this change", codexTurnStateMemoryCap)
		}
	})

	t.Run("switch off leaves it alone", func(t *testing.T) {
		// spec: R-codex-identity-rewrite-5.S3 (BUT NOT) — the feature is opened per
		// pool (DEC-codex-identity-rewrite-8). A pool nobody opted in keeps its
		// bytes, a client-echoed turn-state included, and the worker records
		// nothing for it: both directions sit behind the same switch.
		ledger := useFreshTurnStateMemory(t, codexTurnStateMemoryCap)
		pool := newTurnStatePool(t, codexRewriteSwitchOff)

		pool.serve(t, a, "").reissued(t, "a request on a pool nobody opted in")
		if got := ledger.len(); got != 0 {
			t.Fatalf("the worker recorded %d turn-state(s) for a pool nobody opted in — the ledger must follow the same per-pool switch", got)
		}
		const state = "turn-state-seen-while-the-switch-is-off"
		if got := pool.serve(t, a, state).forwarded(t, "a client-echoed turn-state, switch off"); got != state {
			t.Fatalf("upstream turn-state = %q, want the client's own %q — a pool nobody opted in changed behavior", got, state)
		}
	})
}
