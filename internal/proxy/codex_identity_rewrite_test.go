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
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

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

// ── R-codex-identity-rewrite-5.S1 · the turn-state guard ────────────────────

// TestTurnStateGuard_DropsAcrossAccounts fences the one carrier the rewrite
// cannot alias: x-codex-turn-state is opaque UPSTREAM state, minted by the
// account that served an earlier request of the same turn. Rewriting it is
// meaningless (only the upstream can read it); forwarding it on another
// account's credential hands the upstream a value it can only have issued to a
// different account — exactly the linkage the rewrite exists to cut, restored
// by one header.
//
// Dropping it is safe, and that is measured, not assumed: S0 attempt 2
// (2026-09-21, real ChatGPT Codex backend) sent a turn carrying no turn-state
// and the upstream answered 200, re-issued one, and reported unchanged cache
// hits (11520 = 11520) — tasks.md §1 出口门.
//
// spec: R-codex-identity-rewrite-5 丢弃不是当前账号签发的 x-codex-turn-state
// spec: R-codex-identity-rewrite-5.S1 换账号后上游 B 收到的请求不含该头
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
func TestTurnStateGuard_DropsAcrossAccounts(t *testing.T) {
	// One request as the wiring sees it: the pool lane's own entry point
	// (applyCodexIdentityRewrite), so the legs below exercise the production
	// decision rather than a re-implementation of it.
	serveFor := func(t *testing.T, accountID, turnState string) *http.Request {
		t.Helper()
		header, body := codexIdentityTestInput()
		header.Set(codexTurnStateHeader, turnState)
		req := httptest.NewRequest(http.MethodPost, codexRewriteResponsesPath, bytes.NewReader(body))
		for name, values := range header {
			for _, v := range values {
				req.Header.Add(name, v)
			}
		}
		route := &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-turn-state", ProtocolType: "openai_compatible", RouteSource: "team",
			OauthGroupID: "grp-turn-state", RoutingConfig: codexRewriteSwitchOn,
			IdentityKey: codexRewriteIdentityKey(),
		}
		if !applyCodexIdentityRewrite(req, "openai", route, accountID, quietLogger()) {
			t.Fatal("the rewrite lane did not run, so nothing here is a claim about the guard")
		}
		return req
	}

	t.Run("same account keeps it", func(t *testing.T) {
		// Through the REAL handler chain to the transport: a turn-state that
		// belongs to the serving account must still be there when the request
		// leaves, or every multi-request turn would lose its upstream state and
		// pay for a re-issue on each hop.
		const state = "turn-state-minted-for-the-serving-account"
		pool := newCodexRewritePool(t, "openai", "openai_compatible", codexRewriteSwitchOn)
		for i := 0; i < 2; i++ {
			header, body := codexIdentityTestInput()
			header.Set(codexTurnStateHeader, state)
			if w := pool.serve(t, codexRewriteResponsesPath, header, body); w.Code != http.StatusOK {
				t.Fatalf("request %d: status = %d, want 200 (body=%s)", i, w.Code, w.Body.String())
			}
		}
		seen := pool.transport.all()
		if len(seen) != 2 {
			t.Fatalf("the upstream was dialed %d times, want 2", len(seen))
		}
		for i, s := range seen {
			if got := s.header.Get(codexTurnStateHeader); got != state {
				t.Fatalf("request %d: upstream turn-state = %q, want the client's own %q — the guard dropped a header that belongs to the serving account", i, got, state)
			}
			// The rewrite still happened around it (this is the pool lane).
			codexRewriteAssertNoOriginals(t, "request "+strconv.Itoa(i), s)
		}
	})

	t.Run("another account's turn-state is dropped", func(t *testing.T) {
		const (
			accountA = "acc-turn-state-a"
			accountB = "acc-turn-state-b"
			state    = "turn-state-minted-by-account-a"
		)
		// A serves first: this is where the worker learns who the turn-state
		// belongs to, and A must keep its own.
		if got := serveFor(t, accountA, state).Header.Get(codexTurnStateHeader); got != state {
			t.Fatalf("account A lost its OWN turn-state: %q", got)
		}
		// The device is rebound; the client still echoes A's turn-state.
		if got := serveFor(t, accountB, state).Header.Get(codexTurnStateHeader); got != "" {
			t.Fatalf("account B forwarded a turn-state minted by account A (%q) — the upstream can only have issued it to A, so this request re-links the two accounts", got)
		}
		// Dropping it for B must not evict A's own claim: A is still allowed to
		// use the state it minted (a rebind can move back).
		if got := serveFor(t, accountA, state).Header.Get(codexTurnStateHeader); got != state {
			t.Fatalf("after B was refused, account A lost its own turn-state too: %q", got)
		}
		// A turn-state B minted itself rides along untouched.
		const ownState = "turn-state-minted-by-account-b"
		if got := serveFor(t, accountB, ownState).Header.Get(codexTurnStateHeader); got != ownState {
			t.Fatalf("account B lost a turn-state it minted itself: %q", got)
		}
	})

	t.Run("memory is bounded", func(t *testing.T) {
		// The map is fed by client-supplied values, so an unbounded one is a
		// memory leak any client could drive. Eviction is least-recently-used,
		// and an evicted turn-state is simply learned again on its next sighting.
		owners := newTurnStateOwners(4)
		for i := 0; i < 50; i++ {
			owners.owner("state-"+strconv.Itoa(i), "acc-"+strconv.Itoa(i))
		}
		if got := owners.len(); got != 4 {
			t.Fatalf("remembered %d turn-states, want the cap 4 — an unbounded map grows with client traffic", got)
		}
		if got := owners.owner("state-49", "someone-else"); got != "acc-49" {
			t.Fatalf("the newest turn-state was evicted: owner = %q, want acc-49", got)
		}
		if got := owners.owner("state-0", "acc-fresh"); got != "acc-fresh" {
			t.Fatalf("the oldest turn-state survived eviction: owner = %q, want the re-learned acc-fresh", got)
		}
		// The shipped cap must be a real bound, not a placeholder.
		if codexTurnStateMemoryCap <= 0 {
			t.Fatalf("codexTurnStateMemoryCap = %d: the worker's guard is unbounded", codexTurnStateMemoryCap)
		}
	})

	t.Run("switch off leaves it alone", func(t *testing.T) {
		// The whole feature is opened per pool (design 7.4). With the switch off
		// the pool's bytes are what they were before this task — including a
		// turn-state the client echoes — so the guard must not fire either.
		const state = "turn-state-seen-while-the-switch-is-off"
		pool := newCodexRewritePool(t, "openai", "openai_compatible", codexRewriteSwitchOff)
		header, body := codexIdentityTestInput()
		header.Set(codexTurnStateHeader, state)
		if w := pool.serve(t, codexRewriteResponsesPath, header, body); w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		if got := pool.transport.only(t).header.Get(codexTurnStateHeader); got != state {
			t.Fatalf("upstream turn-state = %q, want the client's own %q — a pool nobody opted in changed behavior", got, state)
		}
	})
}
