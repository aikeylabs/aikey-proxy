// group_serve_rewrite_test.go — the account-pool WIRING fences for the Codex
// identity rewrite. The rewrite itself is fenced as a pure function in
// codex_identity_rewrite_test.go; what these fences answer is the set of
// questions only the serving path can answer:
//
//	does a real pool request reach the TRANSPORT rewritten (and stay stable
//	across 100 requests on one account)?          → R-codex-identity-rewrite-1.S2
//	is a Claude pool request byte-identical?       → R-codex-identity-rewrite-6.S1
//	does a malformed carrier still serve 200,
//	without the header and without X-Aikey-*?      → R-codex-identity-rewrite-7.S1
//	is ChatGPT-Account-Id OURS on this lane only?  → R-codex-identity-rewrite-1
//	is everything byte-identical with the switch
//	off / missing / malformed?                     → 线上安全 (改写默认关)
//
// Requirement package: roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/
// (design §5.5 "worker 按账号改写标识"; spec openspec/specs/codex-identity-rewrite/spec.md).
//
// Every fence asserts on what the TRANSPORT received, not on what the handler
// did: the strip of the X-Aikey-* namespace and the provider Director both run
// after the injection, so an assertion taken any earlier would be a claim about
// the wrong request.
package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

const (
	codexRewriteVK        = "aikey_team_poolrewrite"
	codexRewriteAccountID = "acc-pool-rewrite"
	// codexRewriteExternalID is the SERVING account's upstream (ChatGPT) account
	// id — what ChatGPT-Account-Id must carry on this lane.
	codexRewriteExternalID = "chatgpt-acct-of-the-serving-account"
	// codexRewriteForeignAccountID is what a client sends when it was logged in
	// to a different ChatGPT account: the value that must NOT ride along with
	// another account's token.
	codexRewriteForeignAccountID = "chatgpt-acct-of-somebody-else"

	codexRewriteSwitchOn      = `{"codex_identity_rewrite":true}`
	codexRewriteSwitchOff     = `{"codex_identity_rewrite":false}`
	codexRewriteSwitchInvalid = `{"codex_identity_rewrite":`

	codexRewriteResponsesPath = "/responses"
	codexRewriteMessagesPath  = "/v1/messages"
)

// codexRewriteIdentityKey is the per-account key the control plane delivers
// (2.3). A fixed, non-secret test value: the fences assert relations
// (equal / not equal / stable), never key material.
func codexRewriteIdentityKey() []byte { return bytes.Repeat([]byte{0x3d}, 32) }

// ── fixtures ────────────────────────────────────────────────────────────────

// codexRewriteSeen is one outbound request as the upstream would have seen it.
type codexRewriteSeen struct {
	header http.Header
	body   []byte
	url    string
}

// codexRewriteTransport records EVERY outbound request, not just the last one.
//
// Deliberately separate from capturingTransport (last request only, Anthropic-
// shaped response body) and from scriptedTransport (discards the request):
// widening either would change what the fences already sharing them exercise.
type codexRewriteTransport struct {
	mu   sync.Mutex
	seen []codexRewriteSeen
}

func (c *codexRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	seen := codexRewriteSeen{header: req.Header.Clone(), url: req.URL.String()}
	if req.Body != nil {
		seen.body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	c.mu.Lock()
	c.seen = append(c.seen, seen)
	c.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"id":"resp_1","object":"response","model":"gpt-5-codex","output":[],` +
				`"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)),
		Request: req,
	}, nil
}

func (c *codexRewriteTransport) all() []codexRewriteSeen {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]codexRewriteSeen(nil), c.seen...)
}

func (c *codexRewriteTransport) only(t *testing.T) codexRewriteSeen {
	t.Helper()
	all := c.all()
	if len(all) != 1 {
		t.Fatalf("the upstream was dialed %d times, want exactly 1 — a fence that never reached the transport proves nothing", len(all))
	}
	return all[0]
}

// codexRewritePool is one hermetic account-pool proxy plus its recording
// transport. Modeled on serveGroupOAuthWithUpstream (codex_upstream_reclassify
// _test.go) and kept separate because these fences need three things that
// fixture does not offer: a routing_config, client-set headers, and many
// requests against ONE proxy.
type codexRewritePool struct {
	p         *Proxy
	transport *codexRewriteTransport
}

func newCodexRewritePool(t *testing.T, providerCode, protocolType, routingConfig string) *codexRewritePool {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	key := grKey()
	refs := []vkeys.GroupAccountRef{{
		AccountID: codexRewriteAccountID, ProviderCode: providerCode, ProtocolType: protocolType,
	}}
	// The material carries a DELIVERED per-account identity key (2.3's shape),
	// i.e. the production path — not the node-local fallback.
	mat := map[string]vkeys.GroupRuntimeAccount{
		codexRewriteAccountID: encIdentityKey(t, key, encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ProviderCode:   providerCode,
			ProtocolType:   protocolType,
			ExternalID:     codexRewriteExternalID,
			ExpiresAt:      9_000_000_000,
		}, "pool-oauth-token"), codexRewriteIdentityKey()),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp-rewrite", ProtocolType: protocolType, RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-rewrite",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
		RoutingConfig: routingConfig,
		// RouteKind (task 4.5): serve() below stamps X-Aikey-Route-Account, and
		// the cluster ingress only writes that header for the device_routing_token
		// namespace (it Dels it everywhere else). Since 4.5 the worker refuses the
		// mismatched pair "header present + route is not a device-routing route"
		// with 503 NODE_UNSUPPORTED instead of serving it on the seat path — so
		// declaring the kind here is what makes this fixture a shape production can
		// actually produce. No assertion in this file changed: the pool has one
		// account and the header names it, so the same account serves, and the
		// red-line check still runs against a request that really carried an
		// X-Aikey-* header inbound.
		// spec: R-device-routing-token-dispatch-20.S2
		RouteKind: routeKindDeviceRoutingToken,
	}
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{codexRewriteVK: route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	transport := &codexRewriteTransport{}
	p.SetTransport(transport)
	return &codexRewritePool{p: p, transport: transport}
}

// serve drives ONE request through the real handler chain.
func (f *codexRewritePool) serve(t *testing.T, path string, header http.Header, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+codexRewriteVK)
	// The cluster ingress stamps internal routing headers in this namespace.
	// 🔴 RED LINE: none of it may reach an LLM upstream — every fence here
	// asserts that once, on the request the transport actually got.
	req.Header.Set("X-Aikey-Route-Account", codexRewriteAccountID)
	w := httptest.NewRecorder()
	f.p.Handle(w, req)
	return w
}

// codexRewriteLogs points the DEFAULT logger — the one Handle derives its
// per-request logger from — at a buffer for the duration of one test.
func codexRewriteLogs(t *testing.T) *codexRewriteLogBuffer {
	t.Helper()
	buf := &codexRewriteLogBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// codexRewriteLogBuffer is mutex-guarded because the usage collector logs from
// its own goroutine.
type codexRewriteLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *codexRewriteLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *codexRewriteLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// codexRewriteOriginals are the client's real identifiers, none of which may
// appear anywhere in an outbound request once the rewrite is on.
func codexRewriteOriginals() map[string]string {
	return map[string]string{
		"installation id":   codexIdentityTestInstallation,
		"session/thread id": codexIdentityTestSession,
		"turn id":           codexIdentityTestTurn,
		"context window id": codexIdentityTestContext,
	}
}

// codexRewriteDump renders one outbound request as a single searchable string.
func codexRewriteDump(seen codexRewriteSeen) string {
	var sb strings.Builder
	for name, values := range seen.header {
		for _, v := range values {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
	}
	sb.Write(seen.body)
	return sb.String()
}

func codexRewriteAssertNoOriginals(t *testing.T, where string, seen codexRewriteSeen) {
	t.Helper()
	dump := codexRewriteDump(seen)
	for label, original := range codexRewriteOriginals() {
		if strings.Contains(dump, original) {
			t.Fatalf("%s: the client's own %s reached the upstream — that is the linkage the rewrite exists to cut", where, label)
		}
	}
}

// ── R-codex-identity-rewrite-1.S2 · same device, same account ───────────────

// TestGroupServe_Rewrite_SameAccountStableInstallationID is the "one machine
// still looks like ONE steady device" half of the claim: 100 requests on one
// account must present the SAME rewritten installation id (a value that churned
// per request would look like a new machine on every turn and be a worse signal
// than the original), while never being the client's own value.
//
// spec: R-codex-identity-rewrite-1.S2 同账号稳定 —— 100 个请求安装号始终同一个、
// 会话号始终同一个，且原始值不到上游
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
func TestGroupServe_Rewrite_SameAccountStableInstallationID(t *testing.T) {
	pool := newCodexRewritePool(t, "openai", "openai_compatible", codexRewriteSwitchOn)
	const requests = 100
	for i := 0; i < requests; i++ {
		header, body := codexIdentityTestInput()
		if w := pool.serve(t, codexRewriteResponsesPath, header, body); w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (body=%s)", i, w.Code, w.Body.String())
		}
	}
	seen := pool.transport.all()
	if len(seen) != requests {
		t.Fatalf("the upstream was dialed %d times, want %d", len(seen), requests)
	}

	firstInstallation := seen[0].header.Get("X-Codex-Installation-Id")
	firstSession := seen[0].header.Get("Session-Id")
	if firstInstallation == "" || firstSession == "" {
		t.Fatal("the rewrite dropped the identifier headers instead of rewriting them")
	}
	if firstInstallation == codexIdentityTestInstallation {
		t.Fatal("the installation id reaching the upstream is the client's own — nothing was rewritten")
	}
	if firstSession == codexIdentityTestSession {
		t.Fatal("the session id reaching the upstream is the client's own — nothing was rewritten")
	}
	for i, s := range seen {
		if got := s.header.Get("X-Codex-Installation-Id"); got != firstInstallation {
			t.Fatalf("request %d: installation id changed (%q -> %q) — the upstream sees a new device on every turn", i, firstInstallation, got)
		}
		if got := s.header.Get("Session-Id"); got != firstSession {
			t.Fatalf("request %d: session id changed (%q -> %q) — the conversation would look like a new session each turn", i, firstSession, got)
		}
		codexRewriteAssertNoOriginals(t, "request "+strconv.Itoa(i), s)
		codexIdentityTestAssertNoAikeyHeaders(t, s.header)
	}

	// The body carriers move with the headers: prompt_cache_key is the session
	// id, so a rewrite that only covered headers would split the pair and hand
	// the upstream the original anyway.
	obj := codexIdentityTestObject(t, seen[0].body)
	if got := codexIdentityTestString(t, obj, "prompt_cache_key"); got != firstSession {
		t.Fatalf("prompt_cache_key = %q, want the rewritten session id %q", got, firstSession)
	}
}

// ── R-codex-identity-rewrite-6.S1 · Claude pool bytes unchanged ─────────────

// TestGroupServe_Rewrite_ClaudeBytesUntouched pins the fence side of "只对
// Codex 号池生效": a Claude pool request must reach the upstream with the same
// bytes whether the switch is on or off.
//
// Why the comparison is ON-vs-OFF rather than against a hard-coded expectation:
// the claim is "与今天一致" (identical to today), and the switch-off path IS
// today's code path. A literal expectation would also go stale the moment the
// Claude persona injection legitimately changes.
//
// The request carries Codex identity headers and a prompt_cache_key ON PURPOSE:
// a rewrite that is not scoped to the Codex lane would change exactly those.
//
// spec: R-codex-identity-rewrite-6.S1 Claude 请求 —— 上游收到的请求头与请求体与
// 今天一致
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
func TestGroupServe_Rewrite_ClaudeBytesUntouched(t *testing.T) {
	header, body := codexRewriteClaudeInput()

	withSwitchOn := newCodexRewritePool(t, "anthropic", "anthropic", codexRewriteSwitchOn)
	if w := withSwitchOn.serve(t, codexRewriteMessagesPath, header, body); w.Code != http.StatusOK {
		t.Fatalf("switch-on run: status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	withSwitchOff := newCodexRewritePool(t, "anthropic", "anthropic", "")
	if w := withSwitchOff.serve(t, codexRewriteMessagesPath, header, body); w.Code != http.StatusOK {
		t.Fatalf("switch-off run: status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	on, off := withSwitchOn.transport.only(t), withSwitchOff.transport.only(t)
	if !bytes.Equal(on.body, off.body) {
		t.Fatalf("a Claude pool request body changed when the Codex switch was on:\n on  %s\n off %s", on.body, off.body)
	}
	if on.url != off.url {
		t.Fatalf("a Claude pool request URL changed when the Codex switch was on: %q vs %q", on.url, off.url)
	}
	if diff := codexRewriteHeaderDiff(on.header, off.header); diff != "" {
		t.Fatalf("a Claude pool request header changed when the Codex switch was on: %s", diff)
	}
	for name := range codexRewritePerRequestHeaders {
		if on.header.Get(name) == "" || off.header.Get(name) == "" {
			t.Fatalf("%s is missing upstream — the diff above skips its VALUE, so its absence must be asserted here", name)
		}
	}

	// And the Codex carriers really were there to be broken.
	if got := on.header.Get("X-Codex-Installation-Id"); got != codexIdentityTestInstallation {
		t.Fatalf("X-Codex-Installation-Id = %q, want the client's own %q (Claude lane forwards it verbatim)", got, codexIdentityTestInstallation)
	}
	if got := on.header.Get("X-Codex-Turn-Metadata"); got != codexIdentityTestTurnMetadata() {
		t.Fatalf("X-Codex-Turn-Metadata was not forwarded verbatim on the Claude lane:\n got  %s\n want %s", got, codexIdentityTestTurnMetadata())
	}
	if !bytes.Equal(on.body, body) {
		t.Fatalf("the Claude pool body is not the client's own bytes:\n got  %s\n want %s", on.body, body)
	}
	obj := codexIdentityTestObject(t, on.body)
	metadata := codexIdentityTestChild(t, obj, "metadata")
	if got := codexIdentityTestString(t, metadata, "user_id"); got != codexRewriteClaudeUserID {
		t.Fatalf("metadata.user_id = %q, want the client's own %q", got, codexRewriteClaudeUserID)
	}
	codexIdentityTestAssertNoAikeyHeaders(t, on.header)
}

const codexRewriteClaudeUserID = "member-1"

// codexRewriteClaudeInput is a Claude Code CLI request that also carries the
// Codex identity headers.
//
// Two details make two runs comparable at all, and both mirror real CLI
// traffic: the claude-cli/ User-Agent keeps oauth_inject on its pass-through
// branch (no WAF body rewrite), and a client-set X-Claude-Code-Session-Id keeps
// the injector from minting a random session id + metadata.user_id per run.
func codexRewriteClaudeInput() (http.Header, []byte) {
	h := http.Header{}
	h.Set("User-Agent", "claude-cli/2.1.22 (external, cli)")
	h.Set("X-Claude-Code-Session-Id", "11111111-2222-4333-8444-555555555555")
	h.Set("x-codex-installation-id", codexIdentityTestInstallation)
	h.Set("session-id", codexIdentityTestSession)
	h.Set("x-codex-turn-metadata", codexIdentityTestTurnMetadata())
	body := []byte(`{"model":"claude-sonnet-4","max_tokens":16,` +
		`"metadata":{"user_id":"` + codexRewriteClaudeUserID + `"},` +
		`"messages":[{"role":"user","content":"hi"}],"stream":true,` +
		`"prompt_cache_key":"` + codexIdentityTestSession + `"}`)
	return h, body
}

// codexRewritePerRequestHeaders are outbound headers whose VALUE is a
// per-request correlation id, so two runs can never agree on them and a
// byte-comparison must skip them. X-Request-Id is the proxy's own logical
// request id (forward_and_resolve.go, "Propagate the proxy's logical request id
// to every upstream attempt"). The caller still asserts they are PRESENT, so
// skipping the value cannot hide one going missing.
var codexRewritePerRequestHeaders = map[string]struct{}{
	"X-Request-Id": {},
}

// codexRewriteHeaderDiff reports the first difference between two outbound
// header sets, or "" when they are identical.
func codexRewriteHeaderDiff(a, b http.Header) string {
	for name, av := range a {
		bv, ok := b[name]
		if !ok {
			return name + " is present only in the switch-on run"
		}
		if _, skip := codexRewritePerRequestHeaders[name]; skip {
			continue
		}
		if strings.Join(av, "\x00") != strings.Join(bv, "\x00") {
			return name + " differs: " + strings.Join(av, ",") + " vs " + strings.Join(bv, ",")
		}
	}
	for name := range b {
		if _, ok := a[name]; !ok {
			return name + " is present only in the switch-off run"
		}
	}
	return ""
}

// ── R-codex-identity-rewrite-7.S1 · malformed carrier ──────────────────────

// TestGroupServe_Rewrite_MalformedTurnMetadataDropped: a carrier the rewrite
// cannot read must not block the request and must not travel. The request is
// served (200), the header is gone, ONE WARN names the dropped carrier, and the
// X-Aikey-* red line still holds.
//
// spec: R-codex-identity-rewrite-7.S1 畸形 turn-metadata —— 上游收不到该头，
// 请求 200，日志 WARN，上游请求头不含 X-Aikey-*
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
func TestGroupServe_Rewrite_MalformedTurnMetadataDropped(t *testing.T) {
	logs := codexRewriteLogs(t)
	pool := newCodexRewritePool(t, "openai", "openai_compatible", codexRewriteSwitchOn)

	header, body := codexIdentityTestInput()
	header.Set("x-codex-turn-metadata", "not-json{{{")
	w := pool.serve(t, codexRewriteResponsesPath, header, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an unreadable side-channel header must not fail the request (body=%s)", w.Code, w.Body.String())
	}
	seen := pool.transport.only(t)
	if got := seen.header.Get("X-Codex-Turn-Metadata"); got != "" {
		t.Fatalf("X-Codex-Turn-Metadata reached the upstream as %q — an unrewritable carrier must be dropped, not forwarded", got)
	}
	// The rest of the request still went through, rewritten.
	if got := seen.header.Get("X-Codex-Installation-Id"); got == "" || got == codexIdentityTestInstallation {
		t.Fatalf("X-Codex-Installation-Id = %q — one bad header must not take the whole rewrite down", got)
	}
	codexRewriteAssertNoOriginals(t, "malformed turn-metadata", seen)
	codexIdentityTestAssertNoAikeyHeaders(t, seen.header)

	out := logs.String()
	if !strings.Contains(out, "proxy.codex_identity.carrier_dropped") {
		t.Fatalf("no %q WARN was logged — a dropped identifier carrier that leaves no trace is unexplainable at 3am. logs:\n%s",
			"proxy.codex_identity.carrier_dropped", out)
	}
	if !strings.Contains(out, "x-codex-turn-metadata") {
		t.Fatalf("the WARN does not name the dropped carrier. logs:\n%s", out)
	}
	if strings.Contains(out, codexIdentityTestSession) || strings.Contains(out, codexIdentityTestInstallation) {
		t.Fatal("the log carries an identifier VALUE — carrier names only")
	}
}

// ── R-codex-identity-rewrite-1 · ChatGPT-Account-Id is ours on this lane ────

// TestGroupServe_Rewrite_ChatGPTAccountIDOverwrittenOnCodexPoolLane is the
// [回归·局部反转] fence: on the Codex account-pool lane with the rewrite on,
// ChatGPT-Account-Id is OVERWRITTEN with the serving account's upstream id,
// reversing the setIfAbsent convention of bugfix
// workflow/CI/bugfix/2026-04-16-oauth-inject-missing-beta-and-header-overwrite.md
// for THIS lane only. The second half of the fence is the part that keeps the
// reversal local: the direct (non-pool) lane still injects only when absent.
//
// spec: R-codex-identity-rewrite-1 客户端原始标识不出 worker —— ChatGPT-Account-Id
// MUST 覆盖为当前账号的上游账号 id（不再「缺省才注入」）
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
func TestGroupServe_Rewrite_ChatGPTAccountIDOverwrittenOnCodexPoolLane(t *testing.T) {
	t.Run("codex pool lane overwrites the client's value", func(t *testing.T) {
		pool := newCodexRewritePool(t, "openai", "openai_compatible", codexRewriteSwitchOn)
		header, body := codexIdentityTestInput()
		header.Set("ChatGPT-Account-Id", codexRewriteForeignAccountID)
		if w := pool.serve(t, codexRewriteResponsesPath, header, body); w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		seen := pool.transport.only(t)
		if got := seen.header.Get("ChatGPT-Account-Id"); got != codexRewriteExternalID {
			t.Fatalf("ChatGPT-Account-Id = %q, want the serving account's upstream id %q — another account's id riding with this account's token is both a mismatch and a linkage signal",
				got, codexRewriteExternalID)
		}
		codexIdentityTestAssertNoAikeyHeaders(t, seen.header)
	})

	t.Run("the direct lane still injects only when absent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, codexRewriteResponsesPath, nil)
		req.Header.Set("ChatGPT-Account-Id", codexRewriteForeignAccountID)
		oauthInject(req, &OAuthCredential{
			AccessToken: "codex-tok", ExternalID: codexRewriteExternalID, AccountID: codexRewriteAccountID,
		}, "openai")
		if got := req.Header.Get("ChatGPT-Account-Id"); got != codexRewriteForeignAccountID {
			t.Fatalf("ChatGPT-Account-Id = %q, want the client's own %q preserved — the reversal is scoped to the Codex account-pool lane, every other lane keeps setIfAbsent",
				got, codexRewriteForeignAccountID)
		}
	})
}

// ── 线上安全 · the switch is off by default ─────────────────────────────────

// TestGroupServe_Rewrite_SwitchOffLeavesCodexBytesUntouched is the production
// safety fence for 「改写默认关，按账号池 routing_config.codex_identity_rewrite
// =true 打开」: with the switch missing, false, or unparsable, a Codex pool
// request must reach the upstream exactly as it does today — identifiers
// verbatim, body byte-identical, and ChatGPT-Account-Id still setIfAbsent.
//
// An unparsable routing_config is treated as OFF and logged: a feature whose
// switch cannot be read must not turn itself on, and silence would hide
// control-plane drift.
//
// spec: R-codex-identity-rewrite-6 只对 Codex 号池生效（全局约束「改写默认关」）
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
func TestGroupServe_Rewrite_SwitchOffLeavesCodexBytesUntouched(t *testing.T) {
	cases := []struct {
		name          string
		routingConfig string
		wantWarn      bool
	}{
		{name: "no routing_config at all", routingConfig: ""},
		{name: "empty routing_config", routingConfig: `{}`},
		{name: "another pool knob only", routingConfig: `{"temporary_rate_limit_cooldown_seconds":30}`},
		{name: "explicitly false", routingConfig: codexRewriteSwitchOff},
		{name: "unparsable routing_config", routingConfig: codexRewriteSwitchInvalid, wantWarn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := codexRewriteLogs(t)
			pool := newCodexRewritePool(t, "openai", "openai_compatible", tc.routingConfig)
			header, body := codexIdentityTestInput()
			header.Set("ChatGPT-Account-Id", codexRewriteForeignAccountID)
			if w := pool.serve(t, codexRewriteResponsesPath, header, body); w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
			}
			seen := pool.transport.only(t)

			for name, want := range map[string]string{
				"X-Codex-Installation-Id": codexIdentityTestInstallation,
				"Session-Id":              codexIdentityTestSession,
				"Thread-Id":               codexIdentityTestSession,
				"X-Client-Request-Id":     codexIdentityTestSession,
				"X-Codex-Window-Id":       codexIdentityTestWindow,
				"X-Codex-Turn-Metadata":   codexIdentityTestTurnMetadata(),
			} {
				if got := seen.header.Get(name); got != want {
					t.Fatalf("%s = %q, want the client's own value %q — with the switch off this lane must be byte-identical to before the rewrite existed",
						name, got, want)
				}
			}
			if !bytes.Equal(seen.body, body) {
				t.Fatalf("the body changed with the switch off:\n got  %s\n want %s", seen.body, body)
			}
			if got := seen.header.Get("ChatGPT-Account-Id"); got != codexRewriteForeignAccountID {
				t.Fatalf("ChatGPT-Account-Id = %q, want the client's own %q — the overwrite belongs to the rewrite and must not fire while the rewrite is off",
					got, codexRewriteForeignAccountID)
			}
			codexIdentityTestAssertNoAikeyHeaders(t, seen.header)

			if got := strings.Contains(logs.String(), "proxy.group.routing_config_invalid"); got != tc.wantWarn {
				t.Fatalf("routing_config_invalid WARN present = %v, want %v. logs:\n%s", got, tc.wantWarn, logs.String())
			}
			if strings.Contains(logs.String(), "proxy.codex_identity.carrier_dropped") {
				t.Fatalf("a carrier-dropped WARN fired while the rewrite was off. logs:\n%s", logs.String())
			}
		})
	}
}

// TestGroupServe_Rewrite_MissingIdentityKeyDoesNotClaimARewrite covers the one
// state the consumed contract leaves to this caller: rewriteCodexIdentity
// reports Dropped=["key"] and changes NOTHING when no account key is supplied.
// The resolver promises that never happens, so this fence pins what we do if
// the promise breaks — report "not rewritten", so the request degrades to
// switch-off behavior instead of ending up with OUR account header on a
// request still carrying the CLIENT's identifiers.
func TestGroupServe_Rewrite_MissingIdentityKeyDoesNotClaimARewrite(t *testing.T) {
	logs := codexRewriteLogs(t)
	header, body := codexIdentityTestInput()
	req := httptest.NewRequest(http.MethodPost, codexRewriteResponsesPath, bytes.NewReader(body))
	req.Header = header
	route := &vkeys.ResolvedRoute{OauthGroupID: "grp-rewrite", RoutingConfig: codexRewriteSwitchOn}

	if applyCodexIdentityRewrite(req, "openai", route, codexRewriteAccountID, slog.Default()) {
		t.Fatal("applyCodexIdentityRewrite claimed a rewrite with no account key — the caller would then overwrite ChatGPT-Account-Id on a request that still carries the client's identifiers")
	}
	if got := req.Header.Get("X-Codex-Installation-Id"); got != codexIdentityTestInstallation {
		t.Fatalf("X-Codex-Installation-Id = %q, want the request left untouched %q", got, codexIdentityTestInstallation)
	}
	out := logs.String()
	if !strings.Contains(out, "proxy.codex_identity.carrier_dropped") || !strings.Contains(out, codexIdentityDropKey) {
		t.Fatalf("a missing per-account key must be loud (it means the resolver's guarantee broke). logs:\n%s", out)
	}
}

// ── 席位池 lane · the wiring fences must not all live on one lane ───────────

// serveSeatLane drives ONE request through the real handler chain WITHOUT the
// cluster ingress's X-Aikey-Route-Account decision header.
//
// A sibling of serve rather than a parameter on it: serve is shared by every
// fence above, and stamping that header is precisely what makes those a
// device-routing-token shape (task 4.5). A knob there would re-open the question
// for all of them; one more entry point changes no existing assertion.
func (f *codexRewritePool) serveSeatLane(t *testing.T, path string, header http.Header, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+codexRewriteVK)
	w := httptest.NewRecorder()
	f.p.Handle(w, req)
	return w
}

// newCodexRewriteSeatPool is the same pool as an ordinary SEAT route: identical
// material, identical account, no route_kind. It re-registers a COPY of the
// route under the same virtual key instead of taking a parameter — for the same
// reason serveSeatLane is a sibling, and copying keeps it from mutating a route
// pointer the registry already handed out.
func newCodexRewriteSeatPool(t *testing.T, routingConfig string) *codexRewritePool {
	t.Helper()
	pool := newCodexRewritePool(t, "openai", "openai_compatible", routingConfig)
	registered := pool.p.registry.Resolve(codexRewriteVK)
	if registered == nil {
		t.Fatal("the fixture's virtual key is not registered")
	}
	seat := *registered
	seat.RouteKind = "" // an ordinary seat pool route carries no kind
	pool.p.registry.Merge(map[string]*vkeys.ResolvedRoute{codexRewriteVK: &seat})
	return pool
}

// TestGroupServe_Rewrite_SeatPoolLaneRewritesAndKeepsTheRedLine restores the
// lane coverage the shared fixture gave up in task 4.5. Since that task the
// fixture declares RouteKind=device_routing_token (so the X-Aikey-Route-Account
// header serve() stamps is a shape production can actually produce), which puts
// every wiring fence above on the device-routing-token lane only. The rewrite is
// not scoped to that lane — it fires for any Codex account pool whose
// routing_config opts in, seat pools included — so one case has to prove it
// there, or a regression that only breaks the seat lane ships green.
//
// The inbound X-Aikey-Probe: 1 is what keeps the red-line assertion from being
// vacuous: with no X-Aikey-* header inbound, "the transport saw none" is also
// true of a request that never carried one. That header is the right probe here
// because it is CLIENT-set and legitimately rides any route including a team
// virtual key (middleware.go isAikeyProbe), it is invisible to the
// device-routing classifier (only X-Aikey-Route-Account is a decision), and
// stripAikeyRequestHeaders removes the whole namespace with no exception, so the
// strip is the only thing that can delete it. It does suppress usage accounting
// and quota — orthogonal to everything asserted below.
//
// spec: R-codex-identity-rewrite-1.S2 同账号稳定 / 原始值不到上游（席位池 lane）
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/codex-identity-rewrite/spec.md
func TestGroupServe_Rewrite_SeatPoolLaneRewritesAndKeepsTheRedLine(t *testing.T) {
	pool := newCodexRewriteSeatPool(t, codexRewriteSwitchOn)
	if got := pool.p.registry.Resolve(codexRewriteVK).RouteKind; got != "" {
		t.Fatalf("RouteKind = %q: this fence exists to cover the SEAT lane, so a device-routing route makes it a duplicate of the fences above", got)
	}

	header, body := codexIdentityTestInput()
	header.Set(headerAikeyProbe, "1")
	if header.Get(headerRouteAccount) != "" {
		t.Fatalf("the fence itself is wrong: %s must not be set on the seat lane", headerRouteAccount)
	}
	if header.Get(headerAikeyProbe) != "1" {
		t.Fatal("the fence itself is wrong: no X-Aikey-* header goes in, so the red-line assertion below would be vacuous")
	}

	w := pool.serveSeatLane(t, codexRewriteResponsesPath, header, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an ordinary seat pool request must still serve (body=%s)", w.Code, w.Body.String())
	}

	seen := pool.transport.only(t)
	installation := seen.header.Get("X-Codex-Installation-Id")
	session := seen.header.Get("Session-Id")
	if installation == "" || installation == codexIdentityTestInstallation {
		t.Fatalf("X-Codex-Installation-Id = %q — the rewrite did not run on the seat lane", installation)
	}
	if session == "" || session == codexIdentityTestSession {
		t.Fatalf("Session-Id = %q — the rewrite did not run on the seat lane", session)
	}
	if got := codexIdentityTestString(t, codexIdentityTestObject(t, seen.body), "prompt_cache_key"); got != session {
		t.Fatalf("prompt_cache_key = %q, want the rewritten session id %q", got, session)
	}
	if got := seen.header.Get("ChatGPT-Account-Id"); got != codexRewriteExternalID {
		t.Fatalf("ChatGPT-Account-Id = %q, want the serving account's upstream id %q", got, codexRewriteExternalID)
	}
	codexRewriteAssertNoOriginals(t, "seat lane", seen)
	// 🔴 RED LINE: the inbound request carried X-Aikey-Probe: 1, so this asserts
	// the strip, not an empty namespace.
	codexIdentityTestAssertNoAikeyHeaders(t, seen.header)
}

// ── the switch reader itself ───────────────────────────────────────────────

// TestGroupCodexIdentityRewrite_ParsesRoutingConfig pins the reader: default
// off, explicit on/off honored, unrelated knobs ignored (the two readers share
// one routing_config string), and an unreadable config reported as an ERROR
// while still returning off.
func TestGroupCodexIdentityRewrite_ParsesRoutingConfig(t *testing.T) {
	cases := []struct {
		name          string
		routingConfig string
		want          bool
		wantErr       bool
	}{
		{name: "missing config defaults to off", routingConfig: ""},
		{name: "blank config defaults to off", routingConfig: "   "},
		{name: "empty object defaults to off", routingConfig: `{}`},
		{name: "explicit true", routingConfig: codexRewriteSwitchOn, want: true},
		{name: "explicit false", routingConfig: codexRewriteSwitchOff},
		{name: "unrelated knob is ignored", routingConfig: `{"temporary_rate_limit_cooldown_seconds":30}`},
		{name: "both knobs on one string", routingConfig: `{"temporary_rate_limit_cooldown_seconds":30,"codex_identity_rewrite":true}`, want: true},
		{name: "truncated json", routingConfig: codexRewriteSwitchInvalid, wantErr: true},
		{name: "wrong type", routingConfig: `{"codex_identity_rewrite":"yes"}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := groupCodexIdentityRewrite(tc.routingConfig)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("groupCodexIdentityRewrite(%q) = %v, want %v", tc.routingConfig, got, tc.want)
			}
			if tc.wantErr && got {
				t.Fatal("an unreadable routing_config must never turn the rewrite ON")
			}
		})
	}

	// The cooldown reader must keep working on a string that carries the new
	// key: one routing_config, two independent readers.
	if _, err := groupTemporaryRateLimitCooldown(codexRewriteSwitchOn); err != nil {
		t.Fatalf("the existing cooldown reader broke on a routing_config carrying codex_identity_rewrite: %v", err)
	}
}
