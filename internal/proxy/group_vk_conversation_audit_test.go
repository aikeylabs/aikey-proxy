package proxy

// group_vk_conversation_audit_test.go — 13.F10 / I29 / D-56.
//
// # The premise leg A silently inherits
//
// The conversation audit extracts BOTH the assistant's text and its tool calls
// from the same SSE walk (`extractFrame`), and that walk is dispatched on
// `RequestContext.ProtocolFamily`. An empty family means no extractor, which
// means an empty record — not an error, not a log line, just a turn that reads
// as "the model said nothing and called nothing".
//
// On the GROUP-VK route that premise is not free. The group route deliberately
// arrives with `ProviderCode` empty (the provider is a property of the resolved
// ACCOUNT, not of the route), and `forward_and_resolve.go`'s family fallback
// needs a provider code to work from. `group_serve.go`'s
//
//	rc.ProviderCode = canonicalCode
//
// is what supplies it. Delete that line and the family stays empty — while the
// request itself still succeeds, the upstream is still reached, and the usage
// ledger is still correct. The ONLY visible symptom is an audit record that is
// quietly empty.
//
// 🔴 So this test asserts BOTH halves in one run, and that is the whole point of
// I29: leg A (tool calls) and the pre-existing assistant text share one premise,
// so they must be shown to fail TOGETHER. A test that only checked tool calls
// would let somebody "fix" it by special-casing tools while text stayed broken —
// or, far more likely, conclude that leg A was the fragile part when the premise
// under both of them was what moved.
//
// # 🔴 Two shapes, because the premise has TWO suppliers
//
// Found while drilling this fence (2026-09-03), and it changes what the fence
// has to look like. `forward_and_resolve.go` derives the family in two steps:
//
//	1. LookupByBaseURL(route.BaseURL)      ← wins whenever the account points at
//	                                         a KNOWN vendor host
//	2. ProtocolFamily(route.ProviderCode)  ← only reached when step 1 misses
//
// A group account on plain `api.anthropic.com` is served entirely by step 1, so
// `rc.ProviderCode = canonicalCode` is NOT load-bearing for the audit there —
// and a fence written only in that shape passes whether or not the write-back
// exists. That is what the first version of this test did.
//
// The write-back is load-bearing exactly when the account's base URL is NOT in
// the route table: a relay / self-hosted endpoint, which is a shape this product
// exists to support. So both are exercised, and only the relay one can prove
// I29.
//
// 能红 (relay shape): neuter the `route.ProviderCode != ""` branch in
//       forward_and_resolve.go — both assertions go red together, while the
//       forward itself still succeeds.
// ⚠️ NOT 能红 by deleting `rc.ProviderCode = canonicalCode` outright: that line
//       also feeds path health and the outbound resolve, so removing it kills
//       the route before the audit is reached (the control below fires instead).
//       The task text prescribed that mutation; it is too broad to isolate I29.
//
// tasks: 13.F10 · checklist D-56 / F-43 · 技术方案 I29

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observer/conversation_audit"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// capturingSink collects the records the audit observer submits.
type capturingSink struct {
	mu   sync.Mutex
	recs []*conversation_audit.ConversationRecord
	done chan struct{}
	once sync.Once
}

func newCapturingSink() *capturingSink {
	return &capturingSink{done: make(chan struct{})}
}

func (s *capturingSink) Submit(rec *conversation_audit.ConversationRecord) {
	s.mu.Lock()
	s.recs = append(s.recs, rec)
	s.mu.Unlock()
	s.once.Do(func() { close(s.done) })
}

// first waits for the submitted record, or returns an EMPTY one.
//
// 🔴 It reports and continues instead of t.Fatalf-ing, and that is not
// politeness — it is what makes I29 legible. An empty ProtocolFamily makes the
// observer drop the whole turn (CONTENT_EMPTY_EXTRACT), so a fatal here would
// print ONE failure about a timeout, and the reader would go looking at the
// observer plumbing. Continuing against a zero record makes BOTH the text and
// the tool-call assertions fire, which is the thing I29 actually claims: they
// share one premise and they fail together.
func (s *capturingSink) first(t *testing.T) *conversation_audit.ConversationRecord {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		t.Errorf("the conversation audit submitted NO record within 3s — the turn was dropped " +
			"whole, which is what an empty ProtocolFamily looks like from here: the request " +
			"succeeded, the upstream was reached, and the audit simply produced nothing. " +
			"The two assertions below say what was lost.")
		return &conversation_audit.ConversationRecord{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recs[0]
}

// buildConversationAuditRegistry wires the REAL conversation-audit observer over
// a capturing sink.
//
// 🔴 conversation_audit.New, not a stand-in: the property under test is that the
// production extractor receives a usable ProtocolFamily. A fake observer that
// recorded the family would assert the plumbing while leaving the thing that
// actually consumes it untested — and the consumer is where the emptiness turns
// into an empty record.
func buildConversationAuditRegistry(t *testing.T, sink conversation_audit.RecordSink) *observer.Registry {
	t.Helper()
	observer.ResetRegistrationsForTest()
	t.Cleanup(observer.ResetRegistrationsForTest)
	observer.RegisterObserver(observer.Observer{
		Name:         "conversation-audit-groupvk-test",
		OwnerAppSlug: "aikey-proxy-core",
		Streams:      []string{observer.StreamUserChat},
		Build: func(_ map[string]any) (observer.StreamingObserver, error) {
			return conversation_audit.New(conversation_audit.Config{
				Sink:     sink,
				Enabled:  func() bool { return true },
				MaxBytes: func() int { return 1 << 20 },
				Logger:   slog.Default(),
			}), nil
		},
	})
	reg := observer.NewRegistry(slog.Default())
	reg.BuildObservers(func(_ string) bool { return true }, nil)
	if reg.Active() != 1 {
		t.Fatalf("expected exactly 1 active observer, got %d", reg.Active())
	}
	return reg
}

// anthropicTurnWithTextAndTool is one Anthropic SSE turn carrying an assistant
// sentence AND two tool calls, in the wire shape the extractor's own fixtures use.
const anthropicTurnWithTextAndTool = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_grp","model":"claude-sonnet-4-5","usage":{"input_tokens":7,"output_tokens":0}}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me look."}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_a","name":"query_readonly"}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"sql\":\"SELECT 1\"}"}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_b","name":"create_issue"}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"title\":\"x\"}"}}` + "\n\n" +
	"event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":31}}` + "\n\n" +
	"event: message_stop\n" +
	`data: {"type":"message_stop"}` + "\n\n"

func TestGroupVK_TextAndToolsBothCaptured(t *testing.T) {
	for _, shape := range []struct {
		name string
		// accountBaseURL empty → the provider's own default (a KNOWN vendor
		// host, served by the BaseURL lookup). Non-empty and unknown → the relay
		// shape, where the ProviderCode write-back is the only supplier.
		accountBaseURL string
		wantHost       string
	}{
		{name: "known_vendor_base_url", accountBaseURL: "", wantHost: "api.anthropic.com"},
		{name: "relay_base_url_the_writeback_is_load_bearing",
			accountBaseURL: "https://relay.example.internal", wantHost: "relay.example.internal"},
	} {
		t.Run(shape.name, func(t *testing.T) {
			runGroupVKAuditShape(t, shape.accountBaseURL, shape.wantHost)
		})
	}
}

func runGroupVKAuditShape(t *testing.T, accountBaseURL, wantHost string) {
	t.Helper()
	key := grKey()
	// 🔴 The real group-VK shape: the provider lives on the candidate ACCOUNT,
	// and the route's own Provider / ProviderCode are empty. This is the whole
	// reason group_serve has to write the resolved code back onto the route.
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1",
			BaseURL: accountBaseURL,
		}, "oauth-tok-live"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp-audit", ProtocolType: "anthropic", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)
	tr.respHeader = http.Header{"Content-Type": []string{"text/event-stream"}}
	tr.bodyByAuth = map[string]string{"Bearer oauth-tok-live": anthropicTurnWithTextAndTool}

	sink := newCapturingSink()
	p.SetObserverRegistry(buildConversationAuditRegistry(t, sink))

	req, w := groupReq(`{"model":"claude-sonnet-4-5","stream":true,` +
		`"messages":[{"role":"user","content":"look at the db"}],"max_tokens":64}`)
	req.Header.Set("Accept", "text/event-stream")
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("group-VK forward failed: status=%d body=%s", w.Code, w.Body.String())
	}

	rec := sink.first(t)

	// --- the two assertions I29 requires to fail TOGETHER --------------------

	// (1) the pre-existing half: assistant text.
	if !strings.Contains(rec.AssistantText, "Let me look.") {
		t.Errorf("assistant_text = %q, want it to contain %q.\n"+
			"🔴 On the group-VK route the audit's ProtocolFamily comes from the provider code "+
			"group_serve writes back onto the route. Empty family ⇒ no extractor ⇒ an empty "+
			"record, while the request itself still succeeds.",
			rec.AssistantText, "Let me look.")
	}

	// (2) leg A: the tool calls from the SAME walk.
	if len(rec.ToolCalls) != 2 {
		t.Errorf("tool_calls has %d entries, want 2 (query_readonly, create_issue).\n"+
			"🔴 If assistant_text is ALSO empty above, the fault is not in tool-call extraction — "+
			"it is the shared ProtocolFamily premise (I29). Fixing leg A alone would leave text "+
			"broken and hide the real cause.", len(rec.ToolCalls))
	} else {
		names := []string{rec.ToolCalls[0].ToolName, rec.ToolCalls[1].ToolName}
		if names[0] != "query_readonly" || names[1] != "create_issue" {
			t.Errorf("tool names = %v, want [query_readonly create_issue] in call order", names)
		}
		// 🔴 R6 / R16: the audit stores argument SHAPES, and the digest was
		// actually populated on this route — an extractor that produced tool
		// names but no shapes would pass the count check above.
		//
		// 🔴 There is deliberately NO "and it contains no values" assertion here.
		// ArgDigestEntry is {Key, Type, Len}: there is no field a value could
		// occupy, so the property is constructively true and a test for it would
		// assert nothing while looking like coverage (R53). The place that
		// property can actually break is the digest BUILDER, and it is fenced
		// there (TestDigestArgsNeverCarriesValues).
		sql := rec.ToolCalls[0].ArgsDigest
		if len(sql) != 1 || sql[0].Key != "sql" || sql[0].Type != "string" || sql[0].Len == 0 {
			t.Errorf("query_readonly digest = %+v, want one {key:sql type:string len:>0} entry", sql)
		}
	}

	// The control: the forward itself was fine. Without this, a run where the
	// group route failed outright would produce the same two failures above and
	// send the reader looking for an extraction bug.
	if tr.host != wantHost {
		t.Fatalf("outbound host=%q want %q — the group route did not resolve, so the assertions "+
			"above are about the wrong thing", tr.host, wantHost)
	}
}
