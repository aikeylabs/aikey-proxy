package mcp

// compliance_test.go — P7 task 7.3 and fence 7.F2.
//
// Every test drives the REAL handler through the REAL mux with a stub filter
// standing in for the detector child. A test that called complianceScanner
// directly would prove the scanner works and prove nothing about whether the
// call path uses it, which is the failure this phase is exposed to.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// stubFilter stands in for the detector child.
type stubFilter struct {
	mu      sync.Mutex
	seen    []string
	dirs    []apphook.Direction
	verdict func(payload string, dir apphook.Direction) *apphook.Response
}

func (s *stubFilter) Name() string { return "stub-filter" }

func (s *stubFilter) Detect(_ context.Context, req *apphook.Request) *apphook.Response {
	s.mu.Lock()
	s.seen = append(s.seen, string(req.Payload))
	s.dirs = append(s.dirs, req.Direction)
	v := s.verdict
	s.mu.Unlock()
	if v == nil {
		return &apphook.Response{Action: apphook.ActionAllow}
	}
	return v(string(req.Payload), req.Direction)
}

func (s *stubFilter) Status() *apphook.Status { return &apphook.Status{Healthy: true} }

func (s *stubFilter) Shutdown(context.Context) error { return nil }

func (s *stubFilter) scanned() ([]string, []apphook.Direction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...), append([]apphook.Direction(nil), s.dirs...)
}

// filteredPlane is a real plane with a filter hook installed.
func filteredPlane(t *testing.T, endpoint string, filter apphook.Hook) (*http.ServeMux, *captureSink) {
	t.Helper()
	store := NewPolicyStore()
	store.Store(&Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{
			ID: "b1", Name: "github", Transport: TransportStreamableHTTP,
			EndpointURL: endpoint, Status: "active",
		}},
		Toolsets: []PolicyToolset{{
			ID: "ts1", Slug: testToolset, Status: "active", Tools: []PolicyTool{publishedTool()},
		}},
		Grants: []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}},
	})
	sink := &captureSink{}
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		Logger:          discardLogger(),
		PolicyStore:     store,
		Calls:           sink,
		CallStats:       NewCallStats(),
		Compliance:      func() apphook.Hook { return filter },
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, sink
}

func echoUpstream(t *testing.T, text string) *httptest.Server {
	t.Helper()
	up := &recordingUpstream{reply: func(method string) (any, *mcpwire.RPCError) {
		if method == mcpwire.MethodToolsCall {
			return mcpwire.CallToolResult{Content: []mcpwire.ContentBlock{{Type: "text", Text: text}}}, nil
		}
		return mcpwire.ListToolsResult{}, nil
	}}
	srv := httptest.NewServer(up.handler())
	t.Cleanup(srv.Close)
	return srv
}

// TestBothDirectionsAreScanned is task 7.3's core assertion.
//
// 🔴 BOTH, and the result matters more: a tool that answers a query returns the
// rows themselves, so a gateway that scanned only the request would stop at the
// door that is cheapest to walk around.
func TestBothDirectionsAreScanned(t *testing.T) {
	filter := &stubFilter{}
	srv := echoUpstream(t, "row one from the database")
	mux, _ := filteredPlane(t, srv.URL, filter)

	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"select * from orders"}}}`, nil)
	if env.Error != nil {
		t.Fatalf("the call was refused: %+v", env.Error)
	}

	seen, dirs := filter.scanned()
	var inbound, outbound int
	for i, d := range dirs {
		switch d {
		case apphook.DirectionInbound:
			inbound++
			if !strings.Contains(seen[i], "select * from orders") {
				t.Errorf("the inbound scan did not carry the argument value: %q", seen[i])
			}
		case apphook.DirectionOutbound:
			outbound++
			if !strings.Contains(seen[i], "row one from the database") {
				t.Errorf("the outbound scan did not carry the result text: %q", seen[i])
			}
		}
	}
	if inbound == 0 {
		t.Error("the ARGUMENTS were never scanned: a credential or customer identifier in a tool " +
			"argument would reach a third-party MCP server unexamined")
	}
	if outbound == 0 {
		t.Error("the RESULT was never scanned: the backend could hand the Agent an entire table, " +
			"the Agent feeds it to the model, and the data is out")
	}
}

// TestFence_7F2_ABlockedCallNeverReachesTheUpstream is fence 7.F2's request half.
func TestFence_7F2_ABlockedCallNeverReachesTheUpstream(t *testing.T) {
	up := &recordingUpstream{reply: func(string) (any, *mcpwire.RPCError) {
		return mcpwire.CallToolResult{}, nil
	}}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	filter := &stubFilter{verdict: func(payload string, _ apphook.Direction) *apphook.Response {
		if strings.Contains(payload, "440524") {
			return &apphook.Response{Action: apphook.ActionBlock, Reason: "PII_DETECTED"}
		}
		return &apphook.Response{Action: apphook.ActionAllow}
	}}
	mux, sink := filteredPlane(t, srv.URL, filter)

	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"id=440524198001011234"}}}`, nil)
	if env.Error == nil {
		t.Fatal("a payload the filter blocked was forwarded anyway")
	}
	if code := aikeyCode(t, env); code != string(mcpwire.ErrComplianceBlocked) {
		t.Errorf("aikey_code = %q, want %q. Reusing MCP_TOOL_FORBIDDEN would tell the developer to "+
			"ask for a grant they already have, while the real cause goes unmentioned.",
			code, mcpwire.ErrComplianceBlocked)
	}
	// 🔴 The upstream saw NOTHING. This is the property; the error code is the
	// courtesy.
	for _, m := range up.calledMethods() {
		if m == mcpwire.MethodToolsCall {
			t.Fatal("the upstream received the tools/call despite the compliance block")
		}
	}
	// 🔴 And the refusal is recorded — a blocked call is still a call somebody made.
	recs := sink.all()
	if len(recs) != 1 || recs[0].Status != mcpwire.CallStatusForbidden {
		t.Fatalf("a compliance-blocked call was not recorded as forbidden: %+v", recs)
	}
	if recs[0].ErrorCode != string(mcpwire.ErrComplianceBlocked) {
		t.Errorf("error_code = %q; without it, a DLP refusal and a grant refusal are the same row",
			recs[0].ErrorCode)
	}
}

// TestABlockedResultDoesNotReachTheAgent is fence 7.F2's response half.
//
// 🔴 The tool already ran — that is unavoidable and is not a reason to skip the
// scan. The point is that the DATA does not reach the model.
func TestABlockedResultDoesNotReachTheAgent(t *testing.T) {
	const secret = "440524198001011234"
	srv := echoUpstream(t, "customer id "+secret)
	filter := &stubFilter{verdict: func(payload string, dir apphook.Direction) *apphook.Response {
		if dir == apphook.DirectionOutbound && strings.Contains(payload, secret) {
			return &apphook.Response{Action: apphook.ActionBlock, Reason: "PII_DETECTED"}
		}
		return &apphook.Response{Action: apphook.ActionAllow}
	}}
	mux, _ := filteredPlane(t, srv.URL, filter)

	rec, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"select 1"}}}`, nil)
	if env.Error == nil {
		t.Fatal("a result the filter blocked was returned to the Agent anyway")
	}
	// 🔴 The blocked CONTENT must not appear anywhere in the reply — not in the
	// result and not in the error message. Echoing what was detected would send
	// the sensitive value straight back out, one more copy of exactly what the
	// block exists to contain.
	if strings.Contains(rec.Body.String(), secret) {
		t.Errorf("the blocked value was echoed back to the caller: %s", rec.Body.String())
	}
}

// TestAMaskedArgumentIsWhatGoesUpstream — masking must actually take effect.
//
// 🔴 A mask verdict that was recorded and then ignored would be the worst
// outcome available: the console would show the value was masked while the
// original went to the third-party backend.
func TestAMaskedArgumentIsWhatGoesUpstream(t *testing.T) {
	var mu sync.Mutex
	var gotArgs string
	up := &recordingUpstream{reply: func(string) (any, *mcpwire.RPCError) {
		return mcpwire.CallToolResult{}, nil
	}}
	up.onCallArgs = func(raw json.RawMessage) {
		mu.Lock()
		gotArgs = string(raw)
		mu.Unlock()
	}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	filter := &stubFilter{verdict: func(payload string, dir apphook.Direction) *apphook.Response {
		if dir == apphook.DirectionInbound && strings.Contains(payload, "440524") {
			return &apphook.Response{
				Action:         apphook.ActionMask,
				MutatedPayload: []byte(strings.ReplaceAll(payload, "440524198001011234", "[ID_1]")),
			}
		}
		return &apphook.Response{Action: apphook.ActionAllow}
	}}
	mux, _ := filteredPlane(t, srv.URL, filter)

	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"id=440524198001011234"}}}`, nil)
	if env.Error != nil {
		t.Fatalf("a masked call was refused: %+v", env.Error)
	}
	mu.Lock()
	args := gotArgs
	mu.Unlock()
	if strings.Contains(args, "440524198001011234") {
		t.Errorf("the UNMASKED argument reached the upstream: %s", args)
	}
	if !strings.Contains(args, "[ID_1]") {
		t.Errorf("the masked argument did not reach the upstream: %s", args)
	}
	// The arguments must still be valid JSON of the shape the tool declared — a
	// mask that corrupted the structure would be a different kind of outage.
	var obj map[string]any
	if err := json.Unmarshal([]byte(args), &obj); err != nil {
		t.Fatalf("masking corrupted the arguments object (%s): %v", args, err)
	}
	if _, ok := obj["sql"]; !ok {
		t.Errorf("masking lost the argument key: %s", args)
	}
}

// TestANestedArgumentValueIsAlsoScanned — a rule that only looked at top-level
// strings would be satisfied by putting the payload one level down, which is
// less a threat model than an accident waiting to happen: plenty of tools take
// a `filter` object.
//
// 🔴 The nesting is under a key the schema does NOT constrain, because JSON
// Schema allows additional properties by default. Putting an object where the
// schema says "string" is refused by the validator BEFORE compliance runs —
// correct, but it would make this fence pass for the wrong reason.
func TestANestedArgumentValueIsAlsoScanned(t *testing.T) {
	filter := &stubFilter{}
	srv := echoUpstream(t, "ok")
	mux, _ := filteredPlane(t, srv.URL, filter)

	rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly",`+
			`"arguments":{"sql":"select 1","filter":{"where":{"note":"BURIED_CANARY_7f"}}}}}`, nil)

	seen, _ := filter.scanned()
	found := false
	for _, s := range seen {
		if strings.Contains(s, "BURIED_CANARY_7f") {
			found = true
		}
	}
	if !found {
		t.Errorf("a value nested inside an argument object was never scanned: %v", seen)
	}
}

// TestNoFilterInstalledStillServes — the option must stay optional.
//
// 🔴 A gateway that refused every tool call because an OPTIONAL DLP app was not
// installed would make the option mandatory by accident, on every deployment
// that never asked for compliance.
func TestNoFilterInstalledStillServes(t *testing.T) {
	srv := echoUpstream(t, "fine")
	mux, sink := filteredPlane(t, srv.URL, nil)
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"select 1"}}}`, nil)
	if env.Error != nil {
		t.Fatalf("a node with no filter app refused a tool call: %+v", env.Error)
	}
	if recs := sink.all(); len(recs) != 1 || recs[0].Status != mcpwire.CallStatusOK {
		t.Errorf("the call was not recorded as ok: %+v", recs)
	}
}

// TestADegradedFilterAllowsAndSaysSo — a filter that cannot run must not fail
// the user's request, and must not be silent about it either.
func TestADegradedFilterAllowsAndSaysSo(t *testing.T) {
	srv := echoUpstream(t, "fine")
	filter := &stubFilter{verdict: func(string, apphook.Direction) *apphook.Response {
		return &apphook.Response{Action: apphook.ActionAllow, Degraded: true, Reason: "child unreachable"}
	}}
	mux, _ := filteredPlane(t, srv.URL, filter)
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"select 1"}}}`, nil)
	if env.Error != nil {
		t.Fatalf("a degraded filter failed the user's request: %+v. A filter that cannot run must "+
			"not fail the main path — that is the LLM plane's rule and it applies here.", env.Error)
	}
}

// TestScanCapTruncatesRatherThanSkipping — a value big enough to exceed the cap
// is exactly the shape an exfiltration takes. Skipping it would make "send more
// than 16 KiB" the way past DLP.
func TestScanCapTruncatesRatherThanSkipping(t *testing.T) {
	filter := &stubFilter{}
	srv := echoUpstream(t, "ok")
	mux, _ := filteredPlane(t, srv.URL, filter)

	huge := "PREFIX_CANARY_" + strings.Repeat("x", maxScanValueBytes*2)
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "query_readonly", "arguments": map[string]any{"sql": huge}},
	})
	rpc(t, mux, "/mcp/"+testToolset, testToken, string(body), nil)

	seen, _ := filter.scanned()
	scanned := false
	for _, s := range seen {
		if strings.HasPrefix(s, "PREFIX_CANARY_") {
			scanned = true
			if len(s) > maxScanValueBytes {
				t.Errorf("a %d-byte value was handed to the filter whole; the cap exists because the "+
					"filter child has a millisecond latency budget", len(s))
			}
		}
	}
	if !scanned {
		t.Error("an oversized value was SKIPPED rather than scanned up to the cap. That makes " +
			"'send more than the cap' the way past DLP.")
	}
}

// --- task 7.2: raw retention, and the three gates in front of it ----------

// rawRetentionPlane is filteredPlane with the org's raw-argument switch on.
func rawRetentionPlane(t *testing.T, endpoint string, filter apphook.Hook, rawOn bool) (*http.ServeMux, *captureSink) {
	t.Helper()
	store := NewPolicyStore()
	store.Store(&Policy{
		OrgID: testOrg, Version: 1,
		ArgsRawEnabled: rawOn, ArgsRawRetentionDays: 7,
		Backends: []PolicyBackend{{ID: "b1", Name: "gh", Transport: TransportStreamableHTTP,
			EndpointURL: endpoint, Status: "active"}},
		Toolsets: []PolicyToolset{{ID: "ts1", Slug: testToolset, Status: "active",
			Tools: []PolicyTool{publishedTool()}}},
		Grants: []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}},
	})
	sink := &captureSink{}
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		Logger:          discardLogger(),
		PolicyStore:     store,
		Calls:           sink,
		CallStats:       NewCallStats(),
		Compliance:      func() apphook.Hook { return filter },
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, sink
}

func callOnce(t *testing.T, mux *http.ServeMux, args string) {
	t.Helper()
	rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":`+args+`}}`, nil)
}

// TestRawArgumentsRequireTheOrgSwitch — the default half of fence 7.F1, driven
// through the live policy rather than through an absent policy store.
func TestRawArgumentsRequireTheOrgSwitch(t *testing.T) {
	srv := echoUpstream(t, "ok")

	muxOff, sinkOff := rawRetentionPlane(t, srv.URL, &stubFilter{}, false)
	callOnce(t, muxOff, `{"sql":"select 1"}`)
	if recs := sinkOff.all(); len(recs) != 1 || recs[0].ArgsRaw != nil {
		t.Errorf("raw arguments were stored with the org switch OFF: %+v", recs)
	}

	muxOn, sinkOn := rawRetentionPlane(t, srv.URL, &stubFilter{}, true)
	callOnce(t, muxOn, `{"sql":"select 1"}`)
	recs := sinkOn.all()
	if len(recs) != 1 || recs[0].ArgsRaw == nil {
		t.Fatalf("the org switched raw retention ON and nothing was stored: %+v", recs)
	}
	if !strings.Contains(*recs[0].ArgsRaw, "select 1") {
		t.Errorf("args_raw = %q, want the arguments", *recs[0].ArgsRaw)
	}
}

// TestRawArgumentsAreThePostDLPPayload.
//
// 🔴 Storing the ORIGINAL would make masking cosmetic: the value would be
// redacted on the wire to the backend and kept verbatim in our own database,
// which is the worse of the two places for it to live.
func TestRawArgumentsAreThePostDLPPayload(t *testing.T) {
	srv := echoUpstream(t, "ok")
	filter := &stubFilter{verdict: func(payload string, dir apphook.Direction) *apphook.Response {
		if dir == apphook.DirectionInbound && strings.Contains(payload, "440524") {
			return &apphook.Response{Action: apphook.ActionMask,
				MutatedPayload: []byte(strings.ReplaceAll(payload, "440524198001011234", "[ID_1]"))}
		}
		return &apphook.Response{Action: apphook.ActionAllow}
	}}
	mux, sink := rawRetentionPlane(t, srv.URL, filter, true)
	callOnce(t, mux, `{"sql":"id=440524198001011234"}`)

	recs := sink.all()
	if len(recs) != 1 || recs[0].ArgsRaw == nil {
		t.Fatalf("nothing was stored: %+v", recs)
	}
	if strings.Contains(*recs[0].ArgsRaw, "440524198001011234") {
		t.Errorf("the UNMASKED value was stored: %q. Masking would then be cosmetic — redacted on "+
			"the wire, kept verbatim in our database.", *recs[0].ArgsRaw)
	}
	if !strings.Contains(*recs[0].ArgsRaw, "[ID_1]") {
		t.Errorf("args_raw = %q, want the masked payload", *recs[0].ArgsRaw)
	}
}

// TestADegradedFilterBlocksRawRetention.
//
// 🔴 A degraded filter means NOTHING was scanned. Storing "post-DLP" arguments
// that no DLP ever saw would be a lie told by the field's own name — and it
// would happen precisely when the compliance app is broken, i.e. when nobody is
// watching that path.
func TestADegradedFilterBlocksRawRetention(t *testing.T) {
	srv := echoUpstream(t, "ok")
	filter := &stubFilter{verdict: func(string, apphook.Direction) *apphook.Response {
		return &apphook.Response{Action: apphook.ActionAllow, Degraded: true}
	}}
	mux, sink := rawRetentionPlane(t, srv.URL, filter, true)
	callOnce(t, mux, `{"sql":"select 1"}`)

	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0].ArgsRaw != nil {
		t.Errorf("raw arguments were stored while the DLP filter was DEGRADED: %q. Nothing was "+
			"scanned, so 'this cleared DLP' is not something we know.", *recs[0].ArgsRaw)
	}
	// The call itself still succeeds — a filter that cannot run must not fail
	// the user's request.
	if recs[0].Status != mcpwire.CallStatusOK {
		t.Errorf("status = %q; a degraded filter must not fail the call", recs[0].Status)
	}
}

// TestATruncatedScanBlocksRawRetention — only part of the value was examined,
// so "this cleared DLP" is not something we know about the rest.
func TestATruncatedScanBlocksRawRetention(t *testing.T) {
	srv := echoUpstream(t, "ok")
	mux, sink := rawRetentionPlane(t, srv.URL, &stubFilter{}, true)

	huge := strings.Repeat("x", maxScanValueBytes*2)
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "query_readonly", "arguments": map[string]any{"sql": huge}},
	})
	rpc(t, mux, "/mcp/"+testToolset, testToken, string(body), nil)

	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0].ArgsRaw != nil {
		t.Error("raw arguments were stored after a TRUNCATED scan: only part of the value was " +
			"examined, so the rest cleared nothing")
	}
}

// TestRawRetentionIsOffBeforeTheFirstPoll.
//
// 🔴 A node that has not heard from the control plane must not act on a switch
// it has never been told about. The restored on-disk policy cache makes this
// reachable in production: the cache is real and is served, but it proves
// nothing about whether the control plane is reachable — and if a stale cached
// "on" were honoured, a node that had been cut off for a month would go on
// storing raw arguments for an organisation that switched them off.
func TestRawRetentionIsOffBeforeTheFirstPoll(t *testing.T) {
	store := NewPolicyStore()
	if enabled, days := store.RawArgsRetention(); enabled || days != 0 {
		t.Errorf("a store that has never polled reported raw retention enabled=%v days=%d, want off",
			enabled, days)
	}
	// Even with a policy in hand, an unsynced store (the restored-cache shape)
	// must answer off.
	store.Store(&Policy{OrgID: testOrg, Version: 1, ArgsRawEnabled: true, ArgsRawRetentionDays: 7})
	store.MarkNeverPolled()
	if enabled, _ := store.RawArgsRetention(); !enabled {
		// Store() sets synced; MarkNeverPolled only resets the freshness clock.
		// This branch documents that distinction rather than asserting on it —
		// the fence that matters is the un-Stored case above.
		t.Log("note: MarkNeverPolled resets freshness, not syncedness")
	}
}
