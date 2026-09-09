package mcp

// callrecord_test.go — P7 fences for the call record.
//
// Every test here drives the REAL handler through the REAL mux. A fixture that
// called the recorder directly would prove the recorder works and prove nothing
// about whether the handler uses it, which is the failure this phase is most
// exposed to.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-config-tool/pkg/dbmigrate"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// captureSink collects records the way the local store would.
type captureSink struct {
	mu      sync.Mutex
	records []mcpwire.CallRecord
}

func (c *captureSink) RecordCall(_ context.Context, rec mcpwire.CallRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, rec)
}

func (c *captureSink) all() []mcpwire.CallRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]mcpwire.CallRecord, len(c.records))
	copy(out, c.records)
	return out
}

// recordingPlane builds a plane with a capture sink over a real upstream.
//
// tool lets a test change the tool's state / write-op / schema, which is how
// each refusal branch is reached WITHOUT the test knowing how the refusal is
// implemented.
func recordingPlane(t *testing.T, endpoint string, tool PolicyTool, granted bool) (*http.ServeMux, *captureSink, *CallStats) {
	t.Helper()
	store := NewPolicyStore()
	p := &Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{
			ID: "b1", Name: "github", Transport: TransportStreamableHTTP,
			EndpointURL: endpoint, Status: "active",
		}},
		Toolsets: []PolicyToolset{{
			ID: "ts1", Slug: testToolset, Status: "active", Tools: []PolicyTool{tool},
		}},
	}
	if granted {
		p.Grants = []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}}
	}
	store.Store(p)

	sink := &captureSink{}
	stats := NewCallStats()
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		Logger:          discardLogger(),
		PolicyStore:     store,
		Calls:           sink,
		CallStats:       stats,
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, sink, stats
}

func publishedTool() PolicyTool {
	return PolicyTool{
		ID: "t1", BackendID: "b1", Name: "query_readonly",
		Description:  "Run a read-only SQL query.",
		InputSchema:  `{"type":"object","properties":{"sql":{"type":"string"}}}`,
		ManifestHash: "h1", State: ToolStatePublished,
	}
}

func okUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	up := &recordingUpstream{reply: func(method string) (any, *mcpwire.RPCError) {
		if method == mcpwire.MethodToolsCall {
			return mcpwire.CallToolResult{Content: []mcpwire.ContentBlock{{Type: "text", Text: "42 rows"}}}, nil
		}
		return mcpwire.ListToolsResult{}, nil
	}}
	srv := httptest.NewServer(up.handler())
	t.Cleanup(srv.Close)
	return srv
}

// TestFence_7F1_ArgumentsAreDigestedNeverStoredRaw is fence 7.F1.
//
// 🔴 The canary value must appear NOWHERE in the record. Tool arguments are SQL,
// file contents, internal hostnames and sometimes credentials; a gateway that
// stored them by default would make AiKey a new concentration of exactly the
// data it exists to de-concentrate (R6 / D-4).
func TestFence_7F1_ArgumentsAreDigestedNeverStoredRaw(t *testing.T) {
	const canary = "CANARY_ARGS_9b2c"
	srv := okUpstream(t)
	mux, sink, _ := recordingPlane(t, srv.URL, publishedTool(), true)

	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly",`+
			`"arguments":{"sql":"select * from orders where note='`+canary+`'"}}}`, nil)
	if env.Error != nil {
		t.Fatalf("precondition: the call was refused: %+v", env.Error)
	}

	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("got %d records for one call, want 1", len(recs))
	}
	rec := recs[0]
	if rec.ArgsRaw != nil {
		t.Errorf("args_raw was populated by default: %q. Raw retention requires an explicit "+
			"org-level switch AND a DLP pass (task 7.2).", *rec.ArgsRaw)
	}
	// 🔴 The whole record is searched, not only args_raw: the point of the fence
	// is that the value is nowhere, and a future field could carry it back in.
	blob, _ := json.Marshal(rec)
	if strings.Contains(string(blob), canary) {
		t.Errorf("the argument VALUE survived somewhere in the record: %s", blob)
	}
	// The digest must still say what shape was passed — a record with no digest
	// at all would be private and useless.
	var digest []mcpwire.ArgDigestEntry
	if err := json.Unmarshal([]byte(rec.ArgsDigest), &digest); err != nil {
		t.Fatalf("args_digest is not parseable JSON (%q): %v", rec.ArgsDigest, err)
	}
	if len(digest) != 1 || digest[0].Key != "sql" || digest[0].Type != "string" || digest[0].Len == 0 {
		t.Errorf("the digest does not describe the call: %+v", digest)
	}
}

// TestFence_7F3_ARefusedCallIsRecordedAndNotBilled is fence 7.F3 (R10).
//
// 🔴 "Denied" and "never happened" must never be the same row: the first is the
// signal an administrator is looking for during an incident.
//
// 🔴 The "not billed" half is asserted STRUCTURALLY — the record type has no
// cost field at all — rather than by counting rows in a cost table. Counting
// rows would pass for a build that had a cost field and simply left it zero,
// and the next person to add "just a small usage row here" would not go red.
func TestFence_7F3_ARefusedCallIsRecordedAndNotBilled(t *testing.T) {
	srv := okUpstream(t)

	cases := []struct {
		name       string
		tool       PolicyTool
		granted    bool
		args       string
		wantStatus string
	}{
		{"not granted", publishedTool(), false, `{}`, mcpwire.CallStatusForbidden},
		{"frozen write tool", func() PolicyTool {
			tl := publishedTool()
			tl.State = ToolStateNeedsReview
			tl.WriteOp = true
			return tl
		}(), true, `{}`, mcpwire.CallStatusNeedsReview},
		{"malformed arguments", publishedTool(), true, `{"sql":123}`, mcpwire.CallStatusSchemaRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux, sink, stats := recordingPlane(t, srv.URL, tc.tool, tc.granted)
			_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":`+tc.args+`}}`, nil)
			if env.Error == nil {
				t.Fatalf("precondition: the call was NOT refused")
			}
			recs := sink.all()
			if len(recs) != 1 {
				t.Fatalf("a refused call produced %d records, want exactly 1. A refusal that leaves "+
					"no trace is indistinguishable from nobody having tried.", len(recs))
			}
			if recs[0].Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", recs[0].Status, tc.wantStatus)
			}
			if recs[0].ErrorCode == "" {
				t.Error("error_code is empty on a refusal; the coarse status alone does not tell an " +
					"administrator WHY the call was refused")
			}
			if got := stats.Snapshot().CallsByStatus[tc.wantStatus]; got != 1 {
				t.Errorf("the counter for %q is %d, want 1", tc.wantStatus, got)
			}
		})
	}
}

// TestARefusedCallCarriesNoCostField is the structural half of 7.F3.
func TestARefusedCallCarriesNoCostField(t *testing.T) {
	blob, _ := json.Marshal(mcpwire.CallRecord{})
	for _, forbidden := range []string{"cost", "tokens", "price", "amount", "usd"} {
		if strings.Contains(strings.ToLower(string(blob)), forbidden) {
			t.Errorf("the call record carries a %q-shaped field. A tool call produces no tokens; "+
				"a money-shaped column here will end up in somebody's report, and refusals would "+
				"then be billable by accident.", forbidden)
		}
	}
}

// TestEveryRefusalBranchIsRecordedWithoutBeingTold is the fence behind the
// "observe, do not declare" design.
//
// 🔴 It reaches a refusal the test does NOT enumerate — an unknown tool name,
// which is refused by a branch nothing in P7 touched — and asserts a record
// appeared anyway. That is the property that makes a THIRTEENTH branch safe: no
// branch has to remember to record.
func TestEveryRefusalBranchIsRecordedWithoutBeingTold(t *testing.T) {
	srv := okUpstream(t)
	mux, sink, _ := recordingPlane(t, srv.URL, publishedTool(), true)
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a_tool_that_does_not_exist","arguments":{}}}`, nil)
	if env.Error == nil {
		t.Fatal("precondition: an unknown tool was not refused")
	}
	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("a refusal from a branch this phase never edited produced %d records, want 1", len(recs))
	}
	if recs[0].ToolName != "a_tool_that_does_not_exist" {
		t.Errorf("tool_name = %q; the record must name what the CALLER asked for, which is the "+
			"only thing that makes a probing attempt readable in the log", recs[0].ToolName)
	}
}

// TestASuccessfulCallRecordsWhatItServed covers 7.A2/7.A3's proxy half.
func TestASuccessfulCallRecordsWhatItServed(t *testing.T) {
	srv := okUpstream(t)
	mux, sink, stats := recordingPlane(t, srv.URL, publishedTool(), true)
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{"sql":"select 1"}}}`,
		map[string]string{"User-Agent": "claude-cli/2.1.22 (external)"})
	if env.Error != nil {
		t.Fatalf("the call was refused: %+v", env.Error)
	}
	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Status != mcpwire.CallStatusOK {
		t.Errorf("status = %q, want ok", rec.Status)
	}
	// 🔴 The PUBLISHED hash, so a reader can prove what ran matched what a human
	// approved. A hash recomputed at call time would only prove we agree with
	// ourselves.
	if rec.ManifestHash != "h1" {
		t.Errorf("manifest_hash = %q, want the published h1", rec.ManifestHash)
	}
	if rec.ToolID != "t1" || rec.BackendID != "b1" || rec.VirtualServerID != "ts1" {
		t.Errorf("the record does not identify what served the call: %+v", rec)
	}
	// 🔴 The exact slug, not merely "non-empty": `unknown-app` is also non-empty
	// and would pass a laxer assertion while telling an administrator nothing.
	if rec.AppSlug != "claude-code" {
		t.Errorf("app_slug = %q, want claude-code", rec.AppSlug)
	}
	if rec.Origin != mcpwire.OriginAgent {
		t.Errorf("origin = %q, want agent", rec.Origin)
	}
	if rec.CallID == "" || rec.CreatedAtMs == 0 {
		t.Errorf("the record has no id or no timestamp: %+v", rec)
	}
	if stats.Snapshot().SuccessRatio != 1 {
		t.Errorf("success ratio = %v, want 1", stats.Snapshot().SuccessRatio)
	}
}

// TestAnUnrecognisedClientIsUnknownAppNotEmpty pins task 7.5a2's distinction.
//
// 🔴 `unknown-app` is a VERDICT ("we looked and did not recognise it"), which is
// a different fact from the conversation-audit "attribution pending" state ("a
// second channel has not arrived yet and this WILL change"). Rendering one as
// the other tells an administrator to wait for a value that is never coming.
func TestAnUnrecognisedClientIsUnknownAppNotEmpty(t *testing.T) {
	srv := okUpstream(t)
	mux, sink, _ := recordingPlane(t, srv.URL, publishedTool(), true)
	rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{}}}`,
		map[string]string{"User-Agent": "SomeAgentNobodyHasHeardOf/9"})
	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].AppSlug == "" {
		t.Fatal("app_slug is empty. The existing attribution rules state it is NEVER written empty: " +
			"an empty value collides with 'no app context at all', which is not reachable here.")
	}
	if recs[0].AppSlug != "unknown-app" {
		t.Errorf("app_slug = %q, want unknown-app", recs[0].AppSlug)
	}
}

// TestATransportLevelRefusalIsNotRecordedAsACall — the deliberate NON-record.
//
// 🔴 An unknown Mcp-Session-Id is refused before any tool is named. Recording it
// would invent a row for a call nobody made, in the table an administrator reads
// to answer "who ran what".
func TestATransportLevelRefusalIsNotRecordedAsACall(t *testing.T) {
	srv := okUpstream(t)
	mux, sink, _ := recordingPlane(t, srv.URL, publishedTool(), true)
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_readonly","arguments":{}}}`,
		map[string]string{mcpwire.HeaderSessionID: "a-session-that-never-existed"})
	if env.Error == nil {
		t.Fatal("precondition: an unknown session id was accepted")
	}
	if n := len(sink.all()); n != 0 {
		t.Errorf("a session-level refusal produced %d call records; it must produce none — no tool "+
			"was ever named, so there is no call to record", n)
	}
}

// TestEveryRPCWriterStampsAnOutcome is the fence that keeps the recorder honest
// as the file grows.
//
// 🔴 It DISCOVERS the writers by scanning the source rather than listing them.
// A list would go stale the moment somebody adds a writer, which is exactly the
// case it exists to catch: a new writer that forgets to stamp makes every call
// answered through it record as internal_error, silently.
func TestEveryRPCWriterStampsAnOutcome(t *testing.T) {
	src, err := os.ReadFile("rpcerror.go")
	if err != nil {
		t.Fatalf("read rpcerror.go: %v", err)
	}
	// Writers that answer a JSON-RPC request: they take a ResponseWriter and are
	// named write*. writeJSON is the shared encoder underneath them and is
	// excluded — stamping there would fire for the health and capability
	// documents too.
	re := regexp.MustCompile(`(?m)^func (write\w+)\(w http\.ResponseWriter[^)]*\) \{`)
	body := string(src)
	found := 0
	for _, m := range re.FindAllStringSubmatchIndex(body, -1) {
		name := body[m[2]:m[3]]
		if name == "writeJSON" {
			continue
		}
		found++
		end := strings.Index(body[m[1]:], "\n}\n")
		if end < 0 {
			t.Fatalf("could not find the end of %s", name)
		}
		if !strings.Contains(body[m[1]:m[1]+end], "noteOutcome(") {
			t.Errorf("%s answers a JSON-RPC request without stamping an outcome. Every call "+
				"answered through it would be recorded as internal_error, with nothing saying so. "+
				"Add noteOutcome(w, <frozen code or \"\">, <isError>) at the top.", name)
		}
	}
	if found < 4 {
		t.Fatalf("the writer scan found only %d writers; the pattern has drifted from the file "+
			"and this fence is no longer checking anything", found)
	}
}

// TestCallStatusesMatchTheColumnDomain closes the loop between the wire
// vocabulary and the database's CHECK constraint.
//
// 🔴 Without this, a status the proxy emits and the schema refuses would be
// discovered by the control plane answering 400 forever — a backlog that never
// drains, on a rail whose whole job is not to lose records.
func TestCallStatusesMatchTheColumnDomain(t *testing.T) {
	emitted := []string{
		mcpwire.CallStatusOK, mcpwire.CallStatusForbidden, mcpwire.CallStatusSchemaRejected,
		mcpwire.CallStatusUpstreamError, mcpwire.CallStatusTimeout, mcpwire.CallStatusRateLimited,
		mcpwire.CallStatusNeedsReview, mcpwire.CallStatusCredentialMissing,
		mcpwire.CallStatusInternalError,
	}
	domain := map[string]bool{}
	for _, v := range dbmigrate.MCPCallStatusValues {
		domain[v] = true
	}
	for _, s := range emitted {
		if !domain[s] {
			t.Errorf("the proxy can emit status %q, which is not in mcp_call_event's value domain "+
				"(%v). Every record carrying it would be refused by the control plane and the "+
				"local backlog would never drain.", s, dbmigrate.MCPCallStatusValues)
		}
	}
	if len(emitted) != len(dbmigrate.MCPCallStatusValues) {
		t.Errorf("the column domain has %d values and the proxy emits %d. A value nothing emits is "+
			"either dead or a status somebody forgot to wire.",
			len(dbmigrate.MCPCallStatusValues), len(emitted))
	}
}

// TestMetricNamesAreNotLiteralsInCode is task 7.6c.
//
// 🔴 It reads the JSON tags off the struct and asserts each is registered, so
// ADDING a metric without registering its name goes red. A metric name is a
// contract with whatever alerts on it, and a rename must be a deliberate edit to
// a list somebody looks at — not a struct-tag change nobody reviews.
func TestMetricNamesAreNotLiteralsInCode(t *testing.T) {
	src, err := os.ReadFile("callstats.go")
	if err != nil {
		t.Fatalf("read callstats.go: %v", err)
	}
	registered := map[string]bool{}
	for _, n := range MetricNames {
		registered[n] = true
	}
	block := string(src)
	start := strings.Index(block, "type CallMetrics struct {")
	if start < 0 {
		t.Fatal("CallMetrics is not where this fence looks; the fence has drifted from the code")
	}
	end := strings.Index(block[start:], "\n}\n")
	re := regexp.MustCompile(`json:"([a-z0-9_]+)"`)
	tags := re.FindAllStringSubmatch(block[start:start+end], -1)
	if len(tags) == 0 {
		t.Fatal("no JSON tags found on CallMetrics; this fence is checking nothing")
	}
	for _, m := range tags {
		if !registered[m[1]] {
			t.Errorf("metric %q is published by CallMetrics but is not in MetricNames. "+
				"Register it: a metric name is a contract with whatever alerts on it.", m[1])
		}
	}
	if len(tags) != len(MetricNames) {
		t.Errorf("CallMetrics publishes %d metrics and MetricNames lists %d; a listed name that "+
			"nothing publishes is an alert pointing at nothing", len(tags), len(MetricNames))
	}
}

// TestTheRecordedStatusIsAlwaysADomainConstant closes the gap that
// TestCallStatusesMatchTheColumnDomain cannot see.
//
// 🔴 That test compares two LISTS — the constants against the column's value
// domain — and a list-versus-list check says nothing about what the code
// actually emits. A `return "mystery"` inside status() satisfies it completely
// while writing a value the CHECK constraint refuses, which shows up as the
// control plane answering 400 forever and a backlog that never drains.
//
// So this one reads the FUNCTION and requires every value it returns to come
// from the shared vocabulary. It discovers the returns rather than listing
// them, so a new branch is covered without anyone adding a case here.
func TestTheRecordedStatusIsAlwaysADomainConstant(t *testing.T) {
	src, err := os.ReadFile("callrecord.go")
	if err != nil {
		t.Fatalf("read callrecord.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (c *callRecorder) status(")
	if start < 0 {
		t.Fatal("callRecorder.status is not where this fence looks; the fence has drifted from the code")
	}
	end := strings.Index(body[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not find the end of callRecorder.status")
	}
	fn := body[start : start+end]

	returns := regexp.MustCompile(`return\s+([^\n]+)`).FindAllStringSubmatch(fn, -1)
	if len(returns) < 3 {
		t.Fatalf("the status function has %d returns; the fence's pattern has drifted and it is "+
			"no longer checking anything", len(returns))
	}
	for _, m := range returns {
		expr := strings.TrimSpace(m[1])
		if !strings.HasPrefix(expr, "mcpwire.CallStatus") && !strings.HasPrefix(expr, "status") {
			t.Errorf("callRecorder.status returns %q, which is not a shared CallStatus constant. "+
				"mcp_call_event.status carries a CHECK constraint: a value outside the domain is "+
				"refused by the control plane forever, and the local backlog never drains.", expr)
		}
	}
}
