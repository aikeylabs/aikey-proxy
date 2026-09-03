package mcp

// Fence 6.F1 (requirement R4) — restricted retry.
//
// 🔴 The invariant: a tool call is retried ONLY when retrying cannot execute it
// twice. Widening that to "any failure" is the mutation the fence exists to
// catch, and its real-world cost is a customer's `create_issue` opening two
// issues — or a payment being taken twice.
//
// The two safe cases, and nothing else:
//
//	the request provably never arrived  (connection refused / DNS / TLS)
//	the tool declares itself idempotent (set by a human at review, default false)

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/fallbackpolicy"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// retryStack wires the real handler to a controllable upstream and captures logs.
func retryStack(t *testing.T, idempotent bool, endpoint string) (*http.ServeMux, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	policy := &Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{
			ID: "b1", Name: "db", Transport: TransportStreamableHTTP,
			EndpointURL: endpoint, Status: StatusActive,
		}},
		Toolsets: []PolicyToolset{{
			ID: "ts1", Slug: testToolset, Status: StatusActive,
			Tools: []PolicyTool{{
				ID: "t1", BackendID: "b1", Name: "create_issue", State: ToolStatePublished,
				InputSchema: `{"type":"object"}`, Idempotent: idempotent, WriteOp: true,
			}},
		}},
		Grants: []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}},
	}
	store := NewPolicyStore()
	store.Store(policy)
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		PolicyStore:     store,
		Logger:          slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, logs
}

func callRetryTool(t *testing.T, mux *http.ServeMux) mcpwire.Envelope {
	t.Helper()
	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call",`+
			`"params":{"name":"create_issue","arguments":{}}}`, nil)
	return env
}

// countingUpstream answers every call with a 500 and counts the attempts.
type countingUpstream struct {
	mu    sync.Mutex
	calls int
}

func (u *countingUpstream) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.calls++
		u.mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	})
}

func (u *countingUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

// TestFence_6F1_A5xxOnANonIdempotentToolIsNotRetried.
//
// 🔴 THE case R4 exists for. The request WAS delivered — the upstream answered —
// so `create_issue` may already have created the issue. A second attempt makes
// a second issue, and nothing downstream can tell them apart.
func TestFence_6F1_A5xxOnANonIdempotentToolIsNotRetried(t *testing.T) {
	up := &countingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()
	mux, logs := retryStack(t, false, srv.URL)

	env := callRetryTool(t, mux)
	if env.Error == nil {
		t.Fatal("a 500 from the backend must surface as an error")
	}
	if n := up.count(); n != 1 {
		t.Fatalf("🔴 a non-idempotent tool was called %d times after a 5xx. The request was "+
			"delivered, so the tool may already have run — this is a duplicated write on a "+
			"customer's system.", n)
	}
	// 🔴 And the deliberate non-retry must be VISIBLE, or the user sees one
	// failure and assumes the gateway simply gave up.
	if !strings.Contains(logs.String(), "proxy.mcp.retry_suppressed_non_idempotent") {
		t.Fatalf("the suppression must emit its event so an operator can answer "+
			"\"why did this not retry\":\n%s", logs)
	}
}

// TestFence_6F1_ATimeoutOnANonIdempotentToolIsNotRetried — same rule, the other
// failure that looks retryable and is not.
func TestFence_6F1_ATimeoutOnANonIdempotentToolIsNotRetried(t *testing.T) {
	// 🔴 The delay must exceed the PLANE timeout set below, or this test never
	// times out at all — it just waits and succeeds. The P6 drill caught exactly
	// that: the first version used the 60s default ceiling against a 2s delay,
	// so the "a timeout is not retried" fence never saw a timeout and would have
	// passed against a build that retried every one of them.
	up := &recordingUpstream{delay: 2 * time.Second}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	logs := &bytes.Buffer{}
	policy := &Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{ID: "b1", Name: "db", Transport: TransportStreamableHTTP,
			EndpointURL: srv.URL, Status: StatusActive}},
		Toolsets: []PolicyToolset{{ID: "ts1", Slug: testToolset, Status: StatusActive,
			Tools: []PolicyTool{{ID: "t1", BackendID: "b1", Name: "create_issue",
				State: ToolStatePublished, InputSchema: `{"type":"object"}`, WriteOp: true}}}},
		Grants: []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}},
	}
	store := NewPolicyStore()
	store.Store(policy)
	h := NewHandler(Config{
		Catalog:  NewPolicyCatalog(store, nil),
		Resolver: stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		// A short plane ceiling, so the 2s upstream really does time out.
		Isolation: NewIsolation(DefaultPlaneConcurrency, func() fallbackpolicy.Effective {
			e := fallbackpolicy.Resolve(nil, fallbackpolicy.LocalOverrides{})
			e.UpstreamAttemptTimeout.Value = int64(200 * time.Millisecond / time.Millisecond)
			return e
		}, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		PolicyStore:     store,
		Logger:          slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	env := callRetryTool(t, mux)
	// 🔴 Assert the scenario actually produced a TIMEOUT. Without this the test
	// is satisfied by a call that simply succeeded, which is how it was vacuous.
	if env.Error == nil {
		t.Fatal("the scenario did not time out — this fence would prove nothing")
	}
	// 🔴 And it must be a TIMEOUT specifically. "some error happened" is
	// satisfied by a connection refused, which IS retryable — so without this
	// the fence could pass while testing the wrong failure entirely.
	var data errorData
	if err := json.Unmarshal(env.Error.Data, &data); err != nil {
		t.Fatalf("error data: %v", err)
	}
	if data.AiKeyCode != string(mcpwire.ErrUpstreamTimeout) {
		t.Fatalf("the scenario produced %s, not a timeout — this fence is testing the wrong "+
			"failure mode", data.AiKeyCode)
	}

	up.mu.Lock()
	got := len(up.methods)
	up.mu.Unlock()
	if got > 1 {
		t.Fatalf("🔴 a non-idempotent tool was attempted %d times after a TIMEOUT. A timeout "+
			"means the tool may be running right now; a retry runs it again.", got)
	}

	// 🔴 The attempt count above is necessary but NOT sufficient, and the drill
	// proved it: classifying a timeout as never-accepted leaves the count at 1
	// anyway, because the retry re-uses a context that has already expired and
	// so never reaches the wire. The count is protected by an accident of
	// context plumbing, not by the rule.
	//
	// What the RULE controls is the decision, and the decision is observable in
	// the log: a timeout must be recorded as a SUPPRESSED retry, never as an
	// attempted one. If the per-attempt context is ever made independent of the
	// request context, the count above starts mattering too — and this
	// assertion is what keeps the classification honest until then.
	if !strings.Contains(logs.String(), "proxy.mcp.retry_suppressed_non_idempotent") {
		t.Fatalf("a timed-out non-idempotent call must be recorded as a SUPPRESSED retry — "+
			"the tool may be running right now:\n%s", logs)
	}
	if strings.Contains(logs.String(), "proxy.mcp.retry_attempted") {
		t.Fatalf("a timeout was classified as retryable:\n%s", logs)
	}
}

// TestFence_6F1_AnUnreachableBackendIsRetried — the safe case.
//
// 🔴 Without this the fence above is satisfiable by never retrying anything,
// which would also be wrong: a connection that was refused means the tool
// PROVABLY did not run, and giving up on it costs the user a working call.
func TestFence_6F1_AnUnreachableBackendIsRetried(t *testing.T) {
	// A port with nothing on it: connection refused, before any request byte.
	srv := httptest.NewServer(http.NewServeMux())
	addr := srv.URL
	srv.Close() // now nothing is listening

	mux, logs := retryStack(t, false, addr)
	env := callRetryTool(t, mux)
	if env.Error == nil {
		t.Fatal("an unreachable backend must still surface an error after the retry")
	}
	if !strings.Contains(logs.String(), "proxy.mcp.retry_attempted") {
		t.Fatalf("a request that never reached the backend MUST be retried — the tool "+
			"provably did not run, so declining to retry just loses the call:\n%s", logs)
	}
	if strings.Contains(logs.String(), "retry_suppressed") {
		t.Fatalf("a never-accepted request must not be reported as a suppressed retry:\n%s", logs)
	}
}

// TestFence_6F1_AnIdempotentToolIsRetriedOnA5xx — the second safe case.
func TestFence_6F1_AnIdempotentToolIsRetriedOnA5xx(t *testing.T) {
	up := &countingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()
	mux, _ := retryStack(t, true, srv.URL)

	_ = callRetryTool(t, mux)
	if n := up.count(); n != 2 {
		t.Fatalf("a tool a human declared idempotent should be retried exactly once "+
			"(got %d attempts)", n)
	}
}

// TestFence_6F1_RetryHappensAtMostOnce — one retry, never a loop.
func TestFence_6F1_RetryHappensAtMostOnce(t *testing.T) {
	up := &countingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()
	mux, _ := retryStack(t, true, srv.URL)

	_ = callRetryTool(t, mux)
	if n := up.count(); n > 2 {
		t.Fatalf("🔴 %d attempts: the retry became a loop. A failing backend would then "+
			"receive amplified traffic from every client at once.", n)
	}
}

// TestNotAcceptedIsAWhitelistNotABlacklist guards the classification itself.
//
// 🔴 A blacklist ("everything except a timeout may be retried") would classify
// every NEW error shape as retryable by default, and the cost of being wrong is
// a duplicated write. This asserts the default answer is false.
func TestNotAcceptedIsAWhitelistNotABlacklist(t *testing.T) {
	for _, err := range []error{
		nil,
		errString("some brand new failure mode nobody has classified"),
		errString("unexpected EOF"),
		errString("http2: server sent GOAWAY"),
	} {
		if neverAccepted(err) {
			t.Fatalf("an unclassified error must NOT be treated as never-accepted: %v", err)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

var _ = json.Marshal
