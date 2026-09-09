package mcp

// selfcheck_origin_test.go — fences 8.F5 / 8.F6 for the self-check call
// (task 8.7 · R23 · ruling A-1).
//
// # What a self-check call is, and what it must NOT be
//
// R23 asked for a "try it" surface: the operator invokes one tool with their
// own seat and their own key, through this gateway, so it walks the identical
// chain a real Agent walks. Ruling A-1 moved the surface from the console to
// the CLI (`aikey mcp try`) because a console-initiated call cannot reach an
// employee laptop in Production — but the gateway-side contract is unchanged
// and is what these fences hold:
//
//	R23: 🚫 不许为「这只是测试」跳过任何一步 ——
//	     「测试是特殊的」是所有后门的开场白。
//
// The gateway learns a call is a self-check from ONE header, and it may use
// that knowledge for ONE thing: the value written to `mcp_call_event.origin`.
// The moment anything else reads it, the header becomes a capability — a
// string any client can send to get treatment no ordinary client gets.
//
// 🔴 Before these tests existed there were NO assertions on `originFor` at all,
// and no producer of the header either: `console_test` was a value the code
// could return and nothing had ever caused it to. Task 8.7 supplies the
// producer; these supply the proof.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

const selfCheckCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
	`"params":{"name":"query_readonly","arguments":{"sql":"select 1"}}}`

// TestFence_8F5_TheSelfCheckHeaderOnlyLabelsTheRecord is fence 8.F5.
//
// 🔴 The assertion is a COMPARISON, not a property of one request. "The header
// changes nothing" cannot be checked by looking at one call — it is a statement
// about two, and the only honest way to make it is to run both and diff
// everything except the one field that is allowed to differ.
//
// 能红: make any authorisation, freeze, schema or rate decision read
// ConsoleTestHeader — for example, admit a frozen tool "because it is only a
// test". Both halves of this test go red: the labelled call would then behave
// differently from the unlabelled one.
func TestFence_8F5_TheSelfCheckHeaderOnlyLabelsTheRecord(t *testing.T) {
	srv := okUpstream(t)

	run := func(t *testing.T, hdr map[string]string) (mcpwire.Envelope, mcpwire.CallRecord) {
		t.Helper()
		mux, sink, _ := recordingPlane(t, srv.URL, publishedTool(), true)
		_, env := rpc(t, mux, "/mcp/"+testToolset, testToken, selfCheckCall, hdr)
		recs := sink.all()
		if len(recs) != 1 {
			t.Fatalf("got %d records, want exactly 1", len(recs))
		}
		return env, recs[0]
	}

	plainEnv, plainRec := run(t, nil)
	labelledEnv, labelledRec := run(t, map[string]string{ConsoleTestHeader: "1"})

	// 1. The ORIGIN is the one thing that may differ.
	if plainRec.Origin != mcpwire.OriginAgent {
		t.Errorf("an ordinary call recorded origin %q, want %q", plainRec.Origin, mcpwire.OriginAgent)
	}
	if labelledRec.Origin != mcpwire.OriginConsoleTest {
		t.Fatalf("a self-check recorded origin %q, want %q — the label did not land",
			labelledRec.Origin, mcpwire.OriginConsoleTest)
	}

	// 2. The ANSWER must be identical. A self-check that is served differently
	//    is not a check of anything the operator's Agent will experience.
	if (plainEnv.Error == nil) != (labelledEnv.Error == nil) {
		t.Fatalf("the header changed whether the call was refused: plain=%+v labelled=%+v",
			plainEnv.Error, labelledEnv.Error)
	}
	if string(plainEnv.Result) != string(labelledEnv.Result) {
		t.Errorf("the header changed the RESULT:\n plain    = %s\n labelled = %s",
			plainEnv.Result, labelledEnv.Result)
	}

	// 3. Every other recorded field must be identical. 🔴 Compared by
	//    marshalling both records with origin blanked, rather than by listing
	//    the fields to check: a field added later is covered automatically,
	//    which is exactly how a list of fields stops being a fence.
	plainRec.Origin, labelledRec.Origin = "", ""
	plainRec.CallID, labelledRec.CallID = "", ""
	plainRec.CreatedAtMs, labelledRec.CreatedAtMs = 0, 0
	plainRec.DurationMs, labelledRec.DurationMs = 0, 0
	a, _ := json.Marshal(plainRec)
	b, _ := json.Marshal(labelledRec)
	if string(a) != string(b) {
		t.Errorf("the header changed a recorded field other than origin:\n plain    = %s\n labelled = %s", a, b)
	}
}

// TestFence_8F6_ASelfCheckGetsNoPermissionAnOrdinaryCallLacks is fence 8.F6.
//
// 🔴 R23's one-line test: anything the try surface can do, the operator could
// already do with their own Agent. So the interesting case is the tool the
// operator is NOT granted — the case where a backdoor would pay off, and
// therefore the case a backdoor would be built for.
//
// The refusal must also be RECORDED. An operator who believes a refused
// self-check left no trace will not go looking for it, and an administrator
// investigating "who tried to call delete_branch" must see this attempt.
//
// 能红: admit an ungranted tool when ConsoleTestHeader is present; or skip the
// record for self-checks.
func TestFence_8F6_ASelfCheckGetsNoPermissionAnOrdinaryCallLacks(t *testing.T) {
	srv := okUpstream(t)
	mux, sink, _ := recordingPlane(t, srv.URL, publishedTool(), false /* not granted */)

	_, env := rpc(t, mux, "/mcp/"+testToolset, testToken, selfCheckCall,
		map[string]string{ConsoleTestHeader: "1"})

	if env.Error == nil {
		t.Fatalf("a self-check was SERVED a tool this seat is not granted — " +
			"the try surface is a permission bypass")
	}
	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("the refused self-check left %d records, want 1 — a refusal must be recorded", len(recs))
	}
	if recs[0].Origin != mcpwire.OriginConsoleTest {
		t.Errorf("the refused self-check recorded origin %q, want %q",
			recs[0].Origin, mcpwire.OriginConsoleTest)
	}
	if recs[0].Status == mcpwire.CallStatusOK {
		t.Errorf("a refused call recorded status %q", recs[0].Status)
	}
}

// TestNothingButTheRecorderReadsTheSelfCheckHeader is the structural half of
// 8.F5.
//
// 🔴 The behavioural test above can only catch a branch on a path it happens to
// walk. This one catches the branch wherever it is written, by asserting the
// header constant has exactly one reader in the whole package.
//
// 能红: read ConsoleTestHeader anywhere except originFor.
func TestNothingButTheRecorderReadsTheSelfCheckHeader(t *testing.T) {
	var offenders []string
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot read the package directory: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("cannot read %s: %v", name, err)
		}
		scanned++
		fn := ""
		for _, raw := range strings.Split(string(src), "\n") {
			line := strings.TrimSpace(raw)
			if strings.HasPrefix(raw, "func ") {
				fn = raw
			}
			if !strings.Contains(line, "ConsoleTestHeader") {
				continue
			}
			// The declaration itself, and the doc comment above it.
			if strings.HasPrefix(line, "const ConsoleTestHeader") || strings.HasPrefix(line, "//") {
				continue
			}
			if strings.Contains(fn, "func originFor(") {
				continue
			}
			offenders = append(offenders, name+": "+line)
		}
	}
	// 🔴 The scan must have READ something. A fence whose corpus is empty
	// passes forever; this is the third time in this phase that a check
	// enumerated nothing and reported success.
	if scanned == 0 {
		t.Fatal("scanned no source files — this fence was inspecting nothing")
	}
	if len(offenders) != 0 {
		t.Errorf("ConsoleTestHeader is read outside originFor — a label has become a capability (R23):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
