package admin

// mcp_delegation_test.go — the proxy half of the delegation-boundary contract
// (P15 · 15.7), and the Go side of the cross-language fence with `aikey`.
//
// 🔴 This repo has already been bitten TWICE by a CLI↔proxy shape drifting
// silently (the mcp.json field set, then the health document). Both times the
// symptom was the same: one side kept working, the other quietly read nothing,
// and every test on each side stayed green. So the contract gets a fence on BOTH
// sides — see `the_gateway_contract_is_the_one_the_proxy_serves` in
// aikey-cli/src/mcp_guard/tests.rs.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// The strings the CLI hard-codes. Changing either side alone must go red.
const (
	cliRoute            = "/admin/mcp/delegation"
	cliRequestAgentType = "agent_type"
	cliRequestDepth     = "depth"
)

func TestDelegationWireMatchesTheCLIContract(t *testing.T) {
	// Request: the fields the CLI sends must be the fields we decode.
	var body struct {
		AgentType string `json:"agent_type"`
		Depth     int    `json:"depth"`
	}
	raw := `{"` + cliRequestAgentType + `":"Explore","` + cliRequestDepth + `":1}`
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("the CLI's request body does not decode here: %v", err)
	}
	if body.AgentType != "Explore" || body.Depth != 1 {
		t.Fatalf("decoded %+v; the CLI's field names and ours have drifted", body)
	}

	// Response: every field the CLI reads must exist with that exact JSON name.
	out, err := json.Marshal(mcpwire.Decision{
		Verdict: mcpwire.VerdictNarrow, Tier: "ro", Reason: "because", Stale: true,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"verdict", "tier", "reason", "stale"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("Decision no longer carries %q; the CLI reads that field by name "+
				"and would silently fall back to its zero value", k)
		}
	}

	// The verdict STRINGS are part of the contract too: the CLI compares against
	// "deny" to decide whether to refuse. A rename here would turn every refusal
	// into an allow, and nothing on either side would fail.
	if string(mcpwire.VerdictDeny) != "deny" || string(mcpwire.VerdictNarrow) != "narrow" ||
		string(mcpwire.VerdictAllow) != "allow" {
		t.Fatalf("a verdict string changed; the CLI compares against the literal \"deny\"")
	}
}

// 🔴 The endpoint must NEVER refuse when it cannot decide. Every branch here is
// a state a developer can be in mid-task through no fault of their own, and D-29
// ratified fail-open explicitly rather than by default.
//
// Mutation: return 503 / an error status from any of these paths.
func TestDelegationEndpointNeverRefusesWhenItCannotDecide(t *testing.T) {
	cases := []struct {
		name string
		h    *Handler
		body string
	}{
		{"no decision function wired", &Handler{}, `{"agent_type":"Explore","depth":1}`},
		{"body does not parse", &Handler{}, `{not json`},
		{"empty body", &Handler{}, ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, cliRoute, strings.NewReader(tc.body))
			tc.h.MCPDelegation(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; the gate must answer, not refuse — a developer "+
					"whose proxy cannot decide must keep working (D-29)", rec.Code)
			}
			var d mcpwire.Decision
			if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
				t.Fatalf("response does not decode as a Decision: %v", err)
			}
			if d.Verdict != mcpwire.VerdictAllow {
				t.Fatalf("verdict = %q; want allow", d.Verdict)
			}
			if !d.Stale {
				t.Fatal("a fail-open answer must be FLAGGED stale, or it is " +
					"indistinguishable from a gate that actually decided")
			}
		})
	}
}

// The wired function's answer must reach the caller unchanged — including a
// refusal's sentence, which is the only place the fix is stated.
func TestDelegationEndpointPassesTheDecisionThrough(t *testing.T) {
	h := &Handler{MCPDelegationFn: func(agentType string, depth int) (mcpwire.Decision, string, string) {
		if agentType != "general-purpose" || depth != 2 {
			t.Fatalf("handler received (%q, %d); the request fields were not forwarded", agentType, depth)
		}
		return mcpwire.Decision{
			Verdict: mcpwire.VerdictDeny,
			Tier:    "read-only",
			Code:    mcpwire.DelegationDenied,
			Reason:  "AiKey refused this delegation under tier \"read-only\". Next: …",
		}, "org-test", "seat-test"
	}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, cliRoute,
		strings.NewReader(`{"agent_type":"  general-purpose  ","depth":2}`))
	h.MCPDelegation(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var d mcpwire.Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.Verdict != mcpwire.VerdictDeny {
		t.Fatalf("verdict = %q", d.Verdict)
	}
	if !strings.Contains(d.Reason, "AiKey") {
		t.Fatalf("the refusal reason lost its attribution: %q. The harness refuses "+
			"spawns too, and a message that does not say who spoke leaves the user "+
			"unable to tell which fix applies (D-24)", d.Reason)
	}
}

// ---------------------------------------------------------------------------
// 15.12 / 15.13 — the decision is RECORDED, and `narrow` is its own event
// ---------------------------------------------------------------------------

// TestEveryDelegationDecisionIsRecorded — until 2026-09-03 the gate decided,
// answered, and left no trace: five of the six delegation events in the central
// catalogue had ZERO call sites.
//
// 🔴 Why that mattered more than it looks. A denial, a narrowing, a fail-open
// and a gate that was never installed all produced the same thing — nothing.
// And D-29 ratified failing open when the policy cannot be refreshed *on the
// condition that* the caller emits the WARN; without it, a gateway deciding from
// a month-old snapshot is indistinguishable from a healthy one, which is exactly
// how a control that is not controlling anything survives for months.
//
// 🔴 Why a BEHAVIOURAL test and not a grep. The three verdict events are emitted
// through the `EventForVerdict` table, so the constant names never appear at the
// call site — a coverage grep would report them as never-emitted forever, and
// "fix" it by inlining literals, which the logging conventions forbid. This runs
// the handler and reads what came out.
func TestEveryDelegationDecisionIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision mcpwire.Decision
		want     []string
	}{
		{
			"allow",
			mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Tier: "wide"},
			[]string{mcpwire.EventDelegationRequested, mcpwire.EventDelegationAllowed},
		},
		{
			// 🔴 Its OWN event (15.13). "Allowed, but with fewer toolsets than
			// the parent" is the single thing a tier configuration exists to
			// tell an administrator; folded into `allowed` it becomes a wall of
			// green while half the delegations are quietly downgraded.
			"narrow",
			mcpwire.Decision{Verdict: mcpwire.VerdictNarrow, Tier: "review-only"},
			[]string{mcpwire.EventDelegationRequested, mcpwire.EventDelegationNarrowed},
		},
		{
			"deny",
			mcpwire.Decision{Verdict: mcpwire.VerdictDeny, Tier: "review-only", Code: mcpwire.DelegationDenied},
			[]string{mcpwire.EventDelegationRequested, mcpwire.EventDelegationDenied},
		},
		{
			// 🔴 The D-29 bargain being paid. The stale WARN must fire even
			// though the spawn was ALLOWED — that is the whole point.
			"stale fail-open still warns",
			mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Stale: true},
			[]string{mcpwire.EventDelegationRequested, mcpwire.EventDelegationAllowed, mcpwire.EventPolicyStale},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			restore := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(restore)

			h := &Handler{MCPDelegationFn: func(string, int) (mcpwire.Decision, string, string) {
				return tc.decision, "org-test", "seat-test"
			}}
			rec := httptest.NewRecorder()
			h.MCPDelegation(rec, httptest.NewRequest(http.MethodPost, "/admin/mcp/delegation",
				strings.NewReader(`{"agent_type":"Explore","depth":1}`)))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (the gate never refuses to answer)", rec.Code)
			}
			out := buf.String()
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("the %s decision did not emit %q.\nA decision nobody records is a "+
						"decision nobody can audit — and a fail-open nobody records is "+
						"indistinguishable from a working gate.\ngot:\n%s", tc.name, want, out)
				}
			}
			// 🔴 The negative half: `narrow` must NOT also emit `allowed`, or the
			// separation it exists for is undone at the point of writing.
			if tc.decision.Verdict == mcpwire.VerdictNarrow &&
				strings.Contains(out, mcpwire.EventDelegationAllowed) {
				t.Error("a narrowed delegation also emitted the ALLOWED event; the two must stay " +
					"separate or an administrator sees green for a delegation that was downgraded")
			}
			if !tc.decision.Stale && strings.Contains(out, mcpwire.EventPolicyStale) {
				t.Error("a fresh decision emitted the stale WARN; that would train the reader to " +
					"ignore the one signal that pays for the fail-open")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 🔴 15.16 — the gate's own traffic is the evidence that it is installed
// ---------------------------------------------------------------------------

// Mutation: move the MCPGuardSeenFn call below the json.Decode block, so a
// request we cannot parse no longer counts.
//
// Rationale: reaching this handler AT ALL is the fact 15.16 reports — the hook
// is installed and the harness invokes it. Whether we could decode the body is a
// different question, already answered by the decision. Recording only on the
// happy path would make an encoding bug in the shell look, in the console, like
// an organisation that uninstalled its gate.
func TestGuardIsNotedEvenWhenTheRequestCannotBeParsed(t *testing.T) {
	noted := 0
	h := &Handler{
		MCPGuardSeenFn: func() { noted++ },
		MCPDelegationFn: func(string, int) (mcpwire.Decision, string, string) {
			return mcpwire.Decision{Verdict: mcpwire.VerdictAllow}, "org-test", "seat-test"
		},
	}
	rec := httptest.NewRecorder()
	h.MCPDelegation(rec, httptest.NewRequest(http.MethodPost, "/admin/mcp/delegation",
		strings.NewReader("{this is not json")))

	if rec.Code != http.StatusOK {
		t.Fatalf("a malformed request must still be answered (fail-open), got HTTP %d", rec.Code)
	}
	if noted != 1 {
		t.Fatalf("the hook reached this gateway, so the gate must be recorded as in use; noted=%d", noted)
	}
}

// Mutation: drop the MCPGuardSeenFn field and record inside MCPDelegationFn
// instead.
//
// Rationale: the decision function is ALSO the console-preview path (15.F14
// keeps them one evaluator on purpose). Recording there would let "what would
// happen if I wrote this tier" count as "the gate is in use on that seat" —
// the same separation 15.12 made when it put event emission in the caller
// rather than in DelegationGate.Decide.
func TestGuardIsNotRecordedByTheDecisionItself(t *testing.T) {
	noted := 0
	h := &Handler{MCPDelegationFn: func(string, int) (mcpwire.Decision, string, string) {
		noted++ // stands in for a preview call that must NOT count
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow}, "org-test", "seat-test"
	}}
	rec := httptest.NewRecorder()
	h.MCPDelegation(rec, httptest.NewRequest(http.MethodPost, "/admin/mcp/delegation",
		strings.NewReader(`{"agent_type":"Explore","depth":1}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d", rec.Code)
	}
	// With no MCPGuardSeenFn wired, nothing may be recorded anywhere: the
	// handler must not fall back to treating a decision as evidence of use.
	if h.MCPGuardSeenFn != nil {
		t.Fatal("the guard recorder must stay a separate, explicitly wired seam")
	}
}

// ---------------------------------------------------------------------------
// 🔴 15.A2 / 15.A3 — the record has to be able to answer the question
// ---------------------------------------------------------------------------

// captureDelegationLog runs one delegation request with the default logger
// swapped, and returns everything that was written.
func captureDelegationLog(t *testing.T, h *Handler, body string) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rec := httptest.NewRecorder()
	h.MCPDelegation(rec, httptest.NewRequest(http.MethodPost, "/admin/mcp/delegation",
		strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d", rec.Code)
	}
	return buf.String()
}

// Mutation: log `"toolsets", len(d.Toolsets)` instead of the joined IDs.
//
// Rationale: a COUNT answers "were any removed". It cannot answer "removed down
// to WHICH set", and that is the only question a narrowing record exists to
// settle — 15.A3 asserts the delivered set equals the tier's set verbatim, and
// a number cannot support that assertion. The count version shipped first and
// made the acceptance criterion unrunnable without anybody noticing.
func TestNarrowingRecordsWhichToolsetsNotHowMany(t *testing.T) {
	h := &Handler{MCPDelegationFn: func(string, int) (mcpwire.Decision, string, string) {
		return mcpwire.Decision{
			Verdict:  mcpwire.VerdictNarrow,
			Tier:     "read-only",
			Toolsets: []string{"ts-readonly", "ts-search"},
		}, "org-7", "seat-42"
	}}
	out := captureDelegationLog(t, h, `{"agent_type":"Explore","depth":1}`)

	for _, id := range []string{"ts-readonly", "ts-search"} {
		if !strings.Contains(out, id) {
			t.Fatalf("the narrowing record does not name toolset %q; a count cannot support "+
				"the 15.A3 assertion that the delivered set equals the tier's set verbatim.\n%s", id, out)
		}
	}
}

// Mutation: drop org_id/seat_id from either event, or re-resolve the identity
// inside the handler instead of taking the one the decision was made with.
//
// Rationale: 15.A3's three-hop assertion needs the seat the RULES WERE APPLIED
// FOR to appear in the record. Re-resolving would let a vault reload between
// the two calls put a different seat in the record than the one that was
// judged — and a record naming the wrong seat is worse than one naming none.
func TestDelegationRecordNamesTheIdentityItDecidedWith(t *testing.T) {
	h := &Handler{MCPDelegationFn: func(string, int) (mcpwire.Decision, string, string) {
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Tier: "t"}, "org-7", "seat-42"
	}}
	out := captureDelegationLog(t, h, `{"agent_type":"Explore","depth":1}`)

	if strings.Count(out, "seat-42") < 2 || strings.Count(out, "org-7") < 2 {
		t.Fatalf("both the requested and the decided event must name the identity the "+
			"decision was made with (15.A3 three-hop):\n%s", out)
	}
}

// Mutation: have MCPDelegation call an identity lookup of its own
// (`h.MCPDelegationIdentityFn()` / `sup.MCPDelegationIdentity()`) and log that
// instead of the value the decision returned.
//
// Rationale: 🔴 the "one resolution" property is STRUCTURAL — it cannot be seen
// from the output, because in a test both lookups agree. It only diverges on a
// vault reload between the two calls, in production, silently. So the fence
// reads the handler's own body and asserts the second lookup is not there.
//
// 🚫 Not a grep over the whole file: the identity seam is legitimate elsewhere.
// This narrows to MCPDelegation's body, which is the function that must not
// grow one.
func TestDelegationHandlerDoesNotReResolveTheIdentity(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("read handlers.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (h *Handler) MCPDelegation(")
	if start < 0 {
		t.Fatal("MCPDelegation not found; this fence is pointed at the wrong function")
	}
	end := strings.Index(body[start:], "\n// MCPLocalRefresh")
	if end < 0 {
		t.Fatal("could not bound MCPDelegation's body; retarget this fence")
	}
	fn := body[start : start+end]

	if strings.Contains(fn, "MCPDelegationIdentity") || strings.Contains(fn, "IdentityFn") {
		t.Fatal("MCPDelegation resolves the identity a second time. It must log the " +
			"(org, seat) the decision was MADE WITH — two resolutions can disagree across " +
			"a vault reload, and a record naming the wrong seat is worse than one naming none")
	}
	// The identity must reach the log from the decision call, and nowhere else.
	if !strings.Contains(fn, "d, orgID, seatID := h.MCPDelegationFn(") {
		t.Fatal("the identity no longer comes from the decision call; 15.A3's three-hop " +
			"assertion depends on those being one value from one resolution")
	}
}

// 🔴 A node that cannot identify itself must say so, 🚫 not fill in a
// placeholder. This is the fail-open an operator most needs to see: the gate is
// passing everything through.
func TestUnidentifiedNodeIsRecordedAsEmptyNotInvented(t *testing.T) {
	h := &Handler{MCPDelegationFn: func(string, int) (mcpwire.Decision, string, string) {
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Stale: true}, "", ""
	}}
	out := captureDelegationLog(t, h, `{"agent_type":"Explore","depth":1}`)
	for _, invented := range []string{"unknown-seat", "unknown-org", "n/a", "none"} {
		if strings.Contains(out, invented) {
			t.Fatalf("an unidentifiable node had %q invented for it; empty is the honest value\n%s",
				invented, out)
		}
	}
}
