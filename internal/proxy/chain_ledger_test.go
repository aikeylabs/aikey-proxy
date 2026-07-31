package proxy

// chain_ledger_test.go — the WHOLE ledger shape for one switched request
// (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 3.9/3.10/3.11/3.12,
// F-12, invariants I4 / I25). This is task 6.1's "L2 content" row asserted at
// unit level.
//
// # 🔴 Why a combined assertion, when three separate ones already exist
//
// chain_attribution_test.go checks the three properties INDEPENDENTLY: cost
// follows the serving hop, every hop shares a trace, at most one row carries
// tokens. Each is correct and each can pass while the ledger as a whole is
// wrong, because the invoice-facing statement is a RELATIONSHIP between them:
//
//	one client request  =  ONE charge  +  N upstream-call audit rows,
//	                       all N sharing one trace_id.
//
// A build that recorded only the serving hop passes "at most one row carries
// tokens" and passes "all rows share a trace" — with N = 1. The audit evidence
// that we called the primary at all would be gone, and nothing above would say
// so. So the count, the charge and the trace have to be asserted together,
// against the same row set, in one place.
//
// 🔴 Every failure here is silent by construction: the client gets 200, so no
// user reports it, and the discrepancy surfaces only when an invoice is
// disputed — at which point the ledger is the only record and it is wrong.
//
// This test also PRINTS the ledger under `-v`, because "PASS" is weak evidence
// for a billing claim: the numbers are what a reviewer actually needs to see.

import (
	"net/http"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

func TestAttribution_LedgerShapeForOneSwitchedRequest(t *testing.T) {
	store := &capturingEventStore{}
	p, cap := twoHopChainWithStore(t, store)

	// The primary fails with a retryable status; the fallback answers, and its
	// body carries the only real token counts in the request.
	cap.statusByHost["primary.invalid"] = 503
	cap.bodyByHost["fallback.invalid"] =
		`{"id":"msg_1","model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":11,"output_tokens":22}}`

	req, w := chainReq()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the chain did not recover: status=%d body=%s", w.Code, w.Body.String())
	}

	evs := store.recorded()
	printLedger(t, evs)

	// ── 1. Upstream calls: N rows, one per attempt ─────────────────────────
	//
	// 🚫 Recording only the hop that succeeded would delete the evidence that we
	// ever called the primary — the audit trail would show a clean single call to
	// a vendor that was, in fact, the second choice.
	if len(evs) != 2 {
		t.Fatalf("ledger has %d rows, want 2 (one per upstream attempt).\n"+
			"「上游调用数」= row count. Dropping the failed attempt erases the audit "+
			"evidence that we called that upstream at all", len(evs))
	}

	// ── 2. Charge: exactly ONE row carries tokens ──────────────────────────
	//
	// 「请求数」= trace_id deduplicated = 1. The money comes from the single row
	// that actually produced a completion.
	var charged []events.UsageEvent
	for _, ev := range evs {
		if ev.InputTokens > 0 || ev.OutputTokens > 0 {
			charged = append(charged, ev)
		}
	}
	if len(charged) != 1 {
		t.Fatalf("%d of %d rows carry tokens, want exactly 1.\n"+
			"More than one bills the same conversation once per upstream tried; zero "+
			"means the completion that DID happen is unbilled", len(charged), len(evs))
	}
	if charged[0].InputTokens != 11 || charged[0].OutputTokens != 22 {
		t.Errorf("charged row has %d in / %d out, want 11/22 — the counts must come "+
			"from the body the SERVING upstream actually returned",
			charged[0].InputTokens, charged[0].OutputTokens)
	}

	// ── 3. The charge lands on the hop that served ─────────────────────────
	if charged[0].ServedProvider != "mock" || charged[0].ServedBindingID != "b-fallback" {
		t.Errorf("charge attributed to provider=%q binding=%q, want mock/b-fallback.\n"+
			"Billing the primary for a call the fallback served is wrong in the "+
			"direction nobody checks, because the request succeeded",
			charged[0].ServedProvider, charged[0].ServedBindingID)
	}

	// ── 4. One request: a single trace across every row ────────────────────
	trace := evs[0].TraceID
	if trace == "" {
		t.Fatal("no trace_id — 「请求数」 is defined as trace_id deduplicated, so an " +
			"empty trace makes the request count uncountable rather than merely wrong")
	}
	for i, ev := range evs {
		if ev.TraceID != trace {
			t.Fatalf("row %d trace_id=%q, row 0 trace_id=%q. Two traces for one client "+
				"request inflates 「请求数」 with nothing to signal it", i, ev.TraceID, trace)
		}
	}

	// ── 5. The attempt numbers describe the chain that actually ran ────────
	//
	// 🔴 On a single hop, `attempt` read from the loop's outer route equals the
	// correct value — so only a real switch distinguishes right from wrong here.
	if evs[0].FallbackAttempt != 1 {
		t.Errorf("row 0 fallback_attempt=%d, want 1", evs[0].FallbackAttempt)
	}
	if evs[1].FallbackAttempt != 2 {
		t.Errorf("row 1 fallback_attempt=%d, want 2", evs[1].FallbackAttempt)
	}
	if evs[1].FallbackReason == "" {
		t.Error("row 1 has no fallback_reason — the row a switch created must say what " +
			"caused the switch, or the ledger records that something moved without why")
	}

	// ── 6. The two dashboard figures, computed the way the contract defines ──
	seen := map[string]bool{}
	for _, ev := range evs {
		seen[ev.TraceID] = true
	}
	requests, upstreamCalls := len(seen), len(evs)
	t.Logf("请求数 (trace_id deduplicated) = %d", requests)
	t.Logf("上游调用数 (row count)          = %d", upstreamCalls)
	if requests != 1 || upstreamCalls != 2 {
		t.Errorf("dashboard figures = %d requests / %d upstream calls, want 1 / 2",
			requests, upstreamCalls)
	}
	// 🔴 The two are DIFFERENT numbers on purpose (P7.3 makes telling the customer
	// this before their first invoice a hard requirement). Equality here would mean
	// a failed attempt went unrecorded.
	if requests == upstreamCalls {
		t.Error("请求数 equals 上游调用数 after a switch — a failed attempt is missing " +
			"from the ledger")
	}
}

// printLedger dumps the recorded rows so the evidence is the NUMBERS, not a
// green PASS line. Shown by `go test -v`.
func printLedger(t *testing.T, evs []events.UsageEvent) {
	t.Helper()
	t.Logf("┌─────┬──────────────┬────────────────┬─────────┬──────────────────────┬────────┬────────┐")
	t.Logf("│ row │ served_prov  │ served_binding │ attempt │ fallback_reason      │ tok_in │ tok_out│")
	t.Logf("├─────┼──────────────┼────────────────┼─────────┼──────────────────────┼────────┼────────┤")
	for i, ev := range evs {
		reason := ev.FallbackReason
		if reason == "" {
			reason = "—"
		}
		t.Logf("│ %3d │ %-12s │ %-14s │ %7d │ %-20s │ %6d │ %6d │",
			i, ev.ServedProvider, ev.ServedBindingID, ev.FallbackAttempt, reason,
			ev.InputTokens, ev.OutputTokens)
	}
	t.Logf("└─────┴──────────────┴────────────────┴─────────┴──────────────────────┴────────┴────────┘")
	for i, ev := range evs {
		t.Logf("row %d trace_id = %s", i, ev.TraceID)
	}
}
