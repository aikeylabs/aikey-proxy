package supervisor

// mcp_guard_activity_test.go — fences for the seat half of "is the delegation
// gate being consulted?" (P15 · 15.16). Each test names the mutation it catches.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// Mutation: drop the query parameter from fetchMCPCredentials' URL, or send it
// only when the gate has been seen.
//
// Rationale: 🔴 this is a cross-repo wire contract, and it fails SILENTLY — the
// control plane simply counts every seat as "cannot tell" and the console shows
// an un-governed fleet. This repo has shipped that exact shape twice already
// (the mcp.json object-vs-array drift). The assertion is on what the SERVER
// received, not on a string we build here.
//
// 🚫 Reporting only when active is the specific mutation this forbids: the
// interesting population is the seats with no gate, and a node that reports only
// good news makes them indistinguishable from nodes that are switched off.
func TestCredentialRailCarriesTheGuardActivity(t *testing.T) {
	for _, want := range []mcpwire.GuardActivity{mcpwire.GuardActive, mcpwire.GuardIdle} {
		var got string
		var seen bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, seen = r.URL.Query().Get(mcpwire.GuardActivityParam), true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"credentials":[]}`))
		}))
		if _, err := fetchMCPCredentials(context.Background(), srv.URL, "tok", want); err != nil {
			t.Fatalf("%s: fetch: %v", want, err)
		}
		srv.Close()
		if !seen {
			t.Fatalf("%s: the control plane was never called", want)
		}
		if got != string(want) {
			t.Fatalf("the credential rail must report the gate's state; control plane saw %q, want %q", got, want)
		}
	}
}

// Mutation: make MCPGuardActivity return GuardActive unconditionally, or have
// NoteMCPGuardSeen do nothing.
//
// Rationale: a gateway that always claims "active" turns the whole number into
// a constant, and a constant that says "everything is fine" is worse than no
// number — it answers the administrator's question wrongly and confidently.
func TestGuardActivityStartsIdleAndLatchesOnce(t *testing.T) {
	s := &Supervisor{}
	if got := s.MCPGuardActivity(); got != mcpwire.GuardIdle {
		t.Fatalf("a gateway the hook has never reached must report idle, got %q", got)
	}
	s.NoteMCPGuardSeen()
	if got := s.MCPGuardActivity(); got != mcpwire.GuardActive {
		t.Fatalf("after the hook reached this gateway it must report active, got %q", got)
	}
}
