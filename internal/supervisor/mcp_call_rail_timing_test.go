package supervisor

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// The drain cadence has TWO readers in different modules, and only one of them
// can see this file.
//
//	this package     ships call records on a ticker
//	aikey-data       decides, at drawer-render time, whether a tool call with no
//	                 matching record is late or absent (task 13.10b)
//
// The second answer is only correct when it is expressed in terms of the first
// cadence, so the value was moved to pkg/mcpwire on 2026-09-02 and this package
// aliases it. These two tests are what keeps the alias an alias.
//
// 🔴 The failure they prevent is silent and points the wrong way: a proxy whose
// interval drifted PAST the reader's backfill window delivers its records after
// the reader has already settled them, so healthy tool calls render as
// `bypassed` — a security finding with an alert colour and an escalation rule
// (tasks 13.13a / 13.12a) — for a delivery-timing reason. Nothing errors,
// nothing logs; the audit page simply starts accusing people.

// TestCallRailUsesTheSharedDrainInterval is the value half.
func TestCallRailUsesTheSharedDrainInterval(t *testing.T) {
	if MCPCallDrainInterval != mcpwire.CallRailDrainInterval {
		t.Fatalf("the rail drains every %v but the shared contract says %v; "+
			"the conversation audit's backfill window is derived from the shared value, "+
			"so this rail is now delivering on a cadence its reader does not know about",
			MCPCallDrainInterval, mcpwire.CallRailDrainInterval)
	}

	// 🔴 And the relationship that makes the pair usable at all. Asserted here
	// as well as in pkg/mcpwire because THIS is the side that gets retuned: an
	// operator lengthening the drain to relieve a busy control plane will edit
	// the rail, not the shared file.
	if MCPCallDrainInterval >= mcpwire.ConversationLinkBackfillWindow() {
		t.Fatalf("drain interval %v >= backfill window %v: records would routinely "+
			"arrive after the reader has already settled them",
			MCPCallDrainInterval, mcpwire.ConversationLinkBackfillWindow())
	}
}

// TestCallRailDoesNotRedeclareTheDrainInterval is the source half.
//
// 🔴 Why a source scan and not just the value check above: a re-declared literal
// with the SAME number passes the value check, and stays passing right up until
// somebody retunes pkg/mcpwire — at which point the failure lands on whoever
// touched the shared file rather than on whoever forked it. This catches the
// fork at the moment it is written, which is the only moment the fix is obvious.
func TestCallRailDoesNotRedeclareTheDrainInterval(t *testing.T) {
	src, err := os.ReadFile("mcp_call_rail.go")
	if err != nil {
		t.Fatalf("read rail source: %v", err)
	}
	// A duration literal anywhere in the const's declaration line. `30 *
	// time.Second`, `time.Minute / 2`, a bare `30000000000` — all of them mean
	// the value has been forked back into this file.
	// `const X = …` and a bare `X = …` inside a const block both count.
	decl := regexp.MustCompile(`(?m)^\s*(?:const\s+)?MCPCallDrainInterval\s*=\s*(.+)$`)
	m := decl.FindSubmatch(src)
	if m == nil {
		t.Fatal("MCPCallDrainInterval is no longer declared in mcp_call_rail.go; " +
			"if it moved, move this fence with it")
	}
	rhs := strings.TrimSpace(string(m[1]))
	if !strings.HasPrefix(rhs, "mcpwire.CallRailDrainInterval") {
		t.Fatalf("MCPCallDrainInterval = %q — it must alias mcpwire.CallRailDrainInterval "+
			"and nothing else. Two copies of a delivery cadence drift silently, and the "+
			"drift renders healthy tool calls as `bypassed` in the conversation audit. "+
			"See pkg/mcpwire/linktiming.go.", rhs)
	}
}
