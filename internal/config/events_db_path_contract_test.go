package config

// events_db_path_contract_test.go — the cross-language contract for where the
// proxy's events database lives (task 5.7).
//
// 🔴 The CLI half is `events_db_path_default_matches_the_proxy` in
// aikey-cli/src/commands_mcp.rs. Two languages, no shared schema: the only
// thing holding them in step is a test on each side pinning the SAME literal —
// the arrangement ~/.aikey/mcp.json already needed in task 5.6.
//
// 🔴 Why both halves exist, when one would "obviously" be enough: the failure
// mode is SILENT. `aikey mcp calls` opens the path it believes in; if that is
// not the path the daemon writes to, the file simply is not there and the CLI
// prints "no local call record yet" — a sentence that is indistinguishable from
// the truth. Meanwhile the daemon goes on recording every tool call into a
// database nobody reads. Neither side errors, neither side logs, and the only
// symptom is an audit trail that is always empty.

import "testing"

// TestEventsDBPathDefaultIsWhereTheCLILooks.
//
// 能红: change DefaultEventsDBPath (or DefaultWALRetentionDays) without changing
// the CLI constant in the same commit.
func TestEventsDBPathDefaultIsWhereTheCLILooks(t *testing.T) {
	const cliPath = "~/.aikey/data/events.db"
	if DefaultEventsDBPath != cliPath {
		t.Fatalf("the events database moved.\n  proxy: %s\n  cli:   %s\n"+
			"🔴 `aikey mcp calls` reads this file directly — it is the ONLY way to see MCP tool "+
			"calls on Personal, which has no control plane and no console. When these two "+
			"disagree the CLI reports an empty history for a database being written to right "+
			"now, and nothing about that output looks wrong. If the move is intentional, change "+
			"DEFAULT_EVENTS_DB_PATH in aikey-cli/src/commands_proxy.rs in the SAME commit.",
			DefaultEventsDBPath, cliPath)
	}

	// 🔴 The retention default travels too, because the CLI PRINTS it: "MCP tool
	// calls on this machine (last N days)". A stale N tells the user their local
	// record reaches further back than it does — and on Personal that record is
	// the audit, so the number is load-bearing rather than decorative.
	const cliRetentionDays = 30
	if DefaultWALRetentionDays != cliRetentionDays {
		t.Fatalf("the local retention window changed.\n  proxy: %d\n  cli:   %d\n"+
			"Update DEFAULT_WAL_RETENTION_DAYS in aikey-cli/src/commands_proxy.rs in the same "+
			"commit, or `aikey mcp calls` will tell users their history covers a period it "+
			"does not.", DefaultWALRetentionDays, cliRetentionDays)
	}
}
