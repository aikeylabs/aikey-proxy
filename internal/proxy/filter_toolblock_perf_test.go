// filter_toolblock_perf_test.go — what opening agent tool blocks (方案②,
// 2026-08-10) actually costs on the request hot path.
//
// The detector's own S1 latency gate (ai-compliance-detector `make perf-gate`)
// measures ONE Detect call and is unaffected by this change: nothing about the
// engine changed, only which pieces reach it. The cost that moved is on THIS
// side — how many Detect calls a realistic agent turn produces, and how many of
// them survive the content-hash cache in steady state.
//
// This file measures that, and pins the two properties the budget depends on:
//
//  1. per-block bounded fan-out — a tool_use block contributes exactly ONE
//     Detect call however many arguments it carries (that is why
//     extractToolUseBlock joins instead of emitting per-string pieces);
//  2. steady-state cache absorption — an agent's history is byte-identical
//     across turns, so a long conversation must not re-scan it every turn.
//
// It reports numbers with `-v` and asserts only the SHAPE (bounded, absorbed),
// not a wall-clock threshold: this package has no perf-isolated environment and
// a timing assertion here would be a flake generator, not a gate.
package proxy

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// agentTurnBody builds a Claude Code-shaped conversation: one opening human
// message, then `tools` Read/Bash round-trips (assistant tool_use + user
// tool_result carrying a file body), then the human's new question.
func agentTurnBody(tools, fileBodyBytes int) string {
	var b strings.Builder
	b.WriteString(`{"model":"m","messages":[`)
	b.WriteString(`{"role":"user","content":[{"type":"text","text":"read the configs and summarize"}]}`)
	body := strings.Repeat("KEY=value\n", fileBodyBytes/10)
	for i := 0; i < tools; i++ {
		fmt.Fprintf(&b, `,{"role":"assistant","content":[{"type":"text","text":"reading %d"},`+
			`{"type":"tool_use","id":"t%d","name":"Read","input":{"file_path":"/app/c%d.env",`+
			`"offset":0,"limit":2000}}]}`, i, i, i)
		fmt.Fprintf(&b, `,{"role":"user","content":[{"type":"tool_result","tool_use_id":"t%d",`+
			`"content":[{"type":"text","text":%q}]}]}`, i, body)
	}
	b.WriteString(`,{"role":"user","content":[{"type":"text","text":"now summarize"}]}`)
	b.WriteString(`]}`)
	return b.String()
}

// TestToolBlockPerf_DetectCallsPerAgentTurn reports the piece-count increase and
// pins the per-block bound.
func TestToolBlockPerf_DetectCallsPerAgentTurn(t *testing.T) {
	t.Logf("Detect calls + scanned bytes for one Claude Code-shaped turn (4KB file body per tool call).")
	t.Logf("The scanned-bytes column is the honest cost of this decision: on a real agent turn the tool")
	t.Logf("payload IS the request, so scanned volume goes from a few hundred bytes to tens of KB.")
	t.Logf("%-11s | %-8s | %-9s | %-12s | %-11s | %s",
		"tool calls", "pieces", "per call", "scanned B", "of which tool", "body B")
	for _, tools := range []int{0, 1, 5, 20} {
		body := agentTurnBody(tools, 4096)
		pieces, _, ok := extractUserContent([]byte(body), nil)
		if !ok {
			t.Fatalf("extractUserContent failed for tools=%d", tools)
		}
		// 2 prose pieces bracket the conversation; each tool round-trip adds
		// assistant prose + tool_use + tool_result = 3.
		perTool := 0.0
		if tools > 0 {
			perTool = float64(len(pieces)-2) / float64(tools)
		}
		scanned, toolBytes := 0, 0
		for _, p := range pieces {
			scanned += len(p.text)
			if p.ceiling == ceilingAudit {
				toolBytes += len(p.text)
			}
		}
		pct := 0.0
		if scanned > 0 {
			pct = 100 * float64(toolBytes) / float64(scanned)
		}
		t.Logf("%-11d | %-8d | %-9.1f | %-12d | %-10.0f%% | %d",
			tools, len(pieces), perTool, scanned, pct, len(body))
		if tools > 0 && perTool > 3.0 {
			t.Fatalf("a tool round-trip contributed %.1f Detect calls, expected ≤3 "+
				"(assistant prose + tool_use + tool_result). More than that means the tool_use.input "+
				"join was split into per-string pieces, which puts an unbounded IPC fan-out on the "+
				"request hot path — see extractToolUseBlock.", perTool)
		}
	}
}

// TestToolBlockPerf_ToolUseInputIsOneDetectCall is the tight version of the
// bound: however many arguments a tool carries, the block yields ONE piece.
func TestToolBlockPerf_ToolUseInputIsOneDetectCall(t *testing.T) {
	for _, args := range []int{1, 10, 200} {
		var kv []string
		for i := 0; i < args; i++ {
			kv = append(kv, fmt.Sprintf(`"arg%03d":"value %d"`, i, i))
		}
		body := `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1",` +
			`"name":"MultiEdit","input":{` + strings.Join(kv, ",") + `}}]}]}`
		pieces, _, ok := extractUserContent([]byte(body), nil)
		if !ok {
			t.Fatalf("extract failed for args=%d", args)
		}
		if len(pieces) != 1 {
			t.Fatalf("a tool_use with %d arguments yielded %d Detect calls, want exactly 1. "+
				"Per-string pieces would mean %d IPC round-trips for ONE block.", args, len(pieces), args)
		}
	}
	t.Log("✅ tool_use.input → exactly 1 Detect call regardless of argument count")
}

// TestToolBlockPerf_SteadyStateIsCacheAbsorbed: an agent resends its whole
// history every turn byte-identically, so from turn 2 on the tool pieces must
// come from the content-hash cache. Without that, opening tool blocks would
// multiply the per-turn detector load by the conversation length.
func TestToolBlockPerf_SteadyStateIsCacheAbsorbed(t *testing.T) {
	measure := func(turns int, cacheOn bool) (calls, pieces int) {
		hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
		p := &Proxy{filterHook: hook}
		if cacheOn {
			p.SetFilterCacheEnabled(true, 200)
		}
		for turn := 1; turn <= turns; turn++ {
			r := newReq(agentTurnBody(turn, 4096))
			r.Header.Set("X-Claude-Code-Session-Id", "perf-tool-sess")
			ps, _, _ := extractUserContent([]byte(agentTurnBody(turn, 4096)), nil)
			pieces += len(ps)
			p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "",
				resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger())
		}
		return hook.called, pieces
	}
	t.Logf("Growing agent conversation (turn N carries N tool round-trips, full history resent):")
	t.Logf("%-6s | %-12s | %-14s | %-14s | %s", "turns", "pieces total", "no cache", "cache on", "saved")
	for _, turns := range []int{5, 10, 20} {
		noCache, pieces := measure(turns, false)
		cached, _ := measure(turns, true)
		saved := 100 * float64(noCache-cached) / float64(noCache)
		t.Logf("%-6d | %-12d | %-14d | %-14d | %.0f%%", turns, pieces, noCache, cached, saved)
		if turns == 20 && saved < 80 {
			t.Fatalf("🔴 only %.0f%% of detector calls were absorbed by the content-hash cache at %d "+
				"turns. Agent history is byte-identical across turns, so the tool pieces MUST be cache "+
				"hits in steady state — otherwise opening tool blocks multiplies the per-turn detector "+
				"load by the conversation length and the 15ms budget cannot hold.", saved, turns)
		}
	}
}
