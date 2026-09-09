package mcp

// actor_test.go — fences for executor attribution (P15 · K3 · 15.F4).
//
// # What is actually being protected
//
// `actor_id` says WHICH AGENT made a tool call. On today's dominant client it
// is `unknown-actor` essentially 100% of the time, because Claude Code's MCP
// requests carry no agent identifier at all (PRD §0.7). That number is going to
// look like a bug to somebody, and the cheap fix is obvious and wrong:
//
//	"attribution is 0% — can't we just match the hook event from the same seat
//	 within a few seconds? or fall back to the conversation id? or the app?"
//
// 🔴 No. A plausible-but-wrong attribution in an audit trail is worse than an
// admitted blank, because a blank gets investigated and a wrong one gets acted
// on. I33 forbids it; this file is what makes the ban cost something to break.
//
// The same reasoning already governs `conversation_session_id` (R17) — and the
// reason THIS needs its own fence is that the actor is more tempting: every
// sub-agent in a task shares the seat AND the conversation id, so a heuristic
// built on either would produce a confident, uniform, entirely wrong answer.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// discard keeps the fences from printing the expected WARN/DEBUG lines.
func actorTestLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// actorTable is the shape of actor-fingerprint.yaml, parsed HERE rather than
// through an accessor on sessionid.Matcher.
//
// 🔴 A fence must not force new production API into existence. `go:embed` reads
// this same file at build time, so reading it from disk cannot disagree with
// what the binary carries.
type actorTable struct {
	Rules []struct {
		Sources []struct {
			Type string `yaml:"type"`
		} `yaml:"sources"`
	} `yaml:"rules"`
	CommonFallback []struct {
		Type string `yaml:"type"`
	} `yaml:"common_fallback"`
}

func loadActorTable(t *testing.T) actorTable {
	t.Helper()
	path := filepath.Join("..", "proxy", "sessionid", "actor-fingerprint.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var tbl actorTable
	if err := yaml.Unmarshal(b, &tbl); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return tbl
}

// TestActor_NoHeuristicResolution — 15.F4 / I33.
//
// Two independent claims, because the heuristic could arrive in two shapes and
// a fence that only saw one would be a fence that mostly does not exist.
func TestActor_NoHeuristicResolution(t *testing.T) {
	t.Run("no other identifier on the request becomes the actor", func(t *testing.T) {
		// 🔴 The cheapest heuristic, and therefore the likeliest: reuse an
		// identifier that IS present. This request carries every one of them —
		// seat, our session, the client's conversation id, a recognisable
		// User-Agent — and names no actor. The only correct answer is the
		// verdict `unknown-actor`.
		//
		// 能红: make actorIDFor fall back to the conversation id, the session
		// id, or the app slug.
		r := httptest.NewRequest(http.MethodPost, "/mcp/demo", nil)
		r.Header.Set(mcpwire.HeaderSessionID, "gateway-minted-session")
		r.Header.Set("X-Claude-Code-Session-Id", "conversation-abc")
		r.Header.Set("X-Aikey-Session-Id", "conversation-abc")
		r.Header.Set("User-Agent", "claude-cli/1.2.3")

		h := &Handler{logger: actorTestLogger()}
		got := h.actorIDFor(r)

		if got != mcpwire.UnknownActor {
			t.Fatalf("actorIDFor = %q, want %q.\n"+
				"Some other identifier on the request was promoted to the actor. Every sub-agent "+
				"in a task shares the seat AND the conversation id, so an attribution built on "+
				"either is uniform, confident and wrong — which is worse than an admitted blank "+
				"(I33).", got, mcpwire.UnknownActor)
		}
	})

	t.Run("the extraction table cannot express a correlation", func(t *testing.T) {
		// 🔴 The structural half. A time-window or same-seat rule cannot be
		// written in the actor table at all: the only source types the parser
		// accepts read something the client SENT ON THIS REQUEST. This asserts
		// the table stays inside that box — every source a header, and no
		// common_fallback, because a fallback here could only ever be a proxy
		// for something that is not the actor.
		//
		// 能红: add a `common_fallback` entry to actor-fingerprint.yaml, or a
		// body/derived source type.
		tbl := loadActorTable(t)
		if n := len(tbl.CommonFallback); n != 0 {
			t.Fatalf("actor-fingerprint.yaml declares %d common_fallback source(s); it must declare none. "+
				"Nothing in a generic request names the agent, so any fallback is a proxy for "+
				"something else (the conversation, the seat, the app) wearing a header's name.", n)
		}
		var headers, other int
		for _, r := range tbl.Rules {
			for _, src := range r.Sources {
				if src.Type == "header" {
					headers++
					continue
				}
				other++
			}
		}
		if headers == 0 {
			t.Fatal("the actor table declares no header sources at all — the fence is reading the " +
				"wrong table, or the table was emptied, which would make this assertion vacuous")
		}
		if other != 0 {
			t.Fatalf("actor-fingerprint.yaml declares %d non-header source(s). The actor may only "+
				"be read from something the client explicitly sent on THIS request (I33).", other)
		}
	})

	t.Run("the extractor touches nothing on the receiver but the logger", func(t *testing.T) {
		// 🔴 The third shape, and the one the two above cannot see: a heuristic
		// that consults STORED state. It does NOT need a new parameter — the
		// receiver already carries `h.sessions` and `h.policyStore`, so
		// `h.sessions.RecentActorForSeat(...)` would compile today and read like
		// a helpful improvement.
		//
		// 🔴 An earlier draft asserted the SIGNATURE instead (exactly one
		// parameter). It was VACUOUS twice over: any signature change breaks this
		// test file's own call site, so the drill went red on a build failure
		// rather than on the assertion — the compiler doing the fence's job,
		// which this repo has been caught by before (R43's mirror) — and it
		// guarded the wrong thing anyway, since the tempting heuristic needs no
		// signature change at all.
		//
		// So: walk the function body and collect every `h.<x>` it touches. The
		// only legal one is the logger.
		//
		// 能红: return h.appSlugFor(r) instead of the verdict, or read
		// h.sessions / h.policyStore. All of those compile.
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "callrecord.go", nil, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse callrecord.go: %v", err)
		}
		const allowed = "logger"
		var found bool
		var touched []string
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "actorIDFor" || fn.Recv == nil {
				continue
			}
			found = true
			recv := fn.Recv.List[0].Names[0].Name
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || id.Name != recv || sel.Sel.Name == allowed {
					return true
				}
				touched = append(touched, sel.Sel.Name)
				return true
			})
		}
		if !found {
			t.Fatal("actorIDFor not found in callrecord.go — the fence is inspecting the wrong " +
				"file, which would make this assertion vacuous")
		}
		if len(touched) != 0 {
			t.Fatalf("actorIDFor reads %v off the handler. It may touch only the logger: everything "+
				"else on the receiver (the session store, the policy store, another extractor) is "+
				"the raw material of a correlation heuristic, and an attribution inferred from "+
				"stored state is confidently wrong rather than admittedly blank (I33).", touched)
		}
	})
}

// TestActorUnresolvedIsCountedNotSwallowed — the other half of 15.20.
//
// 🔴 The unresolved case must be OBSERVABLE. Without the event, "no client
// supplies an actor" and "our extractor is broken" produce the same picture:
// a column full of `unknown-actor`. The count is the coverage metric for a
// limitation we publish (PRD §0.7), 🚫 not an error rate.
//
// 能红: delete the log line from actorIDFor, or change its event name.
func TestActorUnresolvedIsCountedNotSwallowed(t *testing.T) {
	src := readSourceFile(t, "callrecord.go")
	if !strings.Contains(src, "mcpwire.EventActorUnresolved") {
		t.Fatal("callrecord.go no longer emits mcpwire.EventActorUnresolved. A gap nobody counts " +
			"is a gap nobody can tell from a defect: `unknown-actor` everywhere looks the same " +
			"whether no client supplies an actor or our extractor stopped working.")
	}
	// 🚫 The event name is taken from the central enumeration, never typed as a
	// literal at the call site (logging conventions).
	if strings.Contains(src, `"proxy.mcp.actor_unresolved"`) {
		t.Fatal("callrecord.go spells the actor_unresolved event name as a literal; use " +
			"mcpwire.EventActorUnresolved so the catalogue stays the single source of truth.")
	}
}
