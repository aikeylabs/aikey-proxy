package proxy

// chain_fences_test.go — the structural fences for the upstream-fallback chain
// (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 2.2 / 2.10 / 2.20 /
// 2.11, invariants I1 / I3 / I18 / I40).
//
// These guard properties that a behavioral test cannot reach: a rule about what
// the SOURCE may contain, or a failure that only appears in the middle of a
// stream.

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── 2.2 / I3: after the first byte, nothing may switch ─────────────────────
//
// A stream that has begun is committed. Switching then splices two upstreams'
// output into one body, and the client cannot detect it — it just receives a
// conversation that changed voice mid-sentence.
type brokenStream struct {
	calls int
	host  string
}

func (b *brokenStream) RoundTrip(req *http.Request) (*http.Response, error) {
	b.calls++
	b.host = req.URL.Host
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
		Body:    io.NopCloser(&failingReader{prefix: "event: message_start\ndata: {}\n\n"}),
		Request: req,
	}, nil
}

// failingReader yields some bytes and then fails — an upstream that dies halfway.
type failingReader struct {
	prefix string
	sent   bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if !f.sent {
		f.sent = true
		n := copy(p, f.prefix)
		return n, nil
	}
	return 0, errors.New("upstream connection reset mid-stream")
}

func TestChain_NoSwitchAfterTheFirstByte(t *testing.T) {
	p, _ := twoHopChain(t)
	tr := &brokenStream{}
	p.SetTransport(tr)

	req, w := chainReq()
	p.Handle(w, req)

	if tr.calls != 1 {
		t.Fatalf("made %d upstream attempts after a stream had already started, want 1.\n"+
			"Once one byte has reached the client the response is committed: switching "+
			"splices two different upstreams into a single body, and the client has no way "+
			"to detect that it happened", tr.calls)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status=%d, want the already-committed 200 to stand", w.Code)
	}
}

// scanChainSources runs fn over every non-test .go file in this package plus the
// supervisor, skipping comment lines — the rules below are about CODE, and the
// files that implement them necessarily discuss the forbidden thing in prose.
func scanChainSources(t *testing.T, fn func(path, code string)) {
	t.Helper()
	roots := []string{".", "../supervisor"}
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || filepath.Ext(path) != ".go" ||
				strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			var code strings.Builder
			for _, line := range strings.Split(string(b), "\n") {
				if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
					continue
				}
				code.WriteString(line)
				code.WriteString("\n")
			}
			fn(path, code.String())
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

// ── 2.20 / I18: switch-back must never consult `session_id` ────────────────
//
// The sessionid package's own documentation states the value is client-controlled
// and trivially forged, and that routing, authentication and billing never read
// it. If it drove switch-back, any client could force us to re-hit a known-dead
// upstream simply by minting a new id per request.
func TestChain_RoutingAndCooldownDoNotImportSessionID(t *testing.T) {
	guarded := map[string]bool{
		"chain_serve.go":             true,
		"chain_activity.go":          true,
		"binding_cooldown.go":        true,
		"candidate_chain.go":         true,
		"fallback_policy_cache.go":   true,
		"fallback_policy_request.go": true,
	}
	var hits []string
	scanChainSources(t, func(path, code string) {
		if !guarded[filepath.Base(path)] {
			return
		}
		if strings.Contains(code, "sessionid") || strings.Contains(code, "SessionID") ||
			strings.Contains(code, "session_id") {
			hits = append(hits, path)
		}
	})
	if len(hits) > 0 {
		t.Errorf("switch-back / cooldown code references a session id: %v\n"+
			"It is client-controlled and trivially forged. A client that mints a new id per "+
			"request could force us to re-hit a known-dead upstream forever, and every one of "+
			"those requests would look legitimate", hits)
	}
}

// ── 2.10 / I1: the real upstream key never becomes observable ──────────────
//
// The chain touches one more credential per hop, so the number of places a key
// could leak grows with the feature. This pins the rule at the source level
// because a leak into a log line is not something a behavioral test would notice.
func TestChain_NeverLogsARealKey(t *testing.T) {
	var hits []string
	scanChainSources(t, func(path, code string) {
		if filepath.Base(path) != "chain_serve.go" && filepath.Base(path) != "candidate_chain.go" {
			return
		}
		for _, line := range strings.Split(code, "\n") {
			if !strings.Contains(line, "logger.") && !strings.Contains(line, "slog.") {
				continue
			}
			// Any log call mentioning a plaintext-key field name is a leak.
			for _, needle := range []string{"PlaintextKey", "realKey", "\"key\"", "api_key"} {
				if strings.Contains(line, needle) {
					hits = append(hits, path+": "+strings.TrimSpace(line))
				}
			}
		}
	})
	if len(hits) > 0 {
		t.Errorf("a chain log line carries key material: %v", hits)
	}
}

// ── 2.11 / 1b.11: no edition branch anywhere in the chain ──────────────────
//
// Personal is unaffected because it has no route groups — a FACT about its data,
// reached through the same code every other edition runs. Writing
// `if edition == personal` would make that a special case instead, and special
// cases are where behavior quietly diverges between editions.
func TestChain_HasNoEditionBranch(t *testing.T) {
	var hits []string
	scanChainSources(t, func(path, code string) {
		base := filepath.Base(path)
		if base != "chain_serve.go" && base != "candidate_chain.go" &&
			base != "binding_cooldown.go" && base != "chain_activity.go" {
			return
		}
		for _, needle := range []string{"edition ==", "Edition ==", "IsPersonal", "personalEdition"} {
			if strings.Contains(code, needle) {
				hits = append(hits, path+": "+needle)
			}
		}
	})
	if len(hits) > 0 {
		t.Errorf("the chain branches on edition: %v\n"+
			"Personal is unaffected because it has no route groups — a property of its DATA, "+
			"reached through the same code path. An edition branch turns that into a special "+
			"case, and special cases are where editions quietly diverge", hits)
	}
}

// ── I40: `sort_basis` is provenance, never a runtime switch ────────────────
//
// The console records WHAT a saved order was computed from (manual, by cost, by
// health). If the runtime ever read it back to re-sort, the order an
// administrator sees would stop being the order that runs — which is precisely
// the failure the "what you see is what executes" rule exists to prevent, and
// F-8 excluded runtime selection for exactly this reason.
func TestChain_RuntimeNeverReadsSortBasis(t *testing.T) {
	var hits []string
	scanChainSources(t, func(path, code string) {
		if strings.Contains(code, "sort_basis") || strings.Contains(code, "SortBasis") {
			hits = append(hits, path)
		}
	})
	if len(hits) > 0 {
		t.Errorf("runtime code reads sort_basis: %v\n"+
			"It is a record of how an order was PRODUCED, not an instruction. Reading it at "+
			"request time would let the served order differ from the order shown in the "+
			"console, with nothing to reveal the difference", hits)
	}
}

// ── 2.9 / I2: a switched response goes through the SAME compliance path ────
//
// The tempting shortcut is a "fast path for retries" that skips outbound
// filtering. That would turn failover into a compliance bypass: the exact moment
// the system is under stress is the moment scanning gets skipped, and nothing in
// the response says so.
//
// The structural guarantee is that the chain has no forwarding code of its own —
// it calls `serveRouteWithObserver`, the one entry every non-chain request also
// uses, so DLP and the confidence check cannot be routed around without deleting
// them for everybody.
func TestChain_ForwardsOnlyThroughTheSharedServePath(t *testing.T) {
	b, err := os.ReadFile("chain_serve.go")
	if err != nil {
		t.Fatalf("read chain_serve.go: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(b), "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	text := code.String()

	if !strings.Contains(text, "p.serveRouteWithObserver(") {
		t.Fatal("the chain no longer forwards through serveRouteWithObserver")
	}
	// Any OTHER forwarding primitive appearing here means a second path exists,
	// and a second path is where the filtering quietly stops happening.
	for _, forbidden := range []string{"httputil.NewSingleHostReverseProxy", "http.Client{", ".RoundTrip(", "p.serveRoute("} {
		if strings.Contains(text, forbidden) {
			t.Errorf("chain_serve.go contains its own forwarding primitive %q.\n"+
				"A second forwarding path is how outbound filtering stops applying to "+
				"switched responses — at exactly the moment the system is under stress, "+
				"and with nothing in the response to say so", forbidden)
		}
	}
}
