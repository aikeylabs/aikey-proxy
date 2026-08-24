package events

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every collector-bound request must carry the credential decision.
//
// 🔴 WHY THIS FENCE EXISTS (2026-08-24). The usage pipeline had TWO ways to
// build a collector request and only ONE of them authenticated. Uploads
// resolved a credential (content_reporter.go). The diagnostics helpers —
// httpGetJSON / httpPostJSON, used by the reconcile read, the stream-switch
// declaration and confirm-lost — sent no Authorization at all.
//
// Measured live on a Windows box:
//
//	usage.reporter.auto_reconcile_failed
//	  GET  .../v1/diagnostics/completeness: status 401
//	usage.reporter.stream_switch_failed  lane=… floor_seq=1823
//	  POST .../v1/diagnostics/stream-switch: status 401
//
// The stream-switch one is the expensive half: its own log line says "the
// terminated span will look like a gap until it lands". A lane that can never
// declare its switch leaves its tail permanently unaccounted, so that
// recipient's usage never reconciles — which is what a user saw as an empty
// usage page while their traffic was flowing fine.
//
// 🔴 A SOURCE fence on purpose. A behavior test would have to stand up a
// collector per helper and would still miss the NEXT helper someone adds. The
// defect is that a request got built without going through the one function
// that decides auth, and only the source shows that.
func TestCollectorRequestBuildersGoThroughAuthorize(t *testing.T) {
	// Files that build requests to the collector / diagnostics surface.
	for _, name := range []string{"reconcile.go", "content_reporter.go"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("cannot read %s: %v", name, err)
		}
		text := string(src)

		// Every http.NewRequestWithContext in these files must be followed by an
		// authorize(...) call before the request is sent.
		builders := regexp.MustCompile(`http\.NewRequestWithContext\(`).FindAllStringIndex(text, -1)
		if len(builders) == 0 {
			t.Fatalf("%s no longer builds any request — if the code moved, move this "+
				"fence with it; leaving it unable to match would make it pass silently", name)
		}
		for _, at := range builders {
			// Look at the window between this builder and the next one (or EOF).
			end := len(text)
			for _, other := range builders {
				if other[0] > at[0] && other[0] < end {
					end = other[0]
				}
			}
			window := text[at[0]:end]
			if !strings.Contains(window, "authorize(") {
				line := 1 + strings.Count(text[:at[0]], "\n")
				t.Errorf("%s:%d builds a collector request that never reaches authorize()\n\n"+
					"An unauthenticated diagnostics call answers 401 forever. That is how the\n"+
					"reconcile read and the stream-switch declaration both shipped dead — the\n"+
					"pipeline looked healthy while a whole lane's usage went unaccounted.",
					name, line)
			}
		}
	}
}

// authorize itself must not silently skip a credential that fails.
func TestAuthorizeSurfacesABrokenCredential(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x/y", http.NoBody)
	if err := authorize(context.Background(), req, brokenCred{}); err == nil {
		t.Fatal("a credential that cannot mint a bearer must be an error, not a silent unauthenticated request — " +
			"silence here is exactly the 401-forever failure this package already shipped once")
	}
	// A nil credential is legitimate: network-trust deployments send no header.
	if err := authorize(context.Background(), req, nil); err != nil {
		t.Fatalf("nil credential must be silence, not an error: %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("nil credential must not set an Authorization header")
	}
}

type brokenCred struct{}

func (brokenCred) Bearer(context.Context) (string, error) {
	return "", context.DeadlineExceeded
}
