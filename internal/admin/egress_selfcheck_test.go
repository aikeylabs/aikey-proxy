package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The endpoint is a thin shell: it parses ?dial=, calls EgressSelfCheckFn, and
// JSON-encodes {dialed, paths}. Presence (default) must NOT request a dial;
// ?dial=1 must. A nil Fn returns an empty list, not a 500.
func TestEgressSelfCheck_PresenceVsDial(t *testing.T) {
	var gotDial *bool
	h := &Handler{
		EgressSelfCheckFn: func(_ context.Context, dial bool) []EgressCheckResult {
			gotDial = &dial
			if !dial {
				return []EgressCheckResult{{Label: "a@x", Dialed: false}}
			}
			return []EgressCheckResult{{Label: "a@x", Dialed: true, OK: true, ExitIP: "1.2.3.4", LatencyMs: 42}}
		},
	}

	call := func(target string) egressSelfCheckBody {
		gotDial = nil
		w := httptest.NewRecorder()
		h.EgressSelfCheck(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", target, w.Code)
		}
		var body egressSelfCheckBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: bad json: %v", target, err)
		}
		return body
	}

	// Presence (default): dial=false passed through, rows not dialed.
	b := call("/admin/egress/selfcheck")
	if gotDial == nil || *gotDial {
		t.Fatalf("presence call must pass dial=false, got %v", gotDial)
	}
	if b.Dialed || len(b.Paths) != 1 || b.Paths[0].Dialed {
		t.Fatalf("presence body wrong: %+v", b)
	}

	// dial=1: dial=true passed, exit IP surfaced.
	b = call("/admin/egress/selfcheck?dial=1")
	if gotDial == nil || !*gotDial {
		t.Fatalf("dial=1 must pass dial=true, got %v", gotDial)
	}
	if !b.Dialed || len(b.Paths) != 1 || !b.Paths[0].OK || b.Paths[0].ExitIP != "1.2.3.4" {
		t.Fatalf("dial body wrong: %+v", b)
	}
}

func TestEgressSelfCheck_NilFnEmptyList(t *testing.T) {
	h := &Handler{} // EgressSelfCheckFn nil
	w := httptest.NewRecorder()
	h.EgressSelfCheck(w, httptest.NewRequest(http.MethodGet, "/admin/egress/selfcheck", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body egressSelfCheckBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if body.Paths == nil || len(body.Paths) != 0 {
		t.Fatalf("nil Fn must yield empty (non-nil) paths, got %+v", body.Paths)
	}
}
