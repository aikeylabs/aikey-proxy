package admin

// Tests for Personal edition's review endpoints (阶段8 P14 task 14.3).
//
// 🔴 The point of each: the failures here are all "answers something plausible
// instead of the truth" — a node that follows a control plane answering with an
// empty list (which reads as "nothing to review"), or a missing `write_op`
// decoding to false (which is the dangerous direction).

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/mcp"
)

func TestMCPLocalManifest_OnANodeWithAControlPlaneSaysWhereReviewingHappens(t *testing.T) {
	h := &Handler{} // no Fn wired: this is a node that follows a control plane
	rec := httptest.NewRecorder()
	h.MCPLocalManifest(rec, httptest.NewRequest(http.MethodGet, "/admin/mcp/local-manifest", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
	// 🔴 An empty 200 would read as "you have nothing to review", which is a
	// different and wrong statement.
	if !strings.Contains(rec.Body.String(), "console") {
		t.Fatalf("the answer must say where reviewing DOES happen: %s", rec.Body)
	}
}

func TestMCPLocalManifest_ReturnsTheBackendsAndSurfacesAnUnreadableRecord(t *testing.T) {
	h := &Handler{MCPLocalReviewFn: func() ([]mcp.ReviewBackend, string) {
		return []mcp.ReviewBackend{{BackendID: "localpg"}}, "unexpected end of JSON input"
	}}
	rec := httptest.NewRecorder()
	h.MCPLocalManifest(rec, httptest.NewRequest(http.MethodGet, "/admin/mcp/local-manifest", nil))

	var doc struct {
		Backends            []mcp.ReviewBackend `json:"backends"`
		ApprovalsUnreadable string              `json:"approvals_unreadable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Backends) != 1 || doc.Backends[0].BackendID != "localpg" {
		t.Fatalf("backends: %+v", doc.Backends)
	}
	if doc.ApprovalsUnreadable == "" {
		t.Fatal("🔴 an unreadable approval record must reach the user: it means every tool " +
			"is being served at whatever its upstream says today")
	}
}

func TestMCPLocalManifestAccept_NothingWaitingIsNotAServerFault(t *testing.T) {
	h := &Handler{MCPLocalAcceptFn: func(string, []string) (mcp.AcceptResult, error) {
		return mcp.AcceptResult{}, errors.New("mcp: nothing is waiting for review on that backend")
	}}
	rec := httptest.NewRecorder()
	h.MCPLocalManifestAccept(rec, httptest.NewRequest(http.MethodPost,
		"/admin/mcp/local-manifest/accept", strings.NewReader(`{"backend":"localpg"}`)))

	// 🔴 404, not 500. "There is nothing waiting for you" is a normal state, and
	// reporting it as a server fault sends the user to read proxy logs.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404: %s", rec.Code, rec.Body)
	}
}

func TestMCPLocalManifestAccept_RefusesAnEmptyBackend(t *testing.T) {
	h := &Handler{MCPLocalAcceptFn: func(string, []string) (mcp.AcceptResult, error) {
		return mcp.AcceptResult{Repinned: 1}, nil
	}}
	rec := httptest.NewRecorder()
	h.MCPLocalManifestAccept(rec, httptest.NewRequest(http.MethodPost,
		"/admin/mcp/local-manifest/accept", strings.NewReader(`{"backend":"   "}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

// 🔴 The one that matters most on this endpoint. A plain `bool` would decode a
// missing field to FALSE, which marks a write tool read-only — precisely the
// mistake the default-true rule exists to prevent, made silently by an omitted
// key.
func TestMCPLocalToolWriteOp_RefusesAMissingFlagRatherThanReadingItAsReadOnly(t *testing.T) {
	called := false
	h := &Handler{MCPLocalWriteOpFn: func(string, string, bool) error { called = true; return nil }}
	rec := httptest.NewRecorder()
	h.MCPLocalToolWriteOp(rec, httptest.NewRequest(http.MethodPost,
		"/admin/mcp/local-manifest/write-op", strings.NewReader(`{"backend":"b","tool":"t"}`)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", rec.Code, rec.Body)
	}
	if called {
		t.Fatal("🔴 an omitted write_op reached the classifier as `false` — a write tool " +
			"would have been silently marked read-only")
	}
	if !strings.Contains(rec.Body.String(), "dangerous") {
		t.Fatalf("the refusal must say WHY, or the caller just adds `false`: %s", rec.Body)
	}
}

func TestMCPLocalToolWriteOp_PassesTheFlagThrough(t *testing.T) {
	var got *bool
	h := &Handler{MCPLocalWriteOpFn: func(_, _ string, w bool) error { got = &w; return nil }}
	for _, want := range []bool{true, false} {
		rec := httptest.NewRecorder()
		body := `{"backend":"b","tool":"t","write_op":` + map[bool]string{true: "true", false: "false"}[want] + `}`
		h.MCPLocalToolWriteOp(rec, httptest.NewRequest(http.MethodPost,
			"/admin/mcp/local-manifest/write-op", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d: %s", rec.Code, rec.Body)
		}
		if got == nil || *got != want {
			t.Fatalf("write_op %v did not reach the classifier", want)
		}
	}
}

// / The deselection reaches the publisher verbatim.
//
// 🔴 14.3c: adoption presents everything SELECTED and the human deselects what
// looks wrong. If the exclusion list were dropped in transit, the command would
// report "3 rejected" and publish all three — a review that reports a decision
// it did not make.
func TestMCPLocalManifestAccept_PassesTheDeselectionThrough(t *testing.T) {
	var got []string
	h := &Handler{MCPLocalAcceptFn: func(_ string, exclude []string) (mcp.AcceptResult, error) {
		got = exclude
		return mcp.AcceptResult{FirstReview: true, Published: 2, Rejected: len(exclude)}, nil
	}}
	rec := httptest.NewRecorder()
	h.MCPLocalManifestAccept(rec, httptest.NewRequest(http.MethodPost,
		"/admin/mcp/local-manifest/accept",
		strings.NewReader(`{"backend":"b","exclude":["delete_repo","read_file"]}`)))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body)
	}
	if len(got) != 2 || got[0] != "delete_repo" {
		t.Fatalf("the deselection did not reach the publisher: %+v", got)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["first_review"] != true {
		t.Fatalf("the caller cannot tell a first review from a re-pin: %s", rec.Body)
	}
}

// 🔴 A node with a control plane must say where its inventory comes from, not
// answer with an empty document that reads as "you have nothing".
func TestMCPLocalRefresh_OnANodeWithAControlPlaneSaysSo(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Handler{}).MCPLocalRefresh(rec, httptest.NewRequest(http.MethodPost,
		"/admin/mcp/local-manifest/refresh", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "control plane") {
		t.Fatalf("%s", rec.Body)
	}
}

// The refresh answers with what it FOUND, in the same round trip — that is what
// lets `aikey mcp adopt` show the human their new tools instead of telling them
// to come back when a five-minute timer next fires.
func TestMCPLocalRefresh_AnswersWithTheReviewDocument(t *testing.T) {
	called := false
	h := &Handler{
		MCPLocalRefreshFn: func() error { called = true; return nil },
		MCPLocalReviewFn: func() ([]mcp.ReviewBackend, string) {
			return []mcp.ReviewBackend{{BackendID: "newly-adopted", AwaitingFirstReview: true}}, ""
		},
	}
	rec := httptest.NewRecorder()
	h.MCPLocalRefresh(rec, httptest.NewRequest(http.MethodPost,
		"/admin/mcp/local-manifest/refresh", nil))
	if !called {
		t.Fatal("the refresh did not actually re-read anything")
	}
	var doc struct {
		Backends []mcp.ReviewBackend `json:"backends"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Backends) != 1 || !doc.Backends[0].AwaitingFirstReview {
		t.Fatalf("the response must carry the gate state: %s", rec.Body)
	}
}
