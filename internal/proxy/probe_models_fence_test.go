package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/probepipe"
)

// Fences for the Probe pipeline's model-discovery path (probe_models.go).
//
// 🔴 WHAT MAKES THIS PATH WORTH FENCING: it is the ONE place in the probe
// pipeline that forwards upstream without running the body sanitizer or the
// model-inference gate, authenticated by a bearer that is a compile-time
// constant. Its safety rests entirely on being narrow — GET only, one exact
// suffix. Widening it turns the probe pipeline into a general pass-through
// for anything the credential can reach.
//
// So the fences pin the narrowness itself, not the happy path.

func probeCtxFor(path string) *probepipe.ProbeContext {
	return probepipe.ExtractProbePath(path)
}

// TestProbeModels_OnlyGET pins the method gate.
//
// A POST to /v1/models is not discovery. If the method check is ever dropped,
// a POST would take the discovery branch and its body would reach upstream
// having skipped apppipe.SanitizeRequestBody — the stage that strips aikey/*
// fields and rejects n>1.
func TestProbeModels_OnlyGET(t *testing.T) {
	ctx := probeCtxFor("/probe/some-alias/v1/models")
	if ctx == nil {
		t.Fatal("sanity: /probe/some-alias/v1/models should parse as a probe path")
	}
	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions,
	} {
		req := httptest.NewRequest(method, "/probe/some-alias/v1/models", nil)
		if isProbeModelsRequest(req, ctx) {
			t.Errorf("%s /v1/models took the discovery branch — it must not; "+
				"only GET is read-only, and this branch skips the body sanitizer", method)
		}
	}
	if !isProbeModelsRequest(httptest.NewRequest(http.MethodGet, "/probe/some-alias/v1/models", nil), ctx) {
		t.Error("GET /v1/models did NOT take the discovery branch — the path is dead")
	}
}

// TestProbeModels_OnlyTheExactSuffix pins the path gate.
//
// 🔴 Exact match, not a prefix. `strings.HasPrefix(path, "/models")` would
// admit /models/../chat/completions and /modelsomething; a prefix match on a
// forwarding path is how a narrow hole becomes a wide one.
func TestProbeModels_OnlyTheExactSuffix(t *testing.T) {
	notDiscovery := []string{
		"/probe/a/v1/chat/completions",
		"/probe/a/v1/messages",
		"/probe/a/v1/models/gpt-4o",
		"/probe/a/v1/modelsomething",
		"/probe/a/v1",
		"/probe/a/v1/",
	}
	for _, path := range notDiscovery {
		ctx := probeCtxFor(path)
		if ctx == nil {
			continue // not a probe path at all; the router already refused it
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if isProbeModelsRequest(req, ctx) {
			t.Errorf("GET %s took the discovery branch — only the exact /models suffix may", path)
		}
	}
}

// TestProbeModels_NilSafe — the gate is called on every probe request, so a
// nil dereference here would take out the whole pipeline, not just discovery.
func TestProbeModels_NilSafe(t *testing.T) {
	if isProbeModelsRequest(nil, probeCtxFor("/probe/a/v1/models")) {
		t.Error("nil request must not be treated as discovery")
	}
	if isProbeModelsRequest(httptest.NewRequest(http.MethodGet, "/probe/a/v1/models", nil), nil) {
		t.Error("nil probe context must not be treated as discovery")
	}
}

// TestProbeModels_BranchesBeforeTheSanitizer pins the ORDER of the branch
// inside handleProbePipeline, at source level.
//
// 🔴 The branch has to sit before stage 3 and stage 4, and the reason is not
// stylistic: SanitizeRequestBody rejects an empty body with
// MALFORMED_REQUEST_BODY (that is the exact error a discovery call got before
// this path existed), and stage 4 infers the upstream from `body.model` — the
// thing discovery exists to find out. Move the branch below either and the
// path stops working, with an error that names the body rather than the
// ordering.
//
// Source-level because the alternative — driving the whole pipeline — needs a
// fake vault and credential broker, and this repository already fences
// ordering invariants this way (see probe_pipeline_inbound_bearer_fence_test.go
// for the sibling rationale).
func TestProbeModels_BranchesBeforeTheSanitizer(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "pipelines.go", nil, 0)
	if err != nil {
		t.Fatalf("parse pipelines.go: %v", err)
	}

	var fn *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == "handleProbePipeline" {
			fn = d
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("handleProbePipeline not found in pipelines.go — did it move? " +
			"This fence must move with it.")
	}

	var discoveryLine, sanitizeLine, inferLine int
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch f := call.Fun.(type) {
		case *ast.Ident:
			name = f.Name
		case *ast.SelectorExpr:
			name = f.Sel.Name
		}
		line := fset.Position(call.Pos()).Line
		switch name {
		case "isProbeModelsRequest":
			if discoveryLine == 0 {
				discoveryLine = line
			}
		case "SanitizeRequestBody":
			if sanitizeLine == 0 {
				sanitizeLine = line
			}
		case "InferUpstreamFromModel":
			if inferLine == 0 {
				inferLine = line
			}
		}
		return true
	})

	if discoveryLine == 0 {
		t.Fatal("handleProbePipeline no longer calls isProbeModelsRequest — " +
			"GET /probe/<alias>/v1/models is dead, and trust-check is back to " +
			"guessing a model for relays")
	}
	if sanitizeLine == 0 {
		t.Fatal("sanity: SanitizeRequestBody call not found in handleProbePipeline")
	}
	if discoveryLine > sanitizeLine {
		t.Errorf("the discovery branch (line %d) runs AFTER SanitizeRequestBody (line %d); "+
			"an empty-bodied GET will be rejected as MALFORMED_REQUEST_BODY before it "+
			"ever reaches the branch", discoveryLine, sanitizeLine)
	}
	if inferLine != 0 && discoveryLine > inferLine {
		t.Errorf("the discovery branch (line %d) runs AFTER InferUpstreamFromModel (line %d); "+
			"discovery has no body.model to infer from — that is its whole purpose",
			discoveryLine, inferLine)
	}
}

// TestProbeModels_DoesNotGoThroughServeRoute pins the "no usage accounting"
// decision.
//
// A model listing consumes no tokens. Routing it through serveRoute would
// write a usage event for a request that spent nothing and attribute it to a
// probe route, putting rows in the ledger that no user action produced.
func TestProbeModels_DoesNotGoThroughServeRoute(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe_models.go", nil, 0)
	if err != nil {
		t.Fatalf("parse probe_models.go: %v", err)
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if strings.HasPrefix(sel.Sel.Name, "serveRoute") || sel.Sel.Name == "reportUsage" {
			found = append(found, sel.Sel.Name)
		}
		return true
	})
	if len(found) > 0 {
		t.Errorf("probe_models.go calls %v — discovery must not enter the chat "+
			"forwarding path; a token-less GET would emit usage events for a "+
			"request that consumed nothing", found)
	}
}
