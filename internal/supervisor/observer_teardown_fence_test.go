package supervisor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Fence for the observer registry's retirement wiring (2026-08-15).
//
// 🔴 WHY THIS NEEDS A FENCE AND NOT JUST A UNIT TEST: the bug this guards
// against was never a broken function — it was a function nobody called.
//
// buildObserverRegistry runs once per GENERATION (see its own doc-comment and
// the call in buildGeneration), so every reload builds a fresh observer set.
// Whatever those observers start in Build — the rhythm plugin starts a 5s
// settings poller plus a reporter worker pool — has to be retired when the
// generation is discarded, or it runs until process exit.
//
// Nothing retired them. Observed live on 2026-08-15: one flip of the
// realtime-detection toggle produced FOUR `rhythm.settings_poller.toggle_changed`
// events, each reporting `from=false`, i.e. four independent leaked pollers each
// hitting trust-local every 5s. rhythm's SettingsPoller.Start doc-comment had
// even called out the hazard, but assumed "exactly one observer instance per
// proxy process" — an invariant the per-generation rebuild quietly breaks.
//
// Allocation-signal state has since moved to Supervisor/process ownership: its
// reporter must survive generation teardown and close only at process shutdown.
//
// Registry.Close and Proxy.StopObservers are unit-tested in pkg/observer. Those
// tests all stay green if the call in closeAll is deleted — which is exactly how
// the original leak survived. So this fence pins the CALL SITE.
//
// 能红: delete `g.proxy.StopObservers()` from generation.closeAll.

// callsMethodOn reports whether fn contains a call of the form `<recv>.<method>(`.
func callsMethodOn(fn *ast.FuncDecl, recv, method string) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != method {
			return true
		}
		// Receiver may be `g.proxy` (SelectorExpr) or a bare ident.
		switch x := sel.X.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == recv {
				found = true
			}
		case *ast.Ident:
			if x.Name == recv {
				found = true
			}
		}
		return true
	})
	return found
}

func funcNamed(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("%s not found in %s — was it renamed? This fence must be re-pointed, "+
		"not deleted: the teardown it guards is what stops per-generation observer "+
		"goroutines leaking.", name, file)
	return nil
}

// TestGenerationCloseRetiresObservers pins that generation teardown actually
// retires the observer registry.
func TestGenerationCloseRetiresObservers(t *testing.T) {
	closeAll := funcNamed(t, "supervisor.go", "closeAll")

	if !callsMethodOn(closeAll, "proxy", "StopObservers") {
		t.Error("generation.closeAll does not call g.proxy.StopObservers(). " +
			"The observer registry is rebuilt per generation, so without this " +
			"every reload leaks whatever its observers started in Build — the " +
			"2026-08-15 rhythm settings-poller leak (four live 5s pollers, one " +
			"per generation, all polling trust-local forever).")
	}
}

// TestSignalReporterLifecycleMatchesProcessOwnership pins both sides of the
// ownership boundary. Closing it per generation loses late 401/429 facts;
// never closing it leaks its loop and ticker at process exit.
func TestSignalReporterLifecycleMatchesProcessOwnership(t *testing.T) {
	closeAll := funcNamed(t, "supervisor.go", "closeAll")
	if callsMethodOn(closeAll, "proxy", "StopSignalReporting") {
		t.Error("generation.closeAll must not stop process-owned signal reporting; " +
			"a draining request can publish a late OAuth failure after reload")
	}

	shutdown := funcNamed(t, "supervisor.go", "Shutdown")
	if !callsMethodOn(shutdown, "oauthPoolRuntime", "Shutdown") {
		t.Error("Supervisor.Shutdown must retire oauthPoolRuntime so the shared " +
			"signal reporter loop and ticker do not leak at process exit")
	}
}
