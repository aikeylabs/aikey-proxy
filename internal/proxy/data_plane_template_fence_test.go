package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// data_plane_template_fence_test.go — invariant I1 (task 4.8, requirement
// R-rge-7): serving an endpoint request reads ONLY the delivered bindings. The
// data plane must never read `route_group` or `route_group_member` at request
// time.
//
// # Why this matters enough to fence
//
// The delivered bindings are a projection: they are pushed to the node, they
// survive a control-plane outage, and they are what makes the data plane able to
// serve when the control plane is down. The moment a request reads the TEMPLATE,
// three things become true at once —
//
//	· the data plane needs the control database on the request path;
//	· an edit to a template changes live traffic with no delivery step, so the
//	  "editing a template does not propagate" rule (I41) stops being enforceable;
//	· the endpoint's chain and the employee's chain start coming from different
//	  places, and D-2's split becomes an accident of which code path ran.
//
// # 🔴 What is NOT a violation
//
// The COLUMN `route_group_id` on a delivered binding is a provenance stamp and
// is read constantly — that is the whole of how the proxy knows a chain came
// from a template. This fence therefore matches TABLE ACCESS (FROM/JOIN/INTO/
// UPDATE/DELETE FROM), not the identifier.
//
// 🔴 The scan covers the WHOLE module, including this package. A fence that
// excluded the code it polices would be exactly the "pass achieved by excluding
// the endpoint code path" that R-rge-7's scenario forbids.
//
// 能红: add `SELECT ... FROM route_group_member` anywhere under this module.

var dataPlaneTemplateTableAccess = regexp.MustCompile(
	`(?i)\b(from|join|into|update|delete\s+from)\s+` + "`" + `?"?(route_group_member|route_group)\b`)

func TestDataPlane_NeverReadsTheRouteGroupTemplateTables(t *testing.T) {
	root := templateFenceModuleRoot(t)
	var violations []string
	scanned := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == ".git" || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(string(blob), "\n") {
			trimmed := strings.TrimSpace(line)
			// Comments describe the control plane's constraints constantly; they
			// are documentation, not access.
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if dataPlaneTemplateTableAccess.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				violations = append(violations, rel+":"+templateFenceItoa(i+1)+": "+trimmed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// 🔴 A scan that found no files is a fence that proves nothing. This is the
	// failure mode the register of fences keeps catching: the check ran, the
	// enumeration was empty, and the suite reported ok.
	if scanned == 0 {
		t.Fatal("the fence scanned 0 source files — it would pass vacuously")
	}
	// And it must have covered the candidate loop — the code path that actually
	// walks an endpoint's chain, and the one a "pass by excluding the endpoint
	// code path" would leave out.
	if _, err := os.Stat(filepath.Join(root, "internal", "proxy", "candidate_chain.go")); err != nil {
		t.Fatalf("the scan root does not contain the candidate loop (%v); the fence is looking at the wrong tree", err)
	}
	if len(violations) > 0 {
		t.Fatalf("the data plane reads a route-group TEMPLATE table at request time (I1 / R-rge-7):\n  %s\n\n"+
			"Serving a request must read only the DELIVERED bindings. Reading the template puts the "+
			"control database on the request path, makes a template edit change live traffic with no "+
			"delivery step, and dissolves D-2's split between endpoint keys and issued employee keys.",
			strings.Join(violations, "\n  "))
	}
}

// moduleRoot walks up from the package directory to the go.mod.
//
// 🔴 Anchored on the MODULE, never on a repo root guessed from the filesystem: a
// fence anchored on a repo root evaluates a different tree when this module is
// checked out in a git worktree, and then reports on somebody else's code while
// looking perfectly healthy.
func templateFenceModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("no go.mod found above the package directory; the fence has no scan root")
	return ""
}

func templateFenceItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
