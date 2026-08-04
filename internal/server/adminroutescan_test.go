package server

import (
	"os"
	"regexp"
	"testing"
)

type adminRoute struct{ method, path, expr string }

var adminRouteRe = regexp.MustCompile(`mux\.HandleFunc\("(GET|POST|PUT|DELETE) (/admin/[^"]*)", ([^\n]*)\)\n`)

// adminRoutePatterns reads server.go itself. Source-scanning beats reflecting
// over http.ServeMux because ServeMux exposes no route list, and a hand-kept
// list of "routes that should be guarded" is the same second source of truth
// this whole change exists to delete.
func adminRoutePatterns(t *testing.T) []adminRoute {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	matches := adminRouteRe.FindAllStringSubmatch(string(src), -1)
	out := make([]adminRoute, 0, len(matches))
	for _, m := range matches {
		out = append(out, adminRoute{method: m[1], path: m[2], expr: m[3]})
	}
	return out
}
