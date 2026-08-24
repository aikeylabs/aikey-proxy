package events

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every collector path this package requests has to survive one more hop that
// nobody compiles: the reverse proxy in front of the collector. Those configs
// are HAND-MAINTAINED lists of `location` blocks, so a newly-added path reaches
// the collector in dev (direct dial) and 404s in every deployment behind nginx.
//
// That is not hypothetical. `/internal/canary-check` was missing from the
// Production template while the cluster installer's config had it, so on every
// Production deployment the usage-pipeline canary answered "unavailable" — which
// the cluster-health page renders as a red PIPELINE verdict — while reporting
// was fine and the proxy's own /health said usage_pipeline=ok. Found 2026-08-22
// only because a human asked whether the pipeline was broken.
//
// Fences the CHAIN: the path list is derived from THIS package's source, so a
// path added tomorrow is covered without anyone extending this test.
//
// 能红: delete the `location /internal/canary-check` line from either config.

// notCollectorPaths are request paths that go somewhere other than the
// collector, so no nginx collector route is expected. Each needs a reason —
// an unexplained entry here is how a real gap gets silenced.
var notCollectorPaths = map[string]string{
	"/v1/messages":          "upstream LLM endpoint (Anthropic wire format), not ours",
	"/v1/compliance/events": "served by control-master (internal/compliance/mux.go), not the collector — location /v1 → control is correct",
}

func TestCollectorPathsHaveNginxRoutes(t *testing.T) {
	// Paths as written in this package: plain literals and fmt.Sprintf targets
	// (the canary builds "%s/internal/canary-check?event_id=%s").
	pathRe := regexp.MustCompile(`"(?:%s)?(/(?:v1|internal)/[a-zA-Z0-9/_.:-]+)`)
	found := map[string]bool{}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pathRe.FindAllStringSubmatch(string(src), -1) {
			p := strings.SplitN(m[1], "?", 2)[0]
			if _, skip := notCollectorPaths[p]; skip {
				continue
			}
			found[p] = true
		}
	}
	if len(found) == 0 {
		t.Fatal("derived ZERO collector paths from this package — the regex or the " +
			"call sites changed, and this test is now fencing nothing")
	}

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	configs := []string{
		filepath.Join(root, "workflow", "CD", "templates", "server", "nginx.default.conf.tmpl"),
		filepath.Join(root, "workflow", "CD", "installer", "cluster-install", "nginx", "control-master.conf"),
	}

	paths := make([]string, 0, len(found))
	for p := range found {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, cfg := range configs {
		body, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatalf("cannot read %s: %v.\nIf the config moved, FIX THIS PATH — a coverage "+
				"test that cannot find its target silently stops covering anything.", cfg, err)
		}
		text := string(body)
		var missing []string
		for _, p := range paths {
			// nginx picks the LONGEST matching prefix location, so coverage is
			// not "some location matches" — it is "the location that actually
			// wins routes to the collector".
			//
			// 🔴 An earlier version stopped at "some location matches" and
			// passed even after the dedicated route was deleted, because the
			// broad `location /internal` (→ control-service) still matched.
			// That is the ORIGINAL BUG's shape: a wide rule swallows the path,
			// sends it to a backend with no such endpoint, and 404s silently.
			// "Something answers" is not the property worth fencing.
			win, ok := longestMatch(text, p)
			if !ok {
				missing = append(missing, p+"  (no location matches at all)")
			} else if !strings.Contains(win.body, "$collector_backend") {
				missing = append(missing, p+"  (matched `location "+win.prefix+
					"` which does NOT proxy to $collector_backend)")
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s does not route these collector paths to the collector:\n  %s\n\n"+
				"Whatever location wins instead answers with a backend that has no such\n"+
				"endpoint, so the request 404s and the caller sees a silent failure — the\n"+
				"canary reads it as \"unavailable\" and the cluster-health page paints the\n"+
				"pipeline red while reporting is fine.\n\n"+
				"Add an EXACT-path location proxying to $collector_backend. Do NOT widen an\n"+
				"existing prefix such as /internal/, which would expose the rest of the\n"+
				"control-plane surface on this origin.",
				filepath.Base(cfg), strings.Join(missing, "\n  "))
		}
	}
}

type nginxLocation struct {
	prefix string
	body   string
}

// longestMatch returns the prefix location nginx would select for path, i.e.
// the longest matching prefix. Regex/exact (`~`, `=`) forms are ignored:
// neither is used for the collector routes, and treating a regex as a prefix
// would mis-model which block wins.
func longestMatch(cfg, path string) (nginxLocation, bool) {
	re := regexp.MustCompile(`(?m)^\s*location\s+(/[^\s{]*)\s*\{([^}]*)\}`)
	var best nginxLocation
	found := false
	for _, m := range re.FindAllStringSubmatch(cfg, -1) {
		prefix, body := m[1], m[2]
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		if !found || len(prefix) > len(best.prefix) {
			best = nginxLocation{prefix: prefix, body: body}
			found = true
		}
	}
	return best, found
}
