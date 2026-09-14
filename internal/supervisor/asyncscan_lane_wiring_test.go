package supervisor

import (
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/asyncscan"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/deepscanfwd"
	"github.com/AiKeyLabs/pkg/scannode"
)

// TestAsyncScanLane_IsActuallyConstructed pins the COMPOSITION ROOT of the
// asynchronous deep-scan lane.
//
// 🔴 WHY A FENCE ON CONSTRUCTION, NOT ON BEHAVIOR.
// Every piece of this lane — asyncscan's enqueuer, local executor, placement,
// merge, coverage and event builder, and deepscanfwd's forwarder, frame builder
// and v2 sink — was written, unit-tested and green, while NOTHING OUTSIDE TESTS
// EVER CONSTRUCTED ANY OF THEM. Measured at the time:
//
//	NewEnqueuer: 0   NewLocalExecutor: 0   NewRemoteForwarder: 0   BuildEvents: 0
//	(non-test references from outside the owning packages)
//
// The result was a proxy that polled GET /v1/compliance/scan-nodes every 60
// seconds, published a trusted node set, computed deepScanMode() == remote —
// and then enqueued nothing, because p.asyncEnqueuer was permanently nil. The
// feature this whole workstream delivers was unreachable in the shipped binary.
//
// Unit tests cannot catch that shape: they construct the component themselves
// and inject its dependencies, which proves "this part works" and never proves
// "the product builds it". And the runtime says nothing either — no enqueuer
// simply means no asynchronous scanning, which is a supported state.
//
// This is the third instance of the shape in one workstream (the master's
// RouterDeps.ScanNodes, the Python node's AIKEY_DEEPSCAN_LISTEN branch, and
// this). Each now has a fence that watches the WIRING.
func TestAsyncScanLane_IsActuallyConstructed(t *testing.T) {
	// 1. The lane must be installed from the generation-apply path, beside the
	//    filter hook whose commit point feeds it. A builder nobody calls is the
	//    same outcome as no builder.
	sup := readSource(t, "supervisor.go")
	if !strings.Contains(sup, "installAsyncScanLane(") {
		t.Fatal("supervisor.go never calls installAsyncScanLane — the lane is never " +
			"constructed, so proxy.asyncEnqueuer stays nil and no committed piece is " +
			"ever scanned asynchronously, however healthy everything looks")
	}

	// 2. The install must reach the proxy. SetAsyncEnqueuer is the ONLY door
	//    into the commit point (filter_dispatch.go reads p.asyncEnqueuer).
	lane := readSource(t, "asyncscan_lane.go")
	if !regexp.MustCompile(`SetAsyncEnqueuer\(`).MatchString(lane) {
		t.Error("asyncscan_lane.go never calls p.SetAsyncEnqueuer — the commit point " +
			"reads p.asyncEnqueuer and nothing else, so the lane cannot receive a piece")
	}

	// 3. Both executors must be reachable. Remote-only would leave Personal and
	//    Trial — and every personal-routed piece anywhere — with nowhere to go;
	//    local-only would make the scan nodes this workstream deploys inert.
	for _, ctor := range []string{"NewEnqueuer(", "NewLocalExecutor(", "NewRemoteForwarder("} {
		if !strings.Contains(lane, ctor) {
			t.Errorf("asyncscan_lane.go never calls %s — that half of the lane is still dead code", ctor)
		}
	}

	// 3b. 🔴 THE CLUSTER PATH. A Cluster worker has no member JWT, so the
	// scan_nodes rail deliberately skips it — its node list comes from the
	// installer-rendered cluster-node.env instead (internal/cluster). That
	// loader was ALSO never called outside tests, which meant everything
	// cluster-install.sh and deploy-cluster-production.sh render into every
	// worker's env landed in a file nothing read. Fifth instance of the shape in
	// this workstream.
	if !strings.Contains(lane, "cluster.LoadRenderedScanNodes(") {
		t.Error("the lane never calls cluster.LoadRenderedScanNodes — a Cluster worker " +
			"would ignore AIKEY_PROXY_SCAN_NODE_ADDRS/_FINGERPRINTS entirely, so every " +
			"scan node the installer deployed sits idle with nothing reporting it")
	}

	// 4. Results must become EVENTS. A lane that scans and discards is worse
	//    than no lane: it spends the CPU and the network, and the finding never
	//    reaches the org's ledger, so the coverage hole is invisible.
	for _, step := range []string{"Merge(", "BuildEvents(", "EncodeForMaster("} {
		if !strings.Contains(lane, step) {
			t.Errorf("asyncscan_lane.go never calls %s — scan results would be computed and dropped", step)
		}
	}

	// 5. 🔴 The remote sink must be the PINNING one. scannode.NewTLSSink is what
	//    enforces https + private-IP + exact certificate fingerprint. Any other
	//    dialer here would send raw employee prompts to whatever answers.
	if !strings.Contains(lane, "scannode.NewTLSSink") {
		t.Error("asyncscan_lane.go does not dial nodes through scannode.NewTLSSink — " +
			"that function IS the trust decision (https, private range, exact fingerprint); " +
			"without it the forwarder would send raw prompt content to an unverified peer")
	}
	// 🔴 AND IT MUST BE HANDED THE PUBLISHED TRUST SET.
	// Checking only the function NAME was not enough: replacing the predicate
	// with `func(string) bool { return true }` still calls NewTLSSink, still
	// compiles, and makes the proxy accept ANY certificate from a node address —
	// and that mutation left this test green until this assertion was added.
	// The predicate must be the closed set the control plane published, so it is
	// required to be an identifier, never an inline literal.
	if regexp.MustCompile(`NewTLSSink\(\s*\w+\s*,\s*func\(`).MatchString(lane) {
		t.Error("scannode.NewTLSSink is called with an INLINE predicate — the fingerprint " +
			"pin must be the closed trust set published by the scan_nodes rail (nodes.Trusted). " +
			"An inline predicate is how `return true` gets in, which accepts any certificate " +
			"from a node's address while still looking like a pinned dial")
	}
	if !regexp.MustCompile(`trusted\s*:?=\s*nodes\.Trusted`).MatchString(lane) {
		t.Error("the dial predicate is not bound from nodes.Trusted — the pin must come " +
			"from the very response that advertised the nodes")
	}
}

// TestAsyncScanLane_PlacementDecidesDestination guards the one rule that has no
// exception: a personal-routed piece is scanned on this machine or not at all.
// The lane must route through asyncscan.Place rather than re-deciding locally,
// because Place is where that rule and the fail-closed unknown-policy rule live.
func TestAsyncScanLane_PlacementDecidesDestination(t *testing.T) {
	lane := readSource(t, "asyncscan_lane.go")
	if !strings.Contains(lane, "asyncscan.Place(") {
		t.Fatal("asyncscan_lane.go decides placement without asyncscan.Place — " +
			"Place is where 'a personal piece never leaves the machine' and " +
			"'an unknown team_async_scan value fails closed' are enforced")
	}
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// ── behavior, not just presence ─────────────────────────────────────────────
//
// The source scans above prove the lane is CONSTRUCTED. These prove it ROUTES:
// a committed piece has to reach an executor, and a personal piece has to reach
// the local one no matter what the org said. Both run against the real
// asyncSubmitFunc, because a test that re-implemented the routing would be
// asserting its own copy of the rule.

type fakeExec struct{ got []deepscanfwd.PieceJob }

func (f *fakeExec) Submit(j deepscanfwd.PieceJob) bool { f.got = append(f.got, j); return true }

func newLaneForTest() *asyncScanLane {
	return &asyncScanLane{lru: asyncscan.NewScannedLRU(16), stop: make(chan struct{}), log: slog.Default()}
}

func TestAsyncSubmit_TeamPieceWithNodesGoesRemote(t *testing.T) {
	s := &Supervisor{cfg: &config.Config{}}
	mode := string(asyncscan.TeamAsyncScanNodes)
	s.teamAsyncScan.Store(&mode)
	tok := "sct1.org_a.9999999999.k1.sig"
	s.scanToken.Store(&tok)

	lane := newLaneForTest()
	fwd := deepscanfwd.NewRemoteForwarder(deepscanfwd.Config{
		Nodes: []scannode.Node{{ID: "n1", Addr: "https://10.0.0.9:27411", Fingerprint: "aa", Weight: 1}},
	})
	lane.remote = fwd

	ok := s.asyncSubmitFunc(lane)(
		asyncscan.CommittedPiece{Text: "客户手机号 13800138000", HeadBytes: 0, Source: "request"},
		asyncscan.RequestIdentity{TenantID: "org_a", TraceID: "t1", ScopeKey: "au1"},
	)
	if !ok {
		t.Fatal("a team piece with nodes and a token was not accepted by the lane")
	}
	if got := fwd.Stats().Enqueued; got != 1 {
		t.Fatalf("forwarder enqueued %d frames, want 1 — the piece did not reach the remote lane", got)
	}
}

func TestAsyncSubmit_PersonalPieceNeverGoesRemote(t *testing.T) {
	// 🔴 The org says "use nodes" and there ARE nodes. A personal piece must
	// still be scanned on this machine: it is an individual's own content, with
	// no organization behind it and no tenant a node could authorise it against.
	s := &Supervisor{cfg: &config.Config{}}
	mode := string(asyncscan.TeamAsyncScanNodes)
	s.teamAsyncScan.Store(&mode)
	tok := "sct1.org_a.9999999999.k1.sig"
	s.scanToken.Store(&tok)

	lane := newLaneForTest()
	fwd := deepscanfwd.NewRemoteForwarder(deepscanfwd.Config{
		Nodes: []scannode.Node{{ID: "n1", Addr: "https://10.0.0.9:27411", Fingerprint: "aa", Weight: 1}},
	})
	lane.remote = fwd
	local := &fakeExec{}
	lane.localSubmit = local.Submit

	s.asyncSubmitFunc(lane)(
		asyncscan.CommittedPiece{Text: "my own note", Source: "request", Personal: true},
		asyncscan.RequestIdentity{TenantID: "org_a", TraceID: "t2", ScopeKey: "au2"},
	)

	if n := fwd.Stats().Enqueued; n != 0 {
		t.Fatalf("a PERSONAL piece was enqueued to a remote node (%d frames) — it must never leave the machine", n)
	}
	if len(local.got) != 1 {
		t.Fatalf("the personal piece reached neither lane (local got %d) — it was silently dropped", len(local.got))
	}
}

func TestAsyncSubmit_TeamOffScansNothing(t *testing.T) {
	// Unset team_async_scan means "we have never heard from a master", and a
	// proxy must not decide on its own that the org permits this.
	s := &Supervisor{cfg: &config.Config{}}
	lane := newLaneForTest()
	local := &fakeExec{}
	lane.localSubmit = local.Submit

	if s.asyncSubmitFunc(lane)(
		asyncscan.CommittedPiece{Text: "team content", Source: "request"},
		asyncscan.RequestIdentity{TenantID: "org_a", TraceID: "t3"},
	) {
		t.Fatal("team content was scanned with no instruction from the control plane")
	}
	if len(local.got) != 0 {
		t.Fatalf("team content reached the local executor anyway (%d jobs)", len(local.got))
	}
}

func TestAsyncSubmit_SameContentTwiceIsScannedOnce(t *testing.T) {
	s := &Supervisor{cfg: &config.Config{}}
	mode := string(asyncscan.TeamAsyncScanLocal)
	s.teamAsyncScan.Store(&mode)
	lane := newLaneForTest()
	local := &fakeExec{}
	lane.localSubmit = local.Submit

	submit := s.asyncSubmitFunc(lane)
	p := asyncscan.CommittedPiece{Text: "identical body", Source: "request"}
	submit(p, asyncscan.RequestIdentity{TenantID: "org_a", TraceID: "t4"})
	submit(p, asyncscan.RequestIdentity{TenantID: "org_a", TraceID: "t5"})

	if len(local.got) != 1 {
		t.Fatalf("the same content was scanned %d times — the already-scanned record is keyed on the whole content", len(local.got))
	}
}
