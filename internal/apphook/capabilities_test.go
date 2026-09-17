package apphook

// capabilities_test.go — TODO-114 (需求包 roadmap20260320/技术实现/阶段9-商业化版本/
// 博时基金合规能力融合/task-execution/runs/design-todo-114.md §7.3).
//
// Two properties, and they fail in different ways:
//
//  1. The declared SET must be derived from what is compiled in, not typed by
//     hand. A hand-maintained list drifts from the Supports* predicates and the
//     proxy ends up promising something this binary cannot do — the TODO-114
//     defect reached from the inside.
//  2. The declaration must actually REACH the child, and must WIN over whatever
//     the proxy's own environment happens to carry. That second half is the
//     residue defense, and it is a property of the append order in childhook.go
//     — invisible in any unit test that does not spawn a real child.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/pipewire"
)

// TestDeclaredCapabilities_DerivedFromCompiledSupport pins the derivation, not a
// literal list: the expectation below is rebuilt from the same Supports*
// predicates the production function reads, so this test cannot be satisfied by
// editing a constant.
func TestDeclaredCapabilities_DerivedFromCompiledSupport(t *testing.T) {
	got := DeclaredCapabilities()
	inSet := func(want string) bool {
		for _, c := range got {
			if c == want {
				return true
			}
		}
		return false
	}

	if SupportsCountProjection() != inSet(pipewire.CapCountProjection) {
		t.Errorf("SupportsCountProjection()=%v but the declared set %v %s count_projection. The set must be "+
			"the compiled answer: declaring a capability this binary cannot serve is the same defect as "+
			"failing open on an unknown action, reached from the other side.",
			SupportsCountProjection(), got, map[bool]string{true: "contains", false: "omits"}[inSet(pipewire.CapCountProjection)])
	}
	if SupportsCannedAnswer() != inSet(pipewire.CapCannedAnswer) {
		t.Errorf("SupportsCannedAnswer()=%v but the declared set %v disagrees", SupportsCannedAnswer(), got)
	}
	// Anti-vacuity: this build really does declare something, so "the child sees
	// the declaration" below is a real statement.
	if len(got) == 0 {
		t.Fatal("this build declares NO capability at all — every assertion downstream would pass vacuously")
	}
	if !inSet(pipewire.CapCountProjection) {
		t.Fatal("count_projection is not declared, yet internal/proxy decodes a personal-route projection " +
			"and counts it (filter_dispatch.go / escalation.go). A detector reading this declaration would " +
			"stop handing one over and the org's cumulative rule would silently stop counting personal keys.")
	}

	t.Run("the env entry is the pipewire encoding of that set", func(t *testing.T) {
		want := pipewire.EnvProxyCapabilities + "=" + pipewire.FormatProxyCapabilities(got)
		if ProxyCapabilitiesEnv() != want {
			t.Errorf("ProxyCapabilitiesEnv() = %q, want %q — the encoding belongs to pkg/pipewire, "+
				"a second spelling here is how the two repositories start disagreeing",
				ProxyCapabilitiesEnv(), want)
		}
	})

	t.Run("an empty set still produces a LINE, not an empty string", func(t *testing.T) {
		// 🔴 The residue defense in one assertion. If the day a Supports* goes
		// false the entry became "" (or the caller skipped it), an inherited
		// AIKEY_PROXY_CAPABILITIES from proxy.env / cluster-node.env / a shell
		// would reach the child unchallenged and be believed.
		if got := capabilitiesEnvLine(nil); got != pipewire.EnvProxyCapabilities+"=" {
			t.Errorf("capabilitiesEnvLine(nil) = %q, want %q", got, pipewire.EnvProxyCapabilities+"=")
		}
		if !strings.HasPrefix(ProxyCapabilitiesEnv(), pipewire.EnvProxyCapabilities+"=") {
			t.Errorf("ProxyCapabilitiesEnv() = %q does not start with %q=",
				ProxyCapabilitiesEnv(), pipewire.EnvProxyCapabilities)
		}
	})
}

// ── the residue fence: a real child, over a real pipe ────────────────────────

// capEchoChildEnv switches this test binary into "be a detector that echoes its
// capability env back" mode.
const capEchoChildEnv = "AIKEY_APPHOOK_CAPABILITY_ECHO_CHILD"

// capResidue is a value no proxy would ever emit: two tokens that do not exist.
// It stands for whatever a stale ~/.aikey/proxy.env, /etc/aikey/cluster-node.env
// or developer shell might be carrying.
const capResidue = "bogus_residue,count_projection_v9"

// capEcho is what the child reports back.
type capEcho struct {
	// Value is os.Getenv(AIKEY_PROXY_CAPABILITIES) as the CHILD sees it.
	Value string `json:"value"`
	// Occurrences counts entries with that key in the child's own environ — a
	// diagnostic for the de-dup half of the contract.
	Occurrences int `json:"occurrences"`
}

// TestHelperCapabilitiesEchoChild is not a test: it is the child process for
// TestChildHook_SpawnEnvCapabilitiesOverrideInheritedResidue, re-executed from
// this same binary (the os/exec TestHelperProcess pattern, as in
// canned_answer_carrier_test.go and detector_gate_test.go).
//
// 🔴 STDOUT IS THE PIPE. Nothing but frames may go there, which is why this ends
// in os.Exit rather than returning into the test framework's summary.
func TestHelperCapabilitiesEchoChild(t *testing.T) {
	if os.Getenv(capEchoChildEnv) == "" {
		t.Skip("helper process; not a test")
	}
	// Reading the env here is the POINT of the child; the proxy's own
	// non-test source may never do this (see
	// TestProxyNeverReadsCapabilitiesFromItsOwnEnvironment in internal/supervisor,
	// which scans non-test files only).
	echo := capEcho{Value: os.Getenv(pipewire.EnvProxyCapabilities)}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, pipewire.EnvProxyCapabilities+"=") {
			echo.Occurrences++
		}
	}
	payload, err := json.Marshal(echo)
	if err != nil {
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "ready capability-echo-child")
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	for {
		version, frame, err := pipewire.ReadFrame(in)
		if err != nil {
			os.Exit(0) // stdin closed: the parent shut us down
		}
		if version != pipewire.ProtocolVersion {
			os.Exit(1)
		}
		req, err := pipewire.DecodeRequest(frame)
		if err != nil || req.Op != pipewire.OpDetect {
			continue
		}
		res := &pipewire.Response{ReqID: req.ReqID, Action: pipewire.ActionAllow, Event: payload}
		if err := pipewire.WriteFrame(out, pipewire.EncodeResponse(res)); err != nil {
			os.Exit(1)
		}
	}
}

// TestChildHook_SpawnEnvCapabilitiesOverrideInheritedResidue
//
// GIVEN the proxy's OWN environment carries a stale AIKEY_PROXY_CAPABILITIES
// WHEN  it spawns a child with ProxyCapabilitiesEnv() in ExtraEnv
// THEN  the child sees EXACTLY what the proxy declared, and none of the residue
//
// WHY A REAL CHILD: the property is a consequence of childhook.go building the
// environment as append(os.Environ(), ExtraEnv...) plus Go's exec keeping the
// LAST occurrence of a key. Reverse those two and every unit-level assertion
// still passes while every real deployment with a stale proxy.env starts lying
// to its detector.
func TestChildHook_SpawnEnvCapabilitiesOverrideInheritedResidue(t *testing.T) {
	// The proxy process is polluted, exactly as a machine with a stale
	// EnvironmentFile would be.
	t.Setenv(pipewire.EnvProxyCapabilities, capResidue)
	if os.Getenv(pipewire.EnvProxyCapabilities) != capResidue {
		t.Fatalf("fixture did not take: parent env = %q", os.Getenv(pipewire.EnvProxyCapabilities))
	}

	declared := ProxyCapabilitiesEnv()
	wantValue := strings.TrimPrefix(declared, pipewire.EnvProxyCapabilities+"=")
	if wantValue == capResidue {
		t.Fatal("the fixture residue equals what the proxy declares; this test could not tell them apart")
	}

	h := NewChildHook(&ChildHookConfig{
		Name:         "capability-echo",
		BinaryPath:   os.Args[0],
		BinaryArgs:   []string{"-test.run", "^TestHelperCapabilitiesEchoChild$"},
		ExtraEnv:     []string{capEchoChildEnv + "=1", declared},
		Timeout:      5 * time.Second,
		ReadyTimeout: 30 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("start capability-echo child: %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	res := h.Detect(ctx, &Request{Payload: []byte("ping"), RouteClass: RouteClassPersonal})
	if res.Degraded {
		t.Fatalf("child degraded: %s", res.Reason)
	}
	var echo capEcho
	if err := json.Unmarshal(res.Event, &echo); err != nil {
		t.Fatalf("child echo %q: %v", res.Event, err)
	}

	if echo.Value != wantValue {
		t.Fatalf("the child sees AIKEY_PROXY_CAPABILITIES=%q, want %q.\n"+
			"The proxy's own environment carried %q. ExtraEnv must be appended AFTER os.Environ() so the "+
			"LAST occurrence — the proxy's own declaration — wins; reverse that and a stale proxy.env / "+
			"cluster-node.env decides what the detector believes this binary can do.",
			echo.Value, wantValue, capResidue)
	}
	if strings.Contains(echo.Value, "bogus_residue") || strings.Contains(echo.Value, "count_projection_v9") {
		t.Errorf("residue tokens survived into the child: %q", echo.Value)
	}
	if echo.Occurrences != 1 {
		t.Errorf("the child's environ carries %d AIKEY_PROXY_CAPABILITIES entries, want exactly 1 — "+
			"a duplicated key makes which value wins depend on the reader", echo.Occurrences)
	}
	// And the value really is parseable back into the declared set.
	parsed := pipewire.ParseProxyCapabilities(echo.Value)
	for _, c := range DeclaredCapabilities() {
		if !parsed.Has(c) {
			t.Errorf("the child cannot read back declared capability %q from %q", c, echo.Value)
		}
	}
}
