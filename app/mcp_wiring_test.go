package app

// mcp_wiring_test.go — the plane must actually be MOUNTED.
//
// # Why this fence exists
//
// Every other MCP test in this repo drives internal/mcp directly. All of them
// would stay green if buildMCPPlane were never called, or if its result were
// dropped instead of appended to the registrar list — and the product would
// ship with a complete, well-tested MCP gateway that answers 404. That failure
// mode ("built, tested, never wired") has cost this project real releases
// before, and no unit test of the component can catch it.
//
// So this file asserts the two things only the WIRING can be wrong about:
//
//	the plane is constructed and returns a registrar
//	the six frozen routes are reachable through a mux built the way the real
//	server builds one
//
// 🔴 It deliberately does NOT test handler behaviour — that belongs in
// internal/mcp, and duplicating it here would make this fence expensive to keep
// and therefore likely to be deleted.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/mcp"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/server"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// mountPlaneForTest calls the REAL buildMCPPlane and registers its result on a
// mux shaped like the one server.buildMux produces.
//
// 🔴 It calls the real function, not a copy of it. A fence that re-implements
// the wiring would stay green if buildMCPPlane returned nil or if its result
// were dropped at the call site — which is the entire failure mode being
// fenced against.
func mountPlaneForTest(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	// The data plane's catch-all, exactly as server.buildMux registers it.
	// 🔴 Its presence is the point: Go 1.22+ ServeMux gives more specific
	// patterns priority, and this fence proves we are actually relying on that
	// correctly rather than on registration order.
	mux.HandleFunc("/{path...}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // a marker only the catch-all can produce
	})
	reg := buildMCPPlane(fakeMCPDeps{}, "127.0.0.1:27200")
	if reg == nil {
		t.Fatal("buildMCPPlane returned nil for a node WITH a key registry — the MCP plane would never be mounted")
	}
	// Registering through the interface is what app.go actually does; asserting
	// the concrete type here would let a refactor break the real path while this
	// stayed green.
	var registrar server.RouteRegistrar = reg
	registrar.RegisterRoutes(mux)
	return mux
}

// TestPlaneIsNotMountedWithoutAKeyRegistry — mounting with no way to
// authenticate anyone would answer every request 503 from inside the plane,
// which reads to a client as "the gateway is broken" rather than "this node has
// no keys". Not mounting yields a plain 404, which is the truth.
func TestPlaneIsNotMountedWithoutAKeyRegistry(t *testing.T) {
	if got := buildMCPPlane(fakeMCPDeps{noRegistry: true}, "127.0.0.1:27200"); got != nil {
		t.Error("the MCP plane mounted on a node with no virtual-key registry")
	}
	if got := buildMCPPlane(nil, "127.0.0.1:27200"); got != nil {
		t.Error("the MCP plane mounted with no supervisor at all")
	}
}

// TestMcpRoutesAreReachableThroughTheRealMuxShape is the wiring fence.
func TestMcpRoutesAreReachableThroughTheRealMuxShape(t *testing.T) {
	mux := mountPlaneForTest(t)

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/mcp/capabilities"},
		{http.MethodGet, "/.well-known/oauth-protected-resource"},
		{http.MethodGet, "/health/mcp"},
		{http.MethodPost, "/mcp/default"},
		{http.MethodGet, "/mcp/default"},
		{http.MethodDelete, "/mcp/default"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")))
			if rec.Code == http.StatusTeapot {
				t.Fatalf("%s %s fell through to the data-plane catch-all — the MCP plane is not mounted",
					tc.method, tc.path)
			}
		})
	}
}

// TestPlaneDoesNotMountWithoutAPolicySource.
//
// 🔴 This REPLACES P1's TestPlaceholderCatalogIsHonestlyDeclared, which asserted
// that the fixture catalog declared itself. The fixture is gone; the assertion
// that replaces it is the stronger one — a node with no control plane must not
// mount the plane at all, because there is nothing to authorise against.
//
// 🚫 Do not delete this test when something else changes here. The P1 version
// existed to keep a declared gap from becoming a silent one; this one exists to
// keep "cannot authorise" from becoming "authorises everything".
func TestPlaneDoesNotMountWithoutAPolicySource(t *testing.T) {
	if got := buildMCPPlane(fakeMCPDeps{noPolicy: true}, "127.0.0.1:27200"); got != nil {
		t.Error("the MCP plane mounted on a node that follows no control plane; " +
			"it would serve a toolset nobody granted")
	}
}

// TestMountedPlaneAdvertisesToolGrants — the capabilities document is quoted in
// sales conversations, so it must move when the capability actually lands.
func TestMountedPlaneAdvertisesToolGrants(t *testing.T) {
	mux := mountPlaneForTest(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp/capabilities", nil))

	var doc struct {
		Features map[string]bool `json:"features"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Features["tool_grants"] {
		t.Error("tool_grants is still advertised false after the policy-backed catalog shipped")
	}
	// 🔴 The shipped/not-yet MATRIX is deliberately NOT re-asserted here. It was,
	// and the duplicate is what let it go stale: this file and
	// internal/mcp/handler_test.go each carried a copy of the "not shipped" list,
	// so P3 and P4 landed with both copies still naming the features they had
	// just shipped — the document under-reported two working capabilities and
	// TWO fences held the error in place.
	//
	// One list, one home: internal/mcp/handler_test.go
	// (TestCapabilitiesDoesNotClaimOAuth) owns it, and asserts BOTH directions.
	// What THIS test owns is narrower and app-specific: that a plane mounted
	// through the real wiring reports the capability its catalog actually
	// provides.
}

// TestExternalBaseURLNormalisesABareListenAddr — ":27200" is what a listener
// bound to all interfaces reports, and a metadata document advertising
// "http://:27200" sends a stuck client nowhere.
func TestExternalBaseURLNormalisesABareListenAddr(t *testing.T) {
	if got := mcpExternalBaseURL(":27200"); got != "http://127.0.0.1:27200" {
		t.Errorf("mcpExternalBaseURL(\":27200\") = %q", got)
	}
	if got := mcpExternalBaseURL("127.0.0.1:27200"); got != "http://127.0.0.1:27200" {
		t.Errorf("mcpExternalBaseURL(\"127.0.0.1:27200\") = %q", got)
	}
}

// fakeMCPDeps stands in for the supervisor.
//
// The registry is EMPTY rather than absent: the wiring fence only asks whether
// routes are reachable, so every authenticated route legitimately answers 401.
// What matters is that the 401 comes from the MCP plane and not a 418 from the
// data-plane catch-all.
type fakeMCPDeps struct {
	noRegistry bool
	// noPolicy models a node with no control plane (Personal). 🔴 The plane must
	// then NOT mount: there is no org to hold grants, and a gateway that cannot
	// authorise must not serve.
	noPolicy bool
}

func (f fakeMCPDeps) Registry() *vkeys.Registry {
	if f.noRegistry {
		return nil
	}
	return vkeys.NewRegistry()
}

// FallbackPolicyCache returns nil — the shape of a node with no org-level
// fallback policy, where the builtin three-state defaults apply.
func (fakeMCPDeps) FallbackPolicyCache() *proxy.FallbackPolicyCache { return nil }

// MCPManifestSyncer returns nil — the shape before the manifest sync starts,
// which is exactly the state buildMCPPlane runs in. 🔴 That the plane still
// mounts with a nil syncer is the point: the syncer is read per request, so a
// plane built before the prober exists still picks it up later.
func (fakeMCPDeps) MCPManifestSyncer() *mcp.ManifestSyncer { return nil }
func (fakeMCPDeps) MCPLocalPublisher() *mcp.LocalPublisher { return nil }

// MCPPolicySource reports the control-plane producer: this fake supplies a
// policy store, which on a real node only the rail does. 🔴 It is a real value
// rather than "" because /health/mcp's policy_source is what `aikey mcp add`
// reads to decide whether ~/.aikey/mcp.json will ever be honoured, and a fake
// that answered "" would let the plane mount without the discriminator and keep
// this fence green while that answer went missing.
func (fakeMCPDeps) MCPPolicySource() string { return mcp.PolicySourceControlPlane }

// EventStore returns nil — a node whose local store is not open. 🔴 That is the
// interesting case for this fence: the plane must still MOUNT and still SERVE.
// A gateway that refused to start because its audit sink was missing would take
// the customer's tools offline over a bookkeeping problem; the honest answer is
// to serve and say `call_recording:"off"` on /health/mcp.
func (fakeMCPDeps) EventStore() *events.Store { return nil }

// FilterHook returns nil — a node with no DLP app installed, which is the
// common default. 🔴 The plane must still MOUNT and still SERVE: refusing tool
// calls because an OPTIONAL filter is absent would make the option mandatory by
// accident, on every deployment that never asked for compliance.
func (fakeMCPDeps) FilterHook() apphook.Hook { return nil }

// UploadComplianceEvents is a no-op here; the wiring fence asserts routes, not
// upload behaviour.
func (fakeMCPDeps) UploadComplianceEvents(context.Context, [][]byte) {}

// MCPCredentialStore is nil here, which is the shape of a node whose vault is
// not unlocked. 🔴 That is the interesting case for this file: the plane must
// still mount, and a backend that declares a credential must be REFUSED rather
// than probed unauthenticated. buildMCPPlane routes this through
// credentialResolver() precisely so a nil store does not become a non-nil
// interface holding a nil pointer.
func (fakeMCPDeps) MCPCredentialStore() *mcp.CredentialStore { return nil }

// MCPPolicyStore returns a store holding one granted toolset, so the wiring
// fence exercises the real (policy-backed) catalog rather than a fixture that
// no longer ships.
func (f fakeMCPDeps) MCPPolicyStore() *mcp.PolicyStore {
	if f.noPolicy {
		return nil
	}
	store := mcp.NewPolicyStore()
	store.Store(&mcp.Policy{
		OrgID:   "org_wiring",
		Version: 1,
		Toolsets: []mcp.PolicyToolset{{
			ID: "ts1", Slug: "default", Status: "active",
			Tools: []mcp.PolicyTool{{
				ID: "t1", BackendID: "b1", Name: "aikey_gateway_info",
				InputSchema: "{}", State: "published",
			}},
		}},
		Grants: []mcp.PolicyGrant{{SubjectKind: "seat", SubjectID: "seat_wiring", VirtualServerID: "ts1"}},
	})
	return store
}

// ---------------------------------------------------------------------------
// The producer must exist before the consumer captures it (P14.3 review surface)
// ---------------------------------------------------------------------------

// TestLocalPublisherExistsBeforeAdminWiring — an ORDERING fence over Run().
//
// # Why this is a source-order assertion and not a behavioural one
//
// bugfix: workflow/CI/bugfix/20260904-personal-mcp-review-surface-was-never-wired.md
//
// The defect was not in any component. Every unit test of internal/mcp passed,
// the publisher worked, the admin handler worked, and the two were joined by a
// single line in Run() that read the publisher 380 lines BEFORE anything created
// it. On a Personal node the capture therefore saw nil, `MCPLocalReviewFn` was
// never set, and `aikey mcp review --accept` — the only way to release a hosted
// server's tools past the first-review gate — answered 503 "this node follows a
// control plane" on the one edition that has none. A Personal install could host
// a backend and serve zero tools forever.
//
// Reproducing that behaviourally means booting Run(): a listener, a vault, a
// supervisor generation and a real child process. This fence instead asserts the
// one property that was wrong, directly — and it is not vacuous: it names two
// specific call sites and goes red if EITHER is deleted or if they swap order.
//
// 🚫 Do NOT "fix" a failure here by deleting an anchor. If the wiring genuinely
// moves, move both and update this test with the reason.
//
// 能红:
//   - move the `sup.EnableLocalMCPPublisher()` call back below the admin handler
//   - delete either anchor
func TestLocalPublisherExistsBeforeAdminWiring(t *testing.T) {
	src, err := os.ReadFile("app.go")
	if err != nil {
		t.Fatalf("read app.go: %v", err)
	}
	text := string(src)

	// The line that CREATES Personal's approval state.
	const producer = "sup.EnableLocalMCPPublisher()"
	// The line that CAPTURES it into the admin handler, once, by value.
	const consumer = "if pub := sup.MCPLocalPublisher(); pub != nil {"
	// The line that installs the local policy the publisher is built from.
	const policy = "mountLocalMCP(sup)"

	for name, anchor := range map[string]string{
		"producer": producer,
		"consumer": consumer,
		"policy":   policy,
	} {
		if n := strings.Count(text, anchor); n != 1 {
			t.Fatalf("%s anchor %q appears %d times in app.go, want exactly 1 — "+
				"this fence can no longer tell the ordering; fix the anchor, do not delete the test",
				name, anchor, n)
		}
	}

	iPolicy := strings.Index(text, policy)
	iProducer := strings.Index(text, producer)
	iConsumer := strings.Index(text, consumer)

	if iProducer > iConsumer {
		t.Fatalf("🔴 app.go creates Personal's MCP approval state (%s, offset %d) AFTER the "+
			"admin handler captures it (%s, offset %d). The capture is by value and happens "+
			"once, so it will see nil on every Personal node: `aikey mcp review --accept` "+
			"then answers 503 \"this node follows a control plane\" on the edition that has "+
			"none, and no hosted tool can ever be released past the first-review gate.",
			producer, iProducer, consumer, iConsumer)
	}
	if iPolicy > iProducer {
		t.Fatalf("🔴 app.go builds the publisher (offset %d) before installing the local policy "+
			"it reads from (%s, offset %d), so EnableLocalMCPPublisher returns nil and the "+
			"review surface is dead for the same reason as above.",
			iProducer, policy, iPolicy)
	}
}
