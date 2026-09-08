package mcp

// instance_fence_test.go — fences over instance selection (task 6.4 / R5).
//
// Each test here states an invariant that a later refactor could silently
// remove, and each was drilled by mutating the product code and observing the
// failure. The drill notes on each test say exactly which line to break.

import (
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// threeInstances is a backend a registry advertises on three addresses.
func threeInstances() PolicyBackend {
	return PolicyBackend{
		ID: "b1", Name: "github", Transport: TransportStreamableHTTP,
		EndpointURL: "http://10.0.0.1:9000/mcp",
		Instances: []string{
			"http://10.0.0.1:9000/mcp",
			"http://10.0.0.2:9000/mcp",
			"http://10.0.0.3:9000/mcp",
		},
		Status: StatusActive,
	}
}

// TestFence_6F7_CredentialBoundBackendNeverFansOutAcrossInstances.
//
// A backend with a credential bound is dialled at its ONE approved address, no
// matter how many instances the registry advertises. The control plane already
// declines to write such a list; this is the same refusal at the point of use,
// so an older, wrong or compromised control plane cannot cause the fan-out on
// its own.
//
// Why it matters: an attacker who can write to the service registry adds an
// instance. If we dialled it, the customer's credential would be sent there on
// the first call, and the manifest freeze cannot see it — he can serve an
// identical manifest. endpoint_url would still read as the approved address, so
// nothing in the console would look wrong.
//
// 能红: in instanceCandidates, delete the `if b.CredentialID != ""` clause.
func TestFence_6F7_CredentialBoundBackendNeverFansOutAcrossInstances(t *testing.T) {
	b := threeInstances()
	b.CredentialID = "cred-1"

	sessions := NewSessionStore(0)
	sess, err := sessions.Create("default", "org", "seat", mcpwire.SupportedProtocolVersions[0], mcpwire.Implementation{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Every call, sessioned or not, must land on the approved address. 32 rounds
	// so a round-robin over three instances could not pass by luck.
	for i := 0; i < 32; i++ {
		got, selErr := selectInstance(sessions, sess.ID, b)
		if selErr != nil {
			t.Fatalf("round %d: unexpected refusal: %v", i, selErr.Detail)
		}
		if got != b.EndpointURL {
			t.Fatalf("round %d: a credential-bound backend was dialled at %q, which is NOT its approved "+
				"address %q. A registry that adds an instance must never receive the customer's credential.",
				i, got, b.EndpointURL)
		}
		if got, selErr = selectInstance(sessions, "", b); selErr != nil || got != b.EndpointURL {
			t.Fatalf("round %d: sessionless call went to %q (err=%v), want the approved address %q",
				i, got, selErr, b.EndpointURL)
		}
	}
}

// TestFence_6F4_SessionPinnedToARetiredInstanceFailsRatherThanReassigning.
//
// R5: 实例不健康时让会话失败并给出明确错误，不许静默改派. MCP is stateful — the
// upstream holds this session's state on ONE instance — so moving a live session
// to a sibling produces "session not found" from a server the client never
// talked to, and the address is the LAST thing anybody suspects.
//
// The fence also asserts the pin is NOT dropped on failure: dropping it would
// let the very next call re-allocate, which is the same silent reassignment
// arriving one call later.
//
// 能红: in selectInstance, replace the refusal with a re-allocation, or make the
// failure path delete the pin.
func TestFence_6F4_SessionPinnedToARetiredInstanceFailsRatherThanReassigning(t *testing.T) {
	b := threeInstances()
	sessions := NewSessionStore(0)
	sess, err := sessions.Create("default", "org", "seat", mcpwire.SupportedProtocolVersions[0], mcpwire.Implementation{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	first, selErr := selectInstance(sessions, sess.ID, b)
	if selErr != nil {
		t.Fatalf("first call must succeed, got %v", selErr.Detail)
	}
	// The session is now pinned. The registry retires that instance.
	shrunk := b
	shrunk.Instances = nil
	for _, inst := range b.Instances {
		if inst != first {
			shrunk.Instances = append(shrunk.Instances, inst)
		}
	}
	shrunk.EndpointURL = shrunk.Instances[0]

	got, selErr := selectInstance(sessions, sess.ID, shrunk)
	if selErr == nil {
		t.Fatalf("the session was pinned to %q, which the registry no longer advertises, and the call "+
			"was SILENTLY REASSIGNED to %q. R5 requires a clear failure: a moved session gets "+
			"\"session not found\" from an instance it never initialised against.", first, got)
	}
	if selErr.Code != mcpwire.ErrBackendUnavailable {
		t.Errorf("refusal code = %q, want %q", selErr.Code, mcpwire.ErrBackendUnavailable)
	}
	if !selErr.NotAccepted {
		t.Error("the refusal must be NotAccepted: the request never left this process, so a " +
			"non-idempotent tool certainly did not run, and the client may safely retry (R4)")
	}
	if !strings.Contains(selErr.Detail, "initialize") {
		t.Errorf("the refusal must name the remedy (run initialize again), got %q", selErr.Detail)
	}

	// And the pin survives the failure — the next call must NOT quietly succeed
	// somewhere else.
	if _, selErr = selectInstance(sessions, sess.ID, shrunk); selErr == nil {
		t.Fatal("the pin was dropped by the failed call, so the NEXT call re-allocated. That is the " +
			"same silent reassignment R5 forbids, one call later. The pin dies with the session.")
	}
}

// TestFence_6F4_ASessionKeepsItsInstanceAcrossCalls.
//
// The positive half of R5: once pinned, every later call in the session goes to
// the same instance even though the list has three.
//
// 能红 (TWO-POINT — a single mutation cannot make this one fail, and the reason
// is worth knowing before someone reports it as a vacuous fence):
// stickiness is held by two independent mechanisms, and either alone is enough.
// selectInstance returns early on a pin it finds, AND SessionStore.PinInstance
// is first-write-wins, so an allocation that runs anyway still ends up returning
// the original pin. Both are deliberate — the early return avoids a pointless
// allocation, first-write-wins settles a race between two concurrent first calls
// — so the redundancy is a design property, not a leftover.
//
// To drill it, break BOTH: neuter the StickyInstance early return in
// selectInstance AND make PinInstance overwrite unconditionally. Drilled
// 2026-09-03, red on the two-point mutation, green on either alone.
func TestFence_6F4_ASessionKeepsItsInstanceAcrossCalls(t *testing.T) {
	b := threeInstances()
	sessions := NewSessionStore(0)
	sess, err := sessions.Create("default", "org", "seat", mcpwire.SupportedProtocolVersions[0], mcpwire.Implementation{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	first, selErr := selectInstance(sessions, sess.ID, b)
	if selErr != nil {
		t.Fatalf("first call: %v", selErr.Detail)
	}
	for i := 0; i < 32; i++ {
		got, selErr := selectInstance(sessions, sess.ID, b)
		if selErr != nil {
			t.Fatalf("call %d: %v", i, selErr.Detail)
		}
		if got != first {
			t.Fatalf("call %d went to %q but the session was pinned to %q. MCP is stateful; a session "+
				"that moves loses the state the upstream minted for it.", i, got, first)
		}
	}
}

// TestFence_6F4_AnEmptyInstanceListBehavesExactlyAsBeforeAlpha12.
//
// Every backend that predates alpha.12, every hand-registered backend, and every
// stdio backend has an empty list. Those must be dialled at endpoint_url with no
// pin taken and no allocation — that is what makes this feature safe to ship for
// customers who run no service registry at all.
//
// 能红: in selectInstance, drop the `len(candidates) < 2` short-circuit.
func TestFence_6F4_AnEmptyInstanceListBehavesExactlyAsBeforeAlpha12(t *testing.T) {
	sessions := NewSessionStore(0)
	sess, err := sessions.Create("default", "org", "seat", mcpwire.SupportedProtocolVersions[0], mcpwire.Implementation{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	for _, b := range []PolicyBackend{
		{ID: "http", Name: "http", Transport: TransportStreamableHTTP, EndpointURL: "http://10.0.0.9:9000/mcp"},
		{ID: "stdio", Name: "stdio", Transport: TransportStdio, Command: "npx"},
	} {
		got, selErr := selectInstance(sessions, sess.ID, b)
		if selErr != nil {
			t.Fatalf("backend %q: unexpected refusal %v", b.ID, selErr.Detail)
		}
		if got != b.EndpointURL {
			t.Fatalf("backend %q was dialled at %q, want its endpoint_url %q", b.ID, got, b.EndpointURL)
		}
		if _, pinned := sessions.StickyInstance(sess.ID, b.ID); pinned {
			t.Errorf("backend %q took a session pin although it has one address. A pin over a "+
				"single-address backend can only ever produce a refusal later.", b.ID)
		}
	}
}

// TestFence_6F4_SessionlessCallsAreSpreadAcrossInstances.
//
// R5's last line: 无会话的调用才走分配. Without this the list would be carried,
// stored and shipped to the fleet, and then every call would still land on
// instances[0] — the feature would look delivered and do nothing.
//
// 能红: in selectInstance, return candidates[0] for the sessionless branch.
func TestFence_6F4_SessionlessCallsAreSpreadAcrossInstances(t *testing.T) {
	b := threeInstances()
	seen := map[string]int{}
	for i := 0; i < 60; i++ {
		got, selErr := selectInstance(nil, "", b)
		if selErr != nil {
			t.Fatalf("call %d: %v", i, selErr.Detail)
		}
		seen[got]++
	}
	if len(seen) != len(b.Instances) {
		t.Fatalf("60 sessionless calls reached %d of %d instances (%v). Calls with no session are the "+
			"only ones that may be allocated, and they must actually be.", len(seen), len(b.Instances), seen)
	}
}
