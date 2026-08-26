package supervisor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// revocationServer serves the two real endpoints this rail consumes.
// snapshotBody is a raw JSON string so a test can reproduce the EXACT wire shape
// the live control plane produced, field names and all.
func revocationServer(t *testing.T, version int64, snapshotBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case syncVersionPath:
			_, _ = fmt.Fprintf(w, `{"account_id":"acct-1","sync_version":%d}`, version)
		case managedKeysSnapshotPath:
			_, _ = fmt.Fprint(w, snapshotBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newRevocationHarness(t *testing.T) (*Supervisor, *generation) {
	t.Helper()
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	dbPath, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-a", "seat": "seat-1", "group": "", "override": ""},
	})
	cfg := &config.Config{}
	cfg.Vault.Path = dbPath
	s := &Supervisor{
		cfg:              cfg,
		routingOverrides: proxy.NewRoutingOverrideCache(),
		teamCred:         &teamCredentialSource{},
		ctx:              context.Background(),
	}
	gen := &generation{vault: reader, registry: vkeys.NewRegistry()}
	s.active.Store(gen)
	return s, gen
}

// 🔴 THE TRAP THIS RAIL EXISTS TO AVOID.
//
// Live on a real tenant (2026-08-26): suspending a member's SEAT left the
// virtual key's own key_status at "active" and moved only effective_status to
// "inactive" (effective_reason "seat_disabled"). A rail keyed on key_status
// polls, parses and decides "nothing to do" — green, and completely blind.
//
// 能红: change syncKeyRevocation to read k.KeyStatus (or to compare against
// anything other than effective_status) and this test fails with an empty set.
func TestKeyRevocationUsesEffectiveStatus(t *testing.T) {
	s, gen := newRevocationHarness(t)
	// Byte-for-byte the shape the live control plane returned.
	body := `{"sync_version":6,"key_delivery_form":"local","keys":[
		{"virtual_key_id":"vk-a","seat_id":"seat-1",
		 "key_status":"active","effective_status":"inactive","effective_reason":"seat_disabled"}]}`
	srv := revocationServer(t, 6, body)
	defer srv.Close()

	if err := s.syncKeyRevocation(context.Background(), gen, srv.URL, "bearer-1"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !s.revokedVKs()["vk-a"] {
		t.Fatalf("vk-a must be revoked: the seat is disabled. Got set %v. "+
			"If this reads key_status (\"active\") instead of effective_status "+
			"(\"inactive\"), the whole rail is a no-op.", s.revokedVKs())
	}
}

// An active key must NOT be revoked — the fence above must not be satisfiable
// by a rail that simply revokes everything it sees.
func TestKeyRevocationLeavesActiveKeyAlone(t *testing.T) {
	s, gen := newRevocationHarness(t)
	body := `{"sync_version":7,"keys":[
		{"virtual_key_id":"vk-a","seat_id":"seat-1",
		 "key_status":"active","effective_status":"active","effective_reason":""}]}`
	srv := revocationServer(t, 7, body)
	defer srv.Close()

	if err := s.syncKeyRevocation(context.Background(), gen, srv.URL, "bearer-1"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(s.revokedVKs()) != 0 {
		t.Fatalf("no key should be revoked, got %v", s.revokedVKs())
	}
}

// 🔴 An empty key list is not evidence. A wrong account, a wrong endpoint or a
// projection that failed to refresh all look exactly like "you have no keys",
// and acting on it would drop every team route on the machine.
//
// 能红: replace the len(snap.Keys)==0 guard with a plain rebuild and the
// previously-known revocation set is wiped — this test fails.
func TestKeyRevocationEmptySnapshotKeepsLastKnownSet(t *testing.T) {
	s, gen := newRevocationHarness(t)

	first := revocationServer(t, 6, `{"sync_version":6,"keys":[
		{"virtual_key_id":"vk-a","effective_status":"inactive","effective_reason":"seat_disabled"}]}`)
	if err := s.syncKeyRevocation(context.Background(), gen, first.URL, "b"); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	first.Close()
	if !s.revokedVKs()["vk-a"] {
		t.Fatalf("precondition: vk-a should be revoked after the first sync")
	}

	empty := revocationServer(t, 9, `{"sync_version":9,"keys":[]}`)
	defer empty.Close()
	if err := s.syncKeyRevocation(context.Background(), gen, empty.URL, "b"); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if !s.revokedVKs()["vk-a"] {
		t.Fatalf("an empty snapshot must not clear a known revocation; got %v", s.revokedVKs())
	}
}

// The version probe must not be able to report success without ever having
// resolved a snapshot. 能红: drop the `revokedVKIDs.Load() != nil` half of the
// cheap-path guard and a control plane sitting at sync_version 0 leaves the rail
// green and blind — this test fails because vk-a is never revoked.
func TestKeyRevocationFirstCycleFetchesSnapshotEvenAtVersionZero(t *testing.T) {
	s, gen := newRevocationHarness(t)
	srv := revocationServer(t, 0, `{"sync_version":0,"keys":[
		{"virtual_key_id":"vk-a","effective_status":"inactive","effective_reason":"seat_disabled"}]}`)
	defer srv.Close()

	if err := s.syncKeyRevocation(context.Background(), gen, srv.URL, "b"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !s.revokedVKs()["vk-a"] {
		t.Fatalf("the first cycle must fetch the snapshot even when sync_version is 0")
	}
}

// A control-plane failure must never widen into "drop every route".
func TestKeyRevocationTransportFailureKeepsLastKnownSet(t *testing.T) {
	s, gen := newRevocationHarness(t)
	srv := revocationServer(t, 6, `{"sync_version":6,"keys":[
		{"virtual_key_id":"vk-a","effective_status":"inactive"}]}`)
	if err := s.syncKeyRevocation(context.Background(), gen, srv.URL, "b"); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	srv.Close() // the control plane goes away

	err := s.syncKeyRevocation(context.Background(), gen, srv.URL, "b")
	if err == nil {
		t.Fatalf("an unreachable control plane must surface as a rail failure, not as success")
	}
	if !s.revokedVKs()["vk-a"] {
		t.Fatalf("the last known revocation must survive an outage; got %v", s.revokedVKs())
	}
}

// The filter has to bite where a managed key becomes a route — otherwise the
// rail computes a correct set that nothing consumes.
func TestBuildManagedRoutesDropsRevokedVirtualKeys(t *testing.T) {
	keys := []vault.ManagedKey{
		{VirtualKeyID: "vk-live", SeatID: "seat-1", ProviderCode: "anthropic", ProtocolType: "anthropic", BaseURL: "https://x", PlaintextKey: "k1"},
		{VirtualKeyID: "vk-dead", SeatID: "seat-2", ProviderCode: "anthropic", ProtocolType: "anthropic", BaseURL: "https://x", PlaintextKey: "k2"},
	}
	routes := buildManagedRoutes(keys, map[string]bool{"vk-dead": true})

	var live, dead bool
	for token := range routes {
		if strings.Contains(token, "vk-live") {
			live = true
		}
		if strings.Contains(token, "vk-dead") {
			dead = true
		}
	}
	if !live {
		t.Fatalf("the live key must still route; got tokens %v", routes)
	}
	if dead {
		t.Fatalf("the revoked key must NOT be routable; got tokens %v", routes)
	}
	// A nil set is today's behavior: never a blanket outage.
	if got := buildManagedRoutes(keys, nil); len(got) != 2 {
		t.Fatalf("a nil revocation set must change nothing, got %d routes", len(got))
	}
}

// 🔴 Registration fence. Every other test here exercises a rail that, if it is
// not in the production railSet, never runs in a real proxy — a fully tested
// piece of dead code. 能红: drop s.keyRevocationRail() from newRailSet.
func TestKeyRevocationRailIsRegisteredInProduction(t *testing.T) {
	src, err := os.ReadFile("supervisor.go")
	if err != nil {
		t.Fatalf("read supervisor.go: %v", err)
	}
	text := string(src)
	idx := strings.Index(text, "newRailSet(")
	if idx < 0 {
		t.Fatalf("newRailSet( call not found — this fence no longer measures anything")
	}
	end := strings.Index(text[idx:], ")\n")
	if end < 0 || !strings.Contains(text[idx:idx+end], "s.keyRevocationRail()") {
		t.Fatalf("keyRevocationRail is not registered in the production railSet: %q", text[idx:idx+end])
	}
}

// The revocation window is a security property, not a tuning knob.
func TestKeyRevocationIntervalIsSixtySeconds(t *testing.T) {
	if keyRevocationPollInterval != 60*time.Second {
		t.Fatalf("keyRevocationPollInterval = %v, want 60s. This constant IS the "+
			"advertised upper bound on how long a suspended seat keeps routing; "+
			"changing it changes a security guarantee.", keyRevocationPollInterval)
	}
}
