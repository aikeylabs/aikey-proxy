package proxy

// chain_app_test.go — the App pipeline's candidate chain (openspec change
// `aliyun-aigw-p0-upstream-fallback`, task 2.0b / decision F-19 · D-5) and the
// entry-coverage fence that keeps every serving entry honest (I35 / I36 / I37).

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// appChainFixture builds a proxy holding one team VK with a two-hop group, plus
// the App-shaped ResolvedRoute that handleAppPipeline would have constructed.
func appChainFixture(t *testing.T) (*Proxy, *vkeys.ResolvedRoute) {
	t.Helper()
	p := setupTestProxy(t, "http://unused.invalid")

	primary := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-app-team", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		BaseURL: "https://primary.invalid", PlaintextKey: "key-primary",
		BindingID: "b-primary", CredentialID: "cred-primary",
		OrgID: "org-1", SeatID: "seat-1",
		Priority: 1, FallbackRole: "primary", RouteGroupID: "rg-app", RouteGroupName: "main",
	}
	fallback := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-app-team", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "zhipu", RouteSource: "team",
		BaseURL: "https://fallback.invalid", PlaintextKey: "key-fallback",
		BindingID: "b-fallback", CredentialID: "cred-fallback",
		OrgID: "org-1", SeatID: "seat-1",
		Priority: 2, FallbackRole: "fallback", RouteGroupID: "rg-app", RouteGroupName: "main",
	}
	container := *primary
	container.Bindings = []*vkeys.ResolvedRoute{primary, fallback}
	container.BaseURL = ""
	container.PlaintextKey = ""
	container.ProviderCode = ""
	container.ProtocolType = ""
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_vk-app-team": &container})

	// What handleAppPipeline builds: a synthetic `app:<slug>` virtual key plus the
	// app-only state (observer context, app identity, protocol family).
	appRoute := &vkeys.ResolvedRoute{
		VirtualKeyID:   "app:my-agent",
		RouteSource:    "app",
		AppSlug:        "my-agent",
		AppKind:        "third-party",
		AppKeyID:       "ak-1",
		ProtocolFamily: "anthropic",
		Provider:       "anthropic",
		ProviderCode:   "anthropic",
		ProtocolType:   "anthropic",
		BaseURL:        "https://primary.invalid",
		PlaintextKey:   "key-primary",
		ObserverContext: &observer.RequestContext{
			AppSlug: "my-agent", AppKeyID: "ak-1",
		},
	}
	return p, appRoute
}

func appPin(routeGroupID, providerCode string) *vault.ProviderBinding {
	return &vault.ProviderBinding{
		ClientRoute:   "anthropic",
		ProviderCode:  providerCode,
		ProtocolType:  "anthropic",
		KeySourceType: "team",
		KeySourceRef:  "vk-app-team",
		RouteGroupID:  routeGroupID,
	}
}

// ── F-19 · D-5: an App-routed team VK with a group DOES fail over ───────────
//
// This is the decision's whole point. Without it, an administrator configures a
// chain, sees it in the console, and the App surface silently ignores it —
// 「配了但没生效」 on a correctly configured path.
func TestAppChain_GroupedTeamVKGetsTheChain(t *testing.T) {
	p, appRoute := appChainFixture(t)

	chain := p.appChain(appRoute, appPin("rg-app", ""), "anthropic", nil)
	if chain == nil {
		t.Fatal("an App-routed team VK with a route group got no chain — this is exactly the " +
			"「配了但没生效」 failure F-19 was decided to prevent")
	}
	if !chain.canFailover() {
		t.Fatalf("chain cannot fail over: pinned=%v candidates=%d", chain.pinned, len(chain.candidates))
	}
	if len(chain.candidates) != 2 {
		t.Fatalf("got %d candidates, want 2", len(chain.candidates))
	}
	if got := chain.candidates[0].ProviderCode; got != "anthropic" {
		t.Errorf("hop 1 provider = %q, want anthropic (priority order must be the admin's)", got)
	}
	if got := chain.candidates[1].ProviderCode; got != "zhipu" {
		t.Errorf("hop 2 provider = %q, want zhipu", got)
	}
}

// ── The overlay: every hop is the APP's route with only the upstream swapped ──
//
// 能红: replace applyHopToAppRoute's field list with `*dst = *hop` → the app
// fields below all revert to the team route's values.
//
// 🔴 Why this needs a fence at all: dropping ObserverContext or the synthetic
// `app:` virtual key still returns 200. The App's usage events would quietly
// re-attribute to the team VK and the plugin fan-out would go silent, with
// nothing in the response to say so.
func TestAppChain_HopsKeepEveryAppScopedField(t *testing.T) {
	p, appRoute := appChainFixture(t)

	chain := p.appChain(appRoute, appPin("rg-app", ""), "anthropic", nil)
	if chain == nil {
		t.Fatal("no chain")
	}
	for i, hop := range chain.candidates {
		if hop.VirtualKeyID != "app:my-agent" {
			t.Errorf("hop %d VirtualKeyID = %q, want app:my-agent. Letting the team VK id through "+
				"silently re-attributes this app's spend to the team key", i+1, hop.VirtualKeyID)
		}
		if hop.RouteSource != "app" {
			t.Errorf("hop %d RouteSource = %q, want app", i+1, hop.RouteSource)
		}
		if hop.AppSlug != "my-agent" || hop.AppKeyID != "ak-1" {
			t.Errorf("hop %d lost its app identity: slug=%q keyid=%q", i+1, hop.AppSlug, hop.AppKeyID)
		}
		if hop.ProtocolFamily != "anthropic" {
			t.Errorf("hop %d ProtocolFamily = %q — the App pipeline resolves this from the "+
				"path-aware base_url row and the team route's copy is not app-aware", i+1, hop.ProtocolFamily)
		}
		if hop.ObserverContext == nil {
			t.Errorf("hop %d lost ObserverContext — the plugin observer fan-out goes silent "+
				"and the request still returns 200", i+1)
		}
	}

	// …and the per-upstream fields ARE swapped (2.3 / I5).
	if chain.candidates[1].BaseURL != "https://fallback.invalid" {
		t.Errorf("hop 2 BaseURL = %q, want the fallback's own address", chain.candidates[1].BaseURL)
	}
	if chain.candidates[1].PlaintextKey != "key-fallback" {
		t.Error("hop 2 did not get its OWN credential — reusing hop 1's key against hop 2's " +
			"address fails in a way that looks exactly like the upstream being down")
	}
	if chain.candidates[1].BindingID != "b-fallback" {
		t.Errorf("hop 2 BindingID = %q, want b-fallback (cooldown is keyed on it)", chain.candidates[1].BindingID)
	}
}

// ── An explicit member pin still means "only this one" on the App surface ────
//
// D-1③ / F-16④ decided that pinning one hop disables failover and must be said
// out loud. Honouring that on the CLI and ignoring it here would give the same
// pin two meanings depending on which surface reads it.
func TestAppChain_MemberPinSuppressesFailover(t *testing.T) {
	p, appRoute := appChainFixture(t)

	chain := p.appChain(appRoute, appPin("rg-app", "zhipu"), "anthropic", nil)
	if chain == nil {
		t.Fatal("no chain")
	}
	if chain.canFailover() {
		t.Error("a member-pinned app still failed over — the pin means 只用这家")
	}
	if len(chain.candidates) != 1 || chain.candidates[0].ProviderCode != "zhipu" {
		t.Fatalf("member pin did not restrict to the pinned hop: %d candidates", len(chain.candidates))
	}
	// Still an app route, even when pinned.
	if chain.candidates[0].VirtualKeyID != "app:my-agent" {
		t.Errorf("pinned hop VirtualKeyID = %q, want app:my-agent", chain.candidates[0].VirtualKeyID)
	}
}

// ── 🔴 The app reads its OWN pin row, never the default profile's ───────────
//
// 能红: make chainFrom look the pin up internally again (via
// activeReader.GetProviderBinding, which is hard-coded to profile 'default') →
// one user's `aikey use --only` would start suppressing failover for every app
// on the machine.
//
// The fence works by passing a GROUP-scoped app pin while the proxy's
// default-profile reader would answer with something else entirely: the app pin
// must win, so the chain stays walkable.
func TestAppChain_UsesTheAppsOwnPinNotTheDefaultProfile(t *testing.T) {
	p, appRoute := appChainFixture(t)

	// The app's own row pins the GROUP → failover applies.
	chain := p.appChain(appRoute, appPin("rg-app", ""), "anthropic", nil)
	if chain == nil || !chain.canFailover() {
		t.Fatal("the app's own group-scoped pin did not produce a walkable chain")
	}

	// A member-scoped app row restricts it. Same registry, same team VK — the
	// ONLY input that changed is the app's row, which proves the decision is
	// taken from the row the caller supplies.
	pinned := p.appChain(appRoute, appPin("rg-app", "zhipu"), "anthropic", nil)
	if pinned == nil || pinned.canFailover() {
		t.Fatal("the app's own member-scoped pin was not honoured")
	}
}

// ── Sources with no chain fall through to single-shot, not to an error ──────
//
// 🔴 Returning an error would break the App pipeline for every installation that
// never configured failover — which is most of them.
func TestAppChain_SourcesWithoutAChainReturnNil(t *testing.T) {
	p, appRoute := appChainFixture(t)

	for _, tc := range []struct {
		name    string
		binding *vault.ProviderBinding
		why     string
	}{
		{
			name:    "personal alias",
			binding: &vault.ProviderBinding{KeySourceType: "alias", KeySourceRef: "claude"},
			why:     "a personal alias has no chain (2.0b: 没有链)",
		},
		{
			name:    "oauth account",
			binding: &vault.ProviderBinding{KeySourceType: "personal_oauth_account", KeySourceRef: "acc-1"},
			why:     "the ACCOUNT axis already owns failover here; a second loop around it is the multiplicative nesting 2.1 forbids",
		},
		{
			name:    "unknown virtual key",
			binding: &vault.ProviderBinding{KeySourceType: "team", KeySourceRef: "vk-does-not-exist"},
			why:     "a stale app binding must surface at the upstream, not as a chain error",
		},
		{
			name:    "empty source ref",
			binding: &vault.ProviderBinding{KeySourceType: "team", KeySourceRef: ""},
			why:     "an empty ref must not be concatenated into a degenerate token",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.appChain(appRoute, tc.binding, "anthropic", nil); got != nil {
				t.Errorf("got a chain for %s — %s", tc.name, tc.why)
			}
		})
	}

	if got := p.appChain(nil, appPin("rg-app", ""), "anthropic", nil); got != nil {
		t.Error("a nil app route produced a chain")
	}
	if got := p.appChain(appRoute, nil, "anthropic", nil); got != nil {
		t.Error("a nil app binding produced a chain")
	}
}

// ── 🔴 Entry coverage (I35 / I36 / I37) ────────────────────────────────────
//
// Task 2.0b enumerated FIVE serving entry functions and gave a per-entry verdict.
// The two failure modes it names are both invisible to behavioral tests:
//
//   - a serving entry that should walk the chain and does not → the same key
//     fails over on one URL shape and not another, and nobody debugging it
//     thinks to suspect the URL prefix;
//   - the PROBE entry walking the chain → `aikey doctor` reports "healthy"
//     while the primary upstream is down. We would have built a health check
//     that lies.
//
// So the verdict table is asserted against the source. 能红: delete the
// serveManagedChain call from any hooked entry, or add one to the probe entry.
func TestChain_HangsOnExactlyTheIntendedEntries(t *testing.T) {
	want := map[string]bool{
		// 🔴 Both team-VK direct-connect entries. They do the SAME thing and
		// differ only in the URL shape the client used.
		"Handle":                true,
		"handlePathPrefixRoute": true,
		// 🔴 F-19 · D-5, signed off 2026-07-30.
		"handleAppPipeline": true,
		// 🔴 Never. The probe's whole job is to report truthfully whether THIS
		// hop is reachable.
		"handleProbePipeline": false,
		// The account axis owns failover for group VKs; it already has it.
		"handleOauthGroupRoute": false,
	}

	bodies := map[string]string{}
	for _, file := range []string{"handle_dispatch.go", "pipelines.go", "group_serve.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(src)
		funcStart := regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?([A-Za-z0-9_]+)\(`)
		locs := funcStart.FindAllStringSubmatchIndex(text, -1)
		for i, loc := range locs {
			end := len(text)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			bodies[text[loc[2]:loc[3]]] = text[loc[0]:end]
		}
	}

	for name, shouldHook := range want {
		body, ok := bodies[name]
		if !ok {
			t.Errorf("entry function %s not found — did it move or get renamed? "+
				"This fence is the only record of the 2.0b verdict table", name)
			continue
		}
		hooks := strings.Contains(body, "serveManagedChain(")
		switch {
		case shouldHook && !hooks:
			t.Errorf("%s does NOT hang the candidate loop but must (task 2.0b).\n"+
				"A team VK with a route group configured will fail over on the other entries "+
				"and not on this one — same key, same chain, different URL shape — and the "+
				"console will keep showing a chain that is inert here.", name)
		case !shouldHook && hooks:
			t.Errorf("%s hangs the candidate loop but must NOT (task 2.0b).\n"+
				"For the probe entry this is the worst case in the whole change: a health "+
				"check that reports OK while the primary upstream is down.", name)
		}
	}
}
