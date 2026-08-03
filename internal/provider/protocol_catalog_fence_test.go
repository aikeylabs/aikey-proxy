package provider

import (
	"sort"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/providerregistry"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// I-7 (task P1c.8 / test-plan T-9): every protocol the console can offer must
// resolve to a real forwarding adapter in THIS binary.
//
// # Why this fence exists, and why it must stay
//
// `gemini` had a route row, had observability vocabulary (vkeys/types.go,
// observer/conversation_audit, stream_accumulator) — and no adapter. The
// registry only ever registers openai / anthropic / kimi / generic, so
// Get("gemini") returns `unknown provider protocol` and all nine forwarding call
// sites answer 502. The console offered "Google Gemini" anyway, so an
// administrator could build a credential that was guaranteed to fail on its
// first real request. Nothing compared the two sets, so nothing failed.
//
// This fence is that comparison. It is worth more in the FUTURE than today:
// the moment somebody adds a `bedrock` row, or re-adds `gemini` after deciding
// the adapter exists, the PR goes red with the reason.
//
// 🚫 There is deliberately NO hand-written exclusion list. The console's
// protocol catalog is DERIVED — protocols of route rows whose provider is
// picker-visible in provider_registry.yaml — so hiding google (R-8:
// `picker: false`) removes `gemini` from the catalog automatically. A
// hard-coded "except gemini" here would be a second source of truth that keeps
// passing after somebody flips google back to picker: true.
func TestFence_I7_EveryOfferedProtocolHasAnAdapter(t *testing.T) {
	catalog := consoleProtocolCatalog(t)
	if len(catalog) == 0 {
		t.Fatal("derived protocol catalog is EMPTY — anti-vacuous assertion; an empty catalog would make this fence pass by asserting nothing")
	}

	reg := NewRegistry()
	for _, protocol := range catalog {
		if _, err := reg.Get(protocol); err != nil {
			t.Errorf("protocol %q is offered by the credential dialog but this binary has NO adapter for it: %v\n"+
				"  → an administrator can create a credential that 502s on its very first real request.\n"+
				"  Fix by EITHER implementing the adapter (register it in NewRegistry) OR taking the\n"+
				"  protocol out of the console's reach — set `picker: false` on every provider that is\n"+
				"  the protocol's only carrier in provider_registry.yaml, as R-8 did for google/gemini.",
				protocol, err)
		}
	}
	t.Logf("offered protocols: %v", catalog)
}

// TestFence_I7_GeminiIsStillOutOfReach pins the specific R-8 outcome, so the
// derivation above cannot quietly start including a protocol we know is dead.
//
// This is NOT a duplicate of the fence above: that one asks "is everything we
// offer implemented", this one asks "is the thing we know is unimplemented
// still hidden". Flipping google back to picker: true reds HERE with the
// history, and reds above with the mechanism.
func TestFence_I7_GeminiIsStillOutOfReach(t *testing.T) {
	// The premise: gemini genuinely has no adapter. If somebody implements one,
	// this test should be deleted, not muted.
	if _, err := NewRegistry().Get("gemini"); err == nil {
		t.Skip("a gemini adapter now exists — delete this fence and put gemini back in the registry picker")
	}
	for _, protocol := range consoleProtocolCatalog(t) {
		if protocol == "gemini" {
			t.Error("`gemini` is back in the console's protocol catalog while this binary still has no gemini adapter.\n" +
				"  Every credential created through that option 502s on its first request, and `probeGoogle`\n" +
				"  does not go through the Registry, so the connectivity probe will show GREEN while\n" +
				"  forwarding 502s — a lying green light is worse than no green light.\n" +
				"  See openspec/changes/provider-credential-cascade/defect-gemini-no-adapter.md")
		}
	}
}

// consoleProtocolCatalog reproduces, in Go, exactly what the web codegen emits
// as PROTOCOL_CATALOG: the distinct protocols of route rows whose provider is
// picker-visible.
//
// Keeping this derivation in one small function (rather than inlining it twice)
// is the point — if the codegen's rule changes, this is the single place that
// has to change with it, and the cross-language parity test (T-10..T-12) is what
// proves they still agree.
func consoleProtocolCatalog(t *testing.T) []string {
	t.Helper()
	reg := providerregistry.Default()
	seen := map[string]bool{}
	var out []string
	for _, r := range providerroutes.Default().All() {
		e, ok := reg.Lookup(r.Provider)
		if !ok || !e.Picker {
			continue // not reachable from the credential dialog
		}
		p := strings.ToLower(r.Protocol)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// TestFence_LegacyCredentialsSurviveASecondProtocolFace guards the regression
// this change nearly shipped.
//
// Adding an `anthropic` row to a provider that previously had only an
// `openai_compatible` one makes ProtocolsForProvider return two values. The old
// "exactly one protocol → use it" fallback then produced ("", false), and every
// credential whose protocol_type predates the two-axis model — 19 such rows on
// staging alone — would have started answering
// `502 Unknown provider protocol: `.
//
// It surfaced only because ONE unrelated test (TestProviderDefaultBaseURL_Moonshot)
// happened to assert a concrete URL for moonshot. Nothing was asserting the
// property itself, so four of the five affected providers had no coverage at
// all, and zhipu had been broken this way since 2026-05 with nobody looking.
// This fence asserts the property directly, for every provider in the table.
func TestFence_LegacyCredentialsSurviveASecondProtocolFace(t *testing.T) {
	tbl := providerroutes.Default()
	seen := map[string]bool{}
	checked := 0
	for _, r := range tbl.All() {
		if seen[r.Provider] {
			continue
		}
		seen[r.Provider] = true

		// The question a protocol-less legacy credential asks.
		protocol, ok := ProtocolFamily(r.Provider, "")
		if !ok {
			// Legitimate only when the provider never HAD a protocol-less era —
			// i.e. it has no bare-host row, so no credential could have been
			// created against it before protocol became explicit.
			bareHost := false
			for _, row := range tbl.All() {
				if row.Provider == r.Provider && row.PathPrefix == "" {
					bareHost = true
					break
				}
			}
			if bareHost {
				t.Errorf("provider %q has a bare-host row but ProtocolFamily(%q, \"\") fails.\n"+
					"  Every credential on it whose protocol_type is empty now answers\n"+
					"  `502 Unknown provider protocol: `. This is what adding a second\n"+
					"  protocol face does if the protocol-less fallback is not handled.",
					r.Provider, r.Provider)
			}
			continue
		}
		checked++

		// And, for providers the console can still create credentials for, the
		// answer must be a protocol this binary can actually forward.
		//
		// 🔴 Scoped to picker-visible providers ON PURPOSE. Unscoped, this
		// assertion reds on `google` → `gemini` → no adapter — which is TRUE, but
		// it is the pre-existing defect R-8 deliberately does NOT fix (it closes
		// the creation path, it does not implement Gemini). A fence that restates
		// a known, accepted, unfixed defect is red forever, and a permanently red
		// fence gets muted, taking the checks around it down with it.
		//
		// The set that matters here is "a 502 nobody has signed off on". For
		// google that 502 is signed off and filed:
		// openspec/changes/provider-credential-cascade/defect-gemini-no-adapter.md
		if e, known := providerregistry.Default().Lookup(r.Provider); known && !e.Picker {
			continue
		}
		if _, err := NewRegistry().Get(protocol); err != nil {
			t.Errorf("ProtocolFamily(%q, \"\") resolved to %q, which has NO adapter: %v\n"+
				"  %q is picker-visible, so an administrator can create this credential today\n"+
				"  and it 502s on its first request.", r.Provider, protocol, err, r.Provider)
		}
	}
	if checked == 0 {
		t.Fatal("no provider resolved a protocol-less credential — anti-vacuous assertion")
	}
	t.Logf("%d provider(s) resolve a protocol-less credential", checked)
}

// I-2 (task P4.2 / test-plan T-21): the URL the dialog SHOWS must be the URL the
// proxy EXECUTES.
//
// # Why ok=true is not the assertion
//
// The tempting check is "LookupByBaseURL finds a row". It finds one for almost
// anything: a host's catch-all row matches every path. deepseek's two URLs both
// resolve — but if `/anthropic` were mistyped as `/anthropic-api`, the anthropic
// URL would quietly land on the OpenAI fallback row. ok=true, wrong protocol,
// no error anywhere, and an Anthropic-shaped body posted to an OpenAI endpoint.
//
// So this asserts WHICH row: same protocol, same provider, for every single
// (provider, protocol) pair the credential dialog can offer.
func TestFence_I2_ShownURLResolvesToTheRowThatProducedIt(t *testing.T) {
	tbl := providerroutes.Default()
	reg := providerregistry.Default()

	checked := 0
	for _, r := range tbl.All() {
		e, known := reg.Lookup(r.Provider)
		if !known || !e.Picker {
			continue // not offerable in the dialog
		}
		// Every endpoint the dialog can put in the box for this pair.
		for _, row := range tbl.All() {
			if !strings.EqualFold(row.Provider, r.Provider) || !strings.EqualFold(row.Protocol, r.Protocol) {
				continue
			}
			url := providerroutes.EffectiveUpstream(row)
			hit, ok := tbl.LookupByBaseURL(url)
			if !ok {
				t.Errorf("%s × %s: the dialog would show %q, which resolves to NO row — the proxy would fall back to a degraded literal-prepend stitch",
					row.Provider, row.Protocol, url)
				continue
			}
			checked++
			if !strings.EqualFold(hit.Protocol, row.Protocol) {
				t.Errorf("🔴 SHOWN ≠ EXECUTED for %q:\n  the dialog offers it as protocol %s (provider %s)\n  the proxy resolves it to protocol %s (provider %s, row %s%s)\n  → the request body would be rewritten for the wrong wire format",
					url, row.Protocol, row.Provider, hit.Protocol, hit.Provider, hit.Host, hit.PathPrefix)
			}
			if !strings.EqualFold(hit.Provider, row.Provider) {
				t.Errorf("provider mismatch for %q: dialog says %s, proxy resolves %s", url, row.Provider, hit.Provider)
			}
			// And the protocol it resolves to must be one this binary can forward.
			if _, err := NewRegistry().Get(hit.Protocol); err != nil {
				t.Errorf("%q resolves to protocol %q which has no adapter: %v", url, hit.Protocol, err)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no offerable endpoint checked — anti-vacuous assertion")
	}
	t.Logf("%d offerable endpoint(s) resolve to the row that produced them", checked)
}
