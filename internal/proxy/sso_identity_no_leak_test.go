package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 🔴 FENCE I13 — AiKey itself puts no member identity onto an upstream request.
//
// The 2026-07-20 first-login change gave every SSO member three new identifying
// values: the Feishu union_id / open_id, the tenant_key, and a synthetic
// account handle (sso+<provider>.<digest>@sso.local). All three live in the
// control plane. None has any business on the wire to Anthropic or OpenAI:
//
//   - Anthropic's OAuth WAF reads unrecognized headers as "this is not a real
//     Claude Code session" and answers 429 with no X-RateLimit-Reset — a business
//     rejection that looks like rate limiting and is diagnosed as such for days.
//   - and quite apart from the WAF, shipping a customer's employee identifiers to
//     a third-party model provider is a data-collection surface nobody authorized.
//
// # SCOPE — read this before adding a case
//
// The fence covers what AiKey AUTHORS or ANNOTATES, in three layers:
//
//	L1 name rule   stripAikeyRequestHeaders — the whole X-Aikey-* namespace,
//	               so annotations that do not exist yet are covered too.
//	L2 value rule  scrubMemberIdentityHeaders — identity SHAPES under any header
//	               name, so header names that do not exist yet are covered too.
//	L3 body rule   injectMetadataUserIDIfAbsent refuses to write an identity-
//	               shaped value into the outbound body.
//
// It does NOT cover a client that types its own union_id into a chat message.
// The main path forwards the client body byte-for-byte on purpose (WAF
// fingerprint is byte-exact; oauth_inject.go's closing note documents that pool
// requests pass real client identity through deliberately). See
// member_identity_guard.go for the full argument. The earlier absolute phrasing
// —"no member identity reaches the upstream"— promised more than any code here
// can keep, which is the same false-safety shape as a compliance filter that
// reports "enabled" while the detector package never loaded.

// L1+L2. 🔴 MUTATION PROOF — verbatim runs, 2026-07-21. Re-run both before
// trusting this file.
//
//	(a) delete the scrubMemberIdentityHeaders(h) call below:
//	    --- FAIL: TestUpstreamRequest_CarriesNoMemberIdentity (0.00s)
//	        sso_identity_no_leak_test.go:91: header "X-Member-Union-Id" carries "on_8ed6aa" to the upstream
//	        sso_identity_no_leak_test.go:91: header "X-Trace-Owner" carries "@sso.local" to the upstream
//	        sso_identity_no_leak_test.go:91: header "X-Trace-Owner" carries "sso+feishu" to the upstream
//	    Note what is ABSENT: not one "identity header … survived" line. The value
//	    loop failed with the prefix loop still green — which is the whole point.
//	    Before 2026-07-21 every poisoned value sat on an X-Aikey-* header, so the
//	    value loop could not fail unless the prefix loop already had; it was a
//	    dead assertion manufacturing the appearance of a second layer.
//
//	(b) degrade stripAikeyRequestHeaders to a lone h.Del("X-Aikey-Union-Id"):
//	    --- FAIL: TestUpstreamRequest_CarriesNoMemberIdentity (0.00s)
//	        sso_identity_no_leak_test.go:87: identity header "X-Aikey-Seat-Id" survived and would reach the model provider
//	        sso_identity_no_leak_test.go:87: identity header "X-Aikey-Tenant-Key" survived and would reach the model provider
//	        sso_identity_no_leak_test.go:87: identity header "X-Aikey-Account-Id" survived and would reach the model provider
//	        sso_identity_no_leak_test.go:87: identity header "X-Aikey-Feishu-Token" survived and would reach the model provider
func TestUpstreamRequest_CarriesNoMemberIdentity(t *testing.T) {
	h := http.Header{}
	// Identity-shaped annotations inside the aikey namespace — L1 catches these.
	h.Set("X-Aikey-Union-Id", "on_8ed6aa67826108097d9ee1438163457c")
	h.Set("X-Aikey-Tenant-Key", "stub_tenant_key")
	h.Set("X-Aikey-Account-Email", "sso+feishu.f11625f5ed9c39bf2c63d742cf65e3cc@sso.local")
	h.Set("x-aikey-account-id", "c4f1aec0-326d-4f20-a20a-90fcc100af00")
	h.Set("X-Aikey-Feishu-Token", "u-stub-user-access-token")
	h.Set("X-Aikey-Seat-Id", "3e527d39-d5a8-46ee-a7ac-7ca2072e65b6")
	// Identity-shaped values OUTSIDE the aikey namespace. L1 is blind to these
	// by construction — they are the "next feature adds one header" leak the
	// review flagged, and only L2 stops them.
	h.Set("X-Member-Union-Id", "on_8ed6aa67826108097d9ee1438163457c")
	h.Set("X-Trace-Owner", "sso+feishu.f11625f5ed9c39bf2c63d742cf65e3cc@sso.local")
	// Headers the upstream legitimately needs — these must survive.
	h.Set("Authorization", "Bearer real-upstream-token")
	h.Set("Content-Type", "application/json")
	h.Set("anthropic-version", "2023-06-01")

	stripAikeyRequestHeaders(h)
	scrubMemberIdentityHeaders(h)

	for name, values := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-aikey-") {
			t.Errorf("identity header %q survived and would reach the model provider", name)
		}
		for _, v := range values {
			for _, forbidden := range []string{"on_8ed6aa", "@sso.local", "sso+feishu"} {
				if strings.Contains(v, forbidden) {
					t.Errorf("header %q carries %q to the upstream", name, forbidden)
				}
			}
		}
	}
	if h.Get("Authorization") != "Bearer real-upstream-token" ||
		h.Get("Content-Type") != "application/json" || h.Get("anthropic-version") != "2023-06-01" {
		t.Errorf("the scrub took a header the upstream needs: %#v", h)
	}
}

// L2 negative half. A guard that deletes everything also passes the test above,
// so pin what it must NOT touch — chiefly the credential headers it is
// deliberately exempt from scanning (a random Bearer can look like anything;
// dropping it would fail every request of that account).
func TestScrubMemberIdentityHeaders_LeavesLegitimateTrafficAlone(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer sk-ant-oat01-on_abcdefghijklmnopqrstuvwxyz012345")
	h.Set("X-Api-Key", "sk-on_abcdefghijklmnopqrstuvwxyz")
	h.Set("User-Agent", "claude-cli/2.1.22 (external, cli)")
	h.Set("X-Claude-Code-Session-Id", "9e0a3d21-1f1c-4a02-9c1b-33a1f0e9d100")
	h.Set("Anthropic-Beta", "claude-code-20250219,oauth-2025-04-20")

	if removed := scrubMemberIdentityHeaders(h); len(removed) != 0 {
		t.Fatalf("scrub removed legitimate headers %v (false positive breaks every request)", removed)
	}
	if len(h) != 5 {
		t.Fatalf("header set mutated: %#v", h)
	}
}

// L3 body rule. 🔴 MUTATION PROOF — verbatim run, 2026-07-21. Remove the
// memberIdentityShape early-return from injectMetadataUserIDIfAbsent:
//
//	--- FAIL: TestUpstreamBody_CarriesNoMemberIdentity (0.00s)
//	    --- FAIL: TestUpstreamBody_CarriesNoMemberIdentity/synthetic_handle (0.00s)
//	        sso_identity_no_leak_test.go:157: body reached the upstream carrying "sso+feishu.": {"messages":[],"metadata":{"user_id":"user_de9f_account_sso+feishu.f11625f5ed9c39bf2c63d742cf65e3cc@sso.local_session_c0ffee"},"model":"claude-sonnet-4-5"}
//	    --- FAIL: TestUpstreamBody_CarriesNoMemberIdentity/sso_local_domain (0.00s)
//	        sso_identity_no_leak_test.go:157: body reached the upstream carrying "@sso.local": …
//	    --- FAIL: TestUpstreamBody_CarriesNoMemberIdentity/feishu_union_id (0.00s)
//	        sso_identity_no_leak_test.go:157: body reached the upstream carrying "on_8ed6aa": …
//
// All three subcases go red, so no single shape is carrying the assertion.
//
// This is the leak the review named: the "attribute upstream usage per member"
// feature only has to compose the handle into the user_id, and both header
// fences stay green while a digest of a named employee's union_id lands at
// Anthropic. Body is the one place the proxy already writes an identifier, so
// it is the one place the fence has to sit.
func TestUpstreamBody_CarriesNoMemberIdentity(t *testing.T) {
	cases := []struct {
		name   string
		userID string
	}{
		{"synthetic_handle", "user_de9f_account_sso+feishu.f11625f5ed9c39bf2c63d742cf65e3cc@sso.local_session_c0ffee"},
		{"sso_local_domain", "user_de9f_account_alice@sso.local_session_c0ffee"},
		{"feishu_union_id", "user_de9f_account_on_8ed6aa67826108097d9ee1438163457c_session_c0ffee"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/messages",
				bytes.NewReader([]byte(`{"model":"claude-sonnet-4-5","messages":[]}`)))
			injectMetadataUserIDIfAbsent(req, c.userID)

			got, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			for _, forbidden := range []string{"sso+feishu.", "@sso.local", "on_8ed6aa"} {
				if bytes.Contains(got, []byte(forbidden)) {
					t.Errorf("body reached the upstream carrying %q: %s", forbidden, got)
				}
			}
			var parsed map[string]any
			if err := json.Unmarshal(got, &parsed); err != nil {
				t.Fatalf("guard corrupted the body: %v (%s)", err, got)
			}
			if _, present := parsed["metadata"]; present {
				t.Errorf("guard refused the value but still wrote metadata: %s", got)
			}
			if parsed["model"] != "claude-sonnet-4-5" {
				t.Errorf("guard damaged unrelated body fields: %s", got)
			}
		})
	}
}

// L3 negative half: the ordinary OAuth user_id (device sha256 + account UUID +
// session UUID) must still be injected. A guard that blocks everything would
// silently drop the WAF persona field and hand every OAuth user a 429 — the
// exact "business rejection disguised as rate limit" this whole path exists to
// avoid. `_session_` contains the letters "on_"; the \b in feishuActorIDRe is
// what keeps it from matching, so this case is also that regex's regression pin.
func TestInjectMetadataUserID_StillInjectsOrdinaryOAuthIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages",
		bytes.NewReader([]byte(`{"model":"claude-sonnet-4-5"}`)))
	const want = "user_9f2c4a1b7d3e5f60a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718" +
		"_account_c4f1aec0-326d-4f20-a20a-90fcc100af00" +
		"_session_3e527d39-d5a8-46ee-a7ac-7ca2072e65b6"
	injectMetadataUserIDIfAbsent(req, want)

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var parsed struct {
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, got)
	}
	if parsed.Metadata.UserID != want {
		t.Errorf("ordinary OAuth user_id was not injected: got %q, body %s", parsed.Metadata.UserID, got)
	}
}

// One invariant, one implementation. probe_raw.go used to carry a second,
// independently written X-Aikey-* stripper; fence I13 pinned only the forward
// one, so "unifying" the probe path by deleting its allowlist would not have
// moved a single test. It now delegates — this pins the delegation, because a
// re-fork would restore the split source of truth silently.
//
// 🔴 MUTATION PROOF — verbatim run, 2026-07-21. Re-fork stripAikeyHeaders as a
// raw-key prefix match (`strings.HasPrefix(name, "X-Aikey-")`, the shape a
// "just inline it" rewrite naturally takes):
//
//	--- FAIL: TestStripperConvergence_ProbeDelegatesToForwardPath (0.00s)
//	    sso_identity_no_leak_test.go:231: strippers diverged: forward=http.Header{"Anthropic-Version":…, "Authorization":…} probe=http.Header{"Anthropic-Version":…, "Authorization":…, "x-aikey-raw-map-key":[]string{"leaked"}}
//
// 💡 This test paid for itself while being written: its first run went red on
// UNMUTATED code, because stripAikeyRequestHeaders used h.Del(k), and Del
// canonicalizes before deleting — so a non-canonical map key matched the
// case-insensitive test and then survived the delete. Fixed in middleware.go
// (delete(h, k)); see the comment there.
func TestStripperConvergence_ProbeDelegatesToForwardPath(t *testing.T) {
	seed := func() http.Header {
		h := http.Header{}
		h.Set("X-Aikey-Union-Id", "on_8ed6aa67826108097d9ee1438163457c")
		h.Set("x-aikey-probe-bearer", "sk-secret")
		h.Set("X-AIKEY-Seat-Id", "3e527d39")
		// Written straight into the map, bypassing Set's canonicalization — the
		// shape a header copied verbatim from another hop can take. The forward
		// stripper is case-insensitive so it catches this; a re-fork that
		// prefix-matches the raw key would not, which is the divergence this
		// test exists to catch.
		h["x-aikey-raw-map-key"] = []string{"leaked"}
		h.Set("Authorization", "Bearer keep-me")
		h.Set("Anthropic-Version", "2023-06-01")
		return h
	}
	viaForward, viaProbe := seed(), seed()
	stripAikeyRequestHeaders(viaForward)
	stripAikeyHeaders(viaProbe)

	if len(viaForward) != len(viaProbe) {
		t.Fatalf("strippers diverged: forward=%#v probe=%#v", viaForward, viaProbe)
	}
	for name, values := range viaForward {
		if got := viaProbe[http.CanonicalHeaderKey(name)]; len(got) != len(values) || (len(got) > 0 && got[0] != values[0]) {
			t.Errorf("strippers diverged on %q: forward=%v probe=%v", name, values, got)
		}
	}
	if viaProbe.Get("Authorization") != "Bearer keep-me" {
		t.Errorf("probe stripper took the upstream credential: %#v", viaProbe)
	}
}

// The vocabulary fence: does the data plane even have the WORDS for a member's
// provider identity?
//
// 🔴 WHAT THIS IS NOT. It is a proxy metric, not a terminal observation
// (SKILL §11). Identity travels as DATA, not as field names — control-plane
// member identity arriving inside GroupRuntimeAccount.Identity (a generically
// named field whose own comment says "email / alias") would not cost this scan
// a single hit. The fences that actually守住 the wire are L1/L2/L3 above; this
// one only catches the cheapest and most common first move, a literal
// `union_id` json tag appearing in the data plane. It is kept, not deleted,
// because that first move IS how this would start and the scan costs ~40ms —
// but it is labelled so nobody mistakes green here for "no identity leaves".
//
// Two defects fixed 2026-07-21:
//   - the walk root was "." = the internal/proxy package only, leaving
//     internal/vkeys (the actual carrier of runtime material), internal/events
//     (usage reporting), internal/supervisor and app/ — precisely where
//     control-plane data enters the data plane — outside the scan.
//   - no anti-vacuity assertion: a walk that reached zero files also passed.
//
// 🚫 If this fails, do not add a header to the stripper — ask why the data plane
// is holding a member's provider identity.
func TestProxySource_DoesNotReferenceMemberIdentityFields(t *testing.T) {
	forbidden := []string{"union_id", "tenant_key", "sso.local"}

	// Repo root: internal/proxy → ../..
	offenders, scanned, err := scanGoSourcesFor(filepath.Join("..", ".."), forbidden)
	// Exactly one exemption: the guard has to name what it hunts. Same shape as
	// the repo's two-arg MAX() fence, whose rule is "the grep may only hit the
	// helper itself". Keep it to one file — every added exemption is a hole.
	offenders = dropExempt(offenders, filepath.Join("internal", "proxy", "member_identity_guard.go"))
	if err != nil {
		t.Fatalf("walk proxy sources: %v", err)
	}

	// Anti-vacuity 1: the scan must have actually read the data plane. 150 is a
	// deliberate floor well under the ~300 non-test .go files present on
	// 2026-07-21 — it catches "walk silently reached nothing", not file-count
	// drift.
	if scanned < 150 {
		t.Fatalf("scan covered only %d files — the walk root is wrong and this fence is vacuous", scanned)
	}
	// Anti-vacuity 2: name the packages that must be in range, so narrowing the
	// root back to one package fails loudly instead of passing quietly.
	for _, pkg := range []string{
		filepath.Join("internal", "vkeys"),
		filepath.Join("internal", "events"),
		filepath.Join("internal", "supervisor"),
		filepath.Join("internal", "proxy"),
		"app",
	} {
		found := false
		for _, p := range scannedPaths {
			if strings.Contains(p, pkg) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("package %s was not scanned — control-plane data enters the data plane there", pkg)
		}
	}

	if len(offenders) > 0 {
		t.Errorf("the data plane references control-plane member identity:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// Anti-vacuity 3: prove the scanner can fire at all. Without this the fence's
// green is indistinguishable from a scanner that matches nothing ever — and on
// 2026-07-21 the three terms had zero occurrences repo-wide, so the fence had
// been idling since the day it merged with no evidence it could ever go red.
//
// 🔴 MUTATION PROOF — verbatim runs, 2026-07-21, with `// union_id` appended to
// internal/vkeys/group_runtime.go:
//
//	(a) current walk root ("../.." = repo root):
//	    --- FAIL: TestProxySource_DoesNotReferenceMemberIdentityFields (0.01s)
//	        sso_identity_no_leak_test.go:307: the data plane references control-plane member identity:
//	          ../../internal/vkeys/group_runtime.go contains union_id
//
//	(b) same plant, walk root reverted to the pre-fix "." :
//	    --- FAIL: TestProxySource_DoesNotReferenceMemberIdentityFields (0.00s)
//	        sso_identity_no_leak_test.go:283: scan covered only 47 files — the walk root is wrong and this fence is vacuous
//
// Read (b) carefully: the planted union_id is NOT in its offender list. The old
// fence walked 47 files of internal/proxy and was structurally blind to the
// package that actually carries runtime material. The scan-root defect was
// real, not theoretical — and only the anti-vacuity floor makes it visible.
func TestSourceScanner_ActuallyFires(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "carrier.go"),
		[]byte("package x\n\ntype A struct{ U string `json:\"union_id\"` }\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "carrier_test.go"),
		[]byte("package x // union_id in a test file must be ignored\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	offenders, scanned, err := scanGoSourcesFor(dir, []string{"union_id", "tenant_key", "sso.local"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scanned != 1 {
		t.Errorf("expected 1 non-test file scanned, got %d", scanned)
	}
	if len(offenders) != 1 || !strings.Contains(offenders[0], "union_id") {
		t.Fatalf("scanner did not fire on a planted hit: %v", offenders)
	}
}

// dropExempt removes offender lines belonging to the named file. Separate
// helper (not a skip inside the walk) so the exemption is visible at the call
// site and cannot be widened by accident.
func dropExempt(offenders []string, exempt string) []string {
	kept := offenders[:0]
	for _, o := range offenders {
		if strings.Contains(o, exempt) {
			continue
		}
		kept = append(kept, o)
	}
	return kept
}

// scannedPaths records the last scan's file list for the coverage assertions.
// Package-level rather than a return value only because both consumers are in
// this file and a 4th return value would read worse; tests here run in one
// process and do not run in parallel.
var scannedPaths []string

// scanGoSourcesFor walks root for non-test .go files containing any forbidden
// term. Returns offenders, the count of files actually read, and any walk error.
func scanGoSourcesFor(root string, forbidden []string) ([]string, int, error) {
	var offenders []string
	var scanned int
	scannedPaths = nil

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", "bin", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path) //nolint:gosec // path comes from the repo walk
		if readErr != nil {
			return readErr
		}
		scanned++
		scannedPaths = append(scannedPaths, path)
		for _, term := range forbidden {
			if strings.Contains(string(body), term) {
				offenders = append(offenders, path+" contains "+term)
			}
		}
		return nil
	})
	return offenders, scanned, err
}
