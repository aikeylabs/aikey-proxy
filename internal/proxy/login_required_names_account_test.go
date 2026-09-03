package proxy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// The defect this guards (2026-09-03, field-confirmed): the LOGIN_REQUIRED
// surface named the account by nothing at all ("this shared account"), while the
// identity rode the very material the resolver had just picked from. A member
// with several accounts in one pool signed into the wrong one twice, each time
// getting the same anonymous error back.
//
// bugfix: workflow/CI/bugfix/2026-09-03-登录提示不说是哪个账号.md
func TestGroupAccountIdentityIsReadFromTheDeliveredMaterial(t *testing.T) {
	material, err := json.Marshal(map[string]vkeys.GroupRuntimeAccount{
		"acct-routed": {Identity: "routed@example.com", NeedsLogin: true},
		"acct-other":  {Identity: "other@example.com"},
	})
	if err != nil {
		t.Fatalf("marshal material: %v", err)
	}
	if got := groupAccountIdentity(string(material), "acct-routed"); got != "routed@example.com" {
		t.Fatalf("identity of the routed account = %q, want routed@example.com — the member cannot act on a bare UUID", got)
	}
	if got := groupAccountIdentity(string(material), "acct-other"); got != "other@example.com" {
		t.Fatalf("identity must be looked up per account, got %q", got)
	}
}

// Degrade honestly: an older master omits identity, the material may be absent
// or unparseable. Returning "" makes the caller fall back to the previous
// generic wording — never a confident-looking UUID the member cannot use.
func TestGroupAccountIdentityDegradesToEmptyRatherThanGuessing(t *testing.T) {
	withoutIdentity, _ := json.Marshal(map[string]vkeys.GroupRuntimeAccount{"acct": {NeedsLogin: true}})
	for name, got := range map[string]string{
		"no material":      groupAccountIdentity("", "acct"),
		"no account id":    groupAccountIdentity(string(withoutIdentity), ""),
		"unparseable":      groupAccountIdentity("{not json", "acct"),
		"unknown account":  groupAccountIdentity(string(withoutIdentity), "missing"),
		"identity omitted": groupAccountIdentity(string(withoutIdentity), "acct"),
	} {
		if got != "" {
			t.Fatalf("%s: expected empty identity, got %q", name, got)
		}
	}
}

// A correct helper nobody calls is the exact defect shape this repository keeps
// hitting: the field arrives, the consumer drops it. So the fence lands on the
// CALL SITE, not just on groupAccountIdentity.
func TestLoginRequiredMessageActuallyNamesTheAccount(t *testing.T) {
	src, err := os.ReadFile("group_serve.go")
	if err != nil {
		t.Fatalf("read group_serve.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (p *Proxy) respondLoginRequired(")
	if start < 0 {
		t.Fatal("respondLoginRequired not found — fence anchor moved, fix the fence")
	}
	end := strings.Index(body[start:], "\nfunc ")
	if end < 0 {
		t.Fatal("could not bound respondLoginRequired")
	}
	fn := body[start : start+end]

	if !strings.Contains(fn, "groupAccountIdentity(route.GroupRuntime, accountID)") {
		t.Fatal("respondLoginRequired no longer resolves the account identity — the member is back to an anonymous 'this shared account'")
	}
	if !strings.Contains(fn, `"account_identity", identity`) {
		t.Fatal("the login_required log dropped account_identity — remote diagnosis is back to mapping UUIDs by hand")
	}
	// The identity must reach the MEMBER-facing message, not only the log: the
	// person who has to act on it never reads our logs.
	if !strings.Contains(fn, `subject = "shared account " + identity`) ||
		!strings.Contains(fn, `"AiKey: " + subject + " is not signed in yet.`) {
		t.Fatal("the user-facing message no longer interpolates the account identity")
	}
	// And it must still degrade honestly when the identity is unknown.
	if !strings.Contains(fn, `subject := "this shared account"`) {
		t.Fatal("lost the empty-identity fallback — an older master would print a bare UUID or an empty name")
	}
}
