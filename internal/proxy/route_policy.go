package proxy

// Grading-driven model routing — the org grading document's `route_policy[]`.
//
// spec: R-compliance-grading-8 (分级驱动的模型路由不改路由、不外泄等级)
//
// WHAT IT ENFORCES: T/AMAC §11.2 b) — high-sensitivity data may only be inferred
// in an isolated environment. The administrator writes
// `{"min_level":4, "allowed_providers":["intranet-*"], "otherwise":"block"}` and
// a request carrying a confirmed hit at L4 or above may then only travel to a
// provider whose code matches `intranet-*`.
//
// WHERE IT RUNS, and why there: inside applyInboundFilter's request-level
// section, after every piece has been scanned (the levels only exist after
// detection) and before anything is forwarded (the provider of THIS route is
// already chosen by the time serveRoute runs, so "before provider selection" in
// design §4b.5 is realized as "before the chosen provider is contacted"). It
// joins the dispatcher's deferred refusal, so the refusal goes through the one
// guardrail short-circuit and nothing reaches the upstream.
//
// WHAT IT DELIBERATELY DOES NOT DO:
//   - It never re-routes. A refused request is refused; picking an intranet
//     provider on the user's behalf is the 「静默改路由」 R-compliance-grading-8
//     forbids. A managed failover chain does not re-route it either: a 403 is
//     not failover-eligible (failoverEligibleResponse), so the refusal reaches
//     the client as-is.
//   - It never re-runs rules. The only input is each finding's `level` and the
//     evidence gate's `confirmed`, both decided by the detector.
//   - It never tells the upstream anything. The level is not written into any
//     request header or body; the outbound scrub (stripAikeyRequestHeaders)
//     applies unchanged to intranet providers — no exception.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync/atomic"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// ProviderRef identifies the provider a request is about to be sent to — the
// `target` a route_policy rule is checked against.
//
// Code is the route's provider code AFTER serveRoute's truthfulProviderCode
// normalization, i.e. the vendor the base URL actually belongs to when the
// proxy has address knowledge of it. That is what stops a binding that is
// merely DECLARED "intranet-x" while pointing at a known public vendor from
// satisfying an `intranet-*` allow-list.
//
// ⚠️ Limit, stated rather than implied: for a host the proxy has no address
// knowledge of, the code is the one the org registered. The allow-list
// therefore trusts the administrator's own provider registration — the same
// administrator who writes the policy.
type ProviderRef struct {
	Code string
}

// RoutePolicyRule is one entry of `route_policy[]`. JSON keys are taken
// VERBATIM from design §4b.1 (`route_policy []{min_level int,
// allowed_providers []string, otherwise string}`). A READER only, never
// marshaled back — the same posture as EscalationRule.
type RoutePolicyRule struct {
	MinLevel         int      `json:"min_level"`
	AllowedProviders []string `json:"allowed_providers"`
	Otherwise        string   `json:"otherwise"`
}

// RoutePolicy is the installed `route_policy[]`, in document order. Every rule
// must hold for a request to be forwarded (they are conjunctive: an L5-only
// rule narrows an L4 rule's allow-list for L5 content).
type RoutePolicy []RoutePolicyRule

// String renders the rule for logs. CONFIG ONLY — every part comes from the
// document the administrator saved, nothing from what was matched.
func (r RoutePolicyRule) String() string {
	return "min_level=" + itoaInt64(int64(r.MinLevel)) +
		" allowed_providers=" + strings.Join(r.AllowedProviders, ",") +
		" otherwise=" + r.Otherwise
}

// allows reports whether target may receive content this rule covers.
// Case-insensitive glob (`path.Match` syntax: `*`, `?`, `[...]`). A malformed
// pattern matches nothing — the restrictive direction; it was already reported
// at install time (parseRoutePolicy).
func (r RoutePolicyRule) allows(target ProviderRef) bool {
	code := strings.ToLower(target.Code)
	for _, pat := range r.AllowedProviders {
		if ok, err := path.Match(strings.ToLower(pat), code); err == nil && ok {
			return true
		}
	}
	return false
}

// routePolicyEnactableOtherwise is THE single place that decides what an
// `otherwise` spelling does. Only `block` exists (design §4b.1: 「否则按
// otherwise 处置（默认 block）」); "" is that default.
//
// 🔴 AN UNKNOWN SPELLING IS ENFORCED AS BLOCK (fail-CLOSED), and that is the
// opposite of escalationEnactableAction, on purpose:
//   - an escalation rule ADDS a refusal to traffic that is otherwise allowed, so
//     reading a typo as `block` would turn one misspelled word into refusals
//     nobody asked for;
//   - a route_policy rule is the administrator saying "L4 must NOT go to
//     external providers". Dropping the rule over an unreadable `otherwise`
//     would forward exactly the content they fenced off — the direction
//     R-compliance-grading-10 lists as a fail-closed trigger (「route_policy 不满足」)
//     and R-compliance-canned-answer-6 applies to any policy value this build
//     cannot read.
//
// ok=false tells the install-time reader to WARN. The enforced action is
// ALWAYS apphook.ActionBlock regardless of ok — this function only reports
// whether the spelling was recognized, it never varies the outcome (see the
// callers, which both hard-code apphook.ActionBlock rather than reading it
// from here — that constancy is exactly what "only `block` exists" means, so
// there is no second action for this function to return; go vet/unparam
// flagged the removed `action` result as always-`block` on 2026-09-19, see
// aikeylabs/workflow/CI/bugfix/2026-09-19-release-lint-fix.md).
func routePolicyEnactableOtherwise(otherwise string) (ok bool) {
	switch otherwise {
	case "", "block":
		return true
	default:
		return false
	}
}

// parseRoutePolicy reads `route_policy[]` out of the org grading document (the
// same bytes the supervisor bakes into the detector's AIKEY_COMPLIANCE_GRADING
// env — one document, several readers, each modeling only its own member).
//
// Decoded INDEPENDENTLY of `escalation[]` on purpose: a malformed escalation
// member must not disarm the routing rule, and vice versa.
//
// Empty document, `{}`, absent or empty `route_policy` → no rules, no error
// (R-compliance-grading-3.S1: an org that never configured it behaves exactly as
// before). notes are human-readable lines for the caller to WARN; a rule named
// in a note is still INSTALLED — no shape of rule is dropped (see below).
func parseRoutePolicy(gradingJSON []byte) (rules RoutePolicy, notes []string, err error) {
	if len(bytes.TrimSpace(gradingJSON)) == 0 {
		return nil, nil, nil
	}
	var doc struct {
		RoutePolicy []RoutePolicyRule `json:"route_policy"`
	}
	if err := json.Unmarshal(gradingJSON, &doc); err != nil {
		return nil, nil, fmt.Errorf("compliance grading policy: route_policy: %w", err)
	}
	for _, r := range doc.RoutePolicy {
		if r.MinLevel < 0 {
			// Kept, not dropped: dropping would forward exactly the content the
			// rule fences off. Ungraded hits (level 0) never count
			// (hasConfirmedAtOrAbove), so a negative floor reads as "any graded
			// hit" — the most restrictive reading, reported so it gets fixed.
			notes = append(notes, r.String()+" (min_level is negative; enforced as \"any graded hit\")")
		}
		for _, pat := range r.AllowedProviders {
			if _, perr := path.Match(pat, ""); perr != nil {
				notes = append(notes, r.String()+" (allowed_providers pattern "+pat+
					" is malformed and matches NO provider; the rule is enforced with it matching nothing)")
			}
		}
		if !routePolicyEnactableOtherwise(r.Otherwise) {
			notes = append(notes, r.String()+" (otherwise="+r.Otherwise+
				" is not recognized; ENFORCED AS block — fail-closed, see routePolicyEnactableOtherwise)")
		}
		rules = append(rules, r)
	}
	return rules, notes, nil
}

// applyGradingRoutePolicy is the route decision: given every finding the
// request produced, the provider it is headed for and the installed policy, may
// it go?
//
// spec: R-compliance-grading-8 (判定只读 level，不重跑规则)
//
// A finding counts only when it is CONFIRMED (the evidence gate's verdict) and
// its level is at or above the rule's floor. Unconfirmed hits never count:
// 「等级不得提升未确认命中的动作」(DEC-compliance-grading-2 约束, design.md) and
// R-compliance-grading-16 — a scored maybe must not turn a forward into a
// refusal. Level 0 is UNGRADED and satisfies no floor of 1 or more.
//
// No family filter (unlike countsTowardEscalation): the level IS the
// administrator's classification of the content, whatever family it is in.
//
// Returns ActionAllow and "" when every rule holds (and always when p is
// empty). Otherwise the FIRST violated rule in document order decides; reason is
// its config-only rendering. The request-level ceiling (MAX_ACTION) is applied
// by the caller, which is where it is known.
//
// 🔴 Signature deviation, stated: design §4b.5 names the first parameter
// `[]FindingLite`. The proxy's finding view already exists as Finding
// (escalation.go) with exactly the fields this needs (level, confirmed); a
// second near-identical type would be two answers to one question.
func applyGradingRoutePolicy(findings []Finding, target ProviderRef, p RoutePolicy) (action apphook.Action, reason string) {
	rule, violated := p.firstViolated(findings, target)
	if !violated {
		return apphook.ActionAllow, ""
	}
	// Only `block` exists (routePolicyEnactableOtherwise), so the action here
	// is always apphook.ActionBlock — an unrecognized `otherwise` spelling is
	// still enforced as block (fail-closed, see routePolicyEnactableOtherwise);
	// parseRoutePolicy is what reports the note that gets a WARN at install time.
	return apphook.ActionBlock, rule.String()
}

// firstViolated is the ONE predicate behind the decision: the first rule, in
// document order, whose floor is reached by a confirmed hit while target is
// outside its allow-list. applyGradingRoutePolicy and the dispatcher's log line
// (which needs min_level as its own field) both read it, so the two cannot
// disagree about which rule fired.
func (p RoutePolicy) firstViolated(findings []Finding, target ProviderRef) (RoutePolicyRule, bool) {
	for _, rule := range p {
		if hasConfirmedAtOrAbove(findings, rule.MinLevel) && !rule.allows(target) {
			return rule, true
		}
	}
	return RoutePolicyRule{}, false
}

// triggeringPieces returns the indexes of the pieces whose OWN findings reach
// this rule's floor — the evidence list of a route-policy verdict
// (R-compliance-grading-18: a verdict SHALL name the content units behind it).
// Same predicate as firstViolated (hasConfirmedAtOrAbove), applied per piece,
// so 「which rule fired」 and 「which pieces fired it」 cannot disagree.
// spec: R-compliance-grading-8.S1
func (r RoutePolicyRule) triggeringPieces(findingsByPiece [][]Finding) []int {
	var out []int
	for i, fs := range findingsByPiece {
		if hasConfirmedAtOrAbove(fs, r.MinLevel) {
			out = append(out, i)
		}
	}
	return out
}

// verdictMinLevel is the floor as recorded on the audit row. A document floor of
// 0 behaves as 1 (level 0 is ungraded and never counts — see
// hasConfirmedAtOrAbove), and master only stores 1–5, so the row says 1.
func (r RoutePolicyRule) verdictMinLevel() int {
	if r.MinLevel < 1 {
		return 1
	}
	return r.MinLevel
}

// hasConfirmedAtOrAbove: level 0 is UNGRADED and never counts, so a min_level
// of 0 behaves as "any graded hit".
func hasConfirmedAtOrAbove(findings []Finding, minLevel int) bool {
	for _, f := range findings {
		if f.Confirmed && f.Level >= minLevel && f.Level > 0 {
			return true
		}
	}
	return false
}

// routePolicyMetrics counts what the route decision did, per generation, so a
// fence can tell "evaluated and allowed" from "never ran". Counts only.
type routePolicyMetrics struct {
	evaluated atomic.Int64 // requests the decision ran on (policy installed)
	denied    atomic.Int64 // requests refused by it
	capped    atomic.Int64 // refusals pressed down by MAX_ACTION=warn (forwarded)
}

func (p *Proxy) routePolicySnapshot() struct{ evaluated, denied, capped int } {
	return struct{ evaluated, denied, capped int }{
		evaluated: int(p.routePolicyMetrics.evaluated.Load()),
		denied:    int(p.routePolicyMetrics.denied.Load()),
		capped:    int(p.routePolicyMetrics.capped.Load()),
	}
}

// ComplianceRoutePolicy reports the route_policy rules this generation enforces
// (status reporting and fences; asserts the wiring by behavior).
func (p *Proxy) ComplianceRoutePolicy() RoutePolicy {
	return append(RoutePolicy(nil), p.complianceGrading().routePolicy...)
}

// parseRoutePolicyLogged parses `route_policy[]`, WARNing every note (失败要显眼:
// a rule enforced differently from how it reads must be visible to the
// operator) and INFO-ing the active rule count. ok=false on an undecodable
// member: the caller (SetComplianceGrading) then keeps the route policy already
// in force (empty on a fresh generation). The supervisor only ever hands over
// the last VALID document (R-compliance-grading-14), so reaching the error path
// means the member itself is the wrong shape, which is WARNed. No request-scoped
// ids exist at install time, hence the package logger — the same posture as the
// supervisor's own install-time lines.
//
// spec: R-compliance-grading-8
func (p *Proxy) parseRoutePolicyLogged(gradingJSON []byte) (RoutePolicy, bool) {
	rules, notes, err := parseRoutePolicy(gradingJSON)
	if err != nil {
		slog.Warn("proxy: org route_policy member unreadable; the route policy in force is kept",
			"event.name", observability.EventComplianceRoutePolicyRuleRefused, "error", err.Error())
		return nil, false
	}
	for _, n := range notes {
		slog.Warn("proxy: route_policy rule will be enforced differently from how it reads",
			"event.name", observability.EventComplianceRoutePolicyRuleRefused, "rule", n)
	}
	if len(rules) > 0 {
		slog.Info("proxy: grading-driven route policy active",
			"event.name", observability.EventComplianceRoutePolicyActive, "rules", len(rules))
	}
	return rules, true
}

// withRouteTarget stashes the target provider on r's context (in place, the same
// pattern as the mask-restore stash) for the filter's route decision.
//
// WHY THE CONTEXT AND NOT A PARAMETER of applyInboundFilter: the filter is
// driven directly by ~140 existing fences, and a wrapper that forwards the
// ResponseWriter to an inner function is itself flagged as a new write site by
// TestFence_GuardrailShortCircuitBodyIsNeverInterpolated. Neither cost buys
// anything: serveRoute is the ONLY production caller, and the fence
// TestRoutePolicy_L4ToExternalProviderDenied drives serveRoute, so dropping this
// stash turns its intranet case red (a missing target is refused, see
// routeTargetFromContext).
//
// spec: R-compliance-grading-8
func withRouteTarget(r *http.Request, target ProviderRef) {
	*r = *r.WithContext(context.WithValue(r.Context(), ctxKeyRouteTarget, target))
}

// routeTargetFromContext returns the stashed target, or ProviderRef{} when none
// was stashed. An empty code matches no allow-list short of a bare "*", so a
// caller that forgot the stash gets a REFUSAL for an L-high hit — never a
// silent forward to an unknown destination.
func routeTargetFromContext(ctx context.Context) ProviderRef {
	t, _ := ctx.Value(ctxKeyRouteTarget).(ProviderRef)
	return t
}
