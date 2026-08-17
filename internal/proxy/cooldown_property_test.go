package proxy

// Property-based fence for cooldownDecision (2026-08-15, owner-approved item
// "1", sibling of vkeys/routed_pick_property_test.go — see the WHY there).
//
// The rules pinned here are the evidence-based cooldown contract the whole
// account-pool scheduling story rests on (schedstress W1/W3/P06/P14 verified
// them live; these properties keep them pinned across randomized header
// combinations):
//
//	C1  429 WITHOUT rate-limit evidence is a WAF/business rejection →
//	    passthrough, NEVER a cooldown (B1, 2026-07-19).
//	C2  429 WITH evidence always cools, into the future.
//	C3  529 is the upstream's own overload signal → exactly the overload-scoped
//	    cooldown, no evidence needed.
//	C4  401 cools for the auth-scoped default (token relogin window).
//	C5  Everything else — 200/400/403/5xx — NEVER cools here: 400/403 are
//	    passthrough classes (P13/P14, 封号可见性 walks the signal rail instead),
//	    generic 5xx cooling belongs to the caller's streak layer only.
//
// hasRateLimitSignal is used as the evidence oracle on purpose: it has its own
// example fences (codex presence / anthropic value discrimination), and what
// these properties pin is the DECISION↔EVIDENCE coupling, not the evidence
// parser itself.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"testing"
	"time"
)

func genCooldownHeaders(r *rand.Rand, now time.Time) http.Header {
	h := http.Header{}
	if r.Intn(3) == 0 {
		h.Set("x-codex-primary-used-percent", fmt.Sprintf("%d", r.Intn(120)))
	}
	if r.Intn(3) == 0 {
		h.Set("anthropic-ratelimit-unified-status",
			[]string{"allowed", "allowed_warning", "rate_limited", "rejected", "exceeded", "exhausted"}[r.Intn(6)])
	}
	if r.Intn(4) == 0 {
		h.Set("anthropic-ratelimit-unified-utilization", fmt.Sprintf("%.2f", r.Float64()*1.4))
	}
	if r.Intn(4) == 0 {
		h.Set("anthropic-ratelimit-unified-5h-reset", fmt.Sprintf("%d", now.Unix()+int64(r.Intn(5*3600))))
	}
	if r.Intn(4) == 0 {
		h.Set("anthropic-ratelimit-unified-7d-reset", fmt.Sprintf("%d", now.Unix()+int64(r.Intn(7*24*3600))))
	}
	if r.Intn(4) == 0 {
		h.Set("Retry-After", fmt.Sprintf("%d", 1+r.Intn(600)))
	}
	if r.Intn(3) == 0 {
		h.Set("X-Request-Id", "noise") // unrelated header must never count as evidence
	}
	return h
}

func TestCooldownDecision_Properties(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	statuses := []int{200, 400, 401, 403, 429, 500, 502, 503, 529}
	const casesPerSeed = 4000
	for seed := int64(1); seed <= 6; seed++ {
		r := rand.New(rand.NewSource(seed))
		for i := 0; i < casesPerSeed; i++ {
			status := statuses[r.Intn(len(statuses))]
			h := genCooldownHeaders(r, now)
			resp := &http.Response{StatusCode: status, Header: h}
			until, cooled := cooldownDecision(resp, now)
			fail := func(property, detail string) {
				raw, _ := json.Marshal(h)
				t.Fatalf("property %s violated (seed=%d case=%d status=%d): %s\n got=(until=%s cooled=%v)\n headers=%s",
					property, seed, i, status, detail, until.Format(time.RFC3339), cooled, raw)
			}
			switch status {
			case http.StatusTooManyRequests:
				if hasRateLimitSignal(h) {
					if !cooled || !until.After(now) {
						fail("C2-evidence-cools", "429 with rate-limit evidence must cool into the future")
					}
				} else if cooled {
					fail("C1-waf-passthrough", "429 without evidence must never cool (WAF/business rejection)")
				}
			case 529:
				if !cooled || !until.Equal(now.Add(poolCooldown529Overload)) {
					fail("C3-overload-scoped", "529 must cool for exactly the overload-scoped window")
				}
			case http.StatusUnauthorized:
				if !cooled || !until.Equal(now.Add(poolCooldownDefault)) {
					fail("C4-auth-scoped", "401 must cool for the auth-scoped default")
				}
			default:
				if cooled {
					fail("C5-passthrough-classes", "only 401/evidence-429/529 may cool here (400/403 passthrough, 5xx is the streak layer's job)")
				}
			}
		}
	}
}
