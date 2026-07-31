package proxy

// chain_serve.go — walking a primary/fallback chain for ONE client request
// (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 2.1–2.11, 2.30–2.32).
//
// # 🔴 What this is NOT
//
// It is not a second failover engine. The account axis already owns the three
// load-bearing rules — first-byte gate, body replay, failed-candidate exclusion —
// and they are reused verbatim here (`groupFailoverWriter`). What this file adds
// is a different SOURCE of candidates: the next binding in the route group,
// instead of the next account in the pool.
//
// Two shapes were explicitly rejected (task 2.1):
//
//	🚫 A middleware wrapping the account retry. Nesting makes attempts
//	   MULTIPLICATIVE — 3 accounts × 3 vendors = 9 sequential upstream
//	   round-trips — and the outer layer cannot see the inner one's first-byte
//	   state, so the gate silently stops working.
//	🚫 Recursing into the whole forwarding path. Stack depth becomes
//	   unbounded and the one-shot state stashed on the context (injected
//	   headers, a rewritten URL) accumulates layer by layer.
//
// The fence in chain_serve_test.go asserts attempts stay ADDITIVE.
//
// # 🔴 The first-byte gate is not touched (2.2 / I3)
//
// Once one byte has reached the client the response is committed: switching then
// would splice two different upstreams' streams into one body, and the client has
// no way to detect it. `groupFailoverWriter` decides once, at WriteHeader time.
// This file only chooses what to try next — it never reaches into that decision.
//
// # 🔴 Every hop uses ITS OWN credential and address (2.3 / I5)
//
// Each candidate is a full binding row carrying its own base_url and decrypted
// key, so switching is just "use the next row". 🚫 Never fall back to the
// provider's default address on a switch: the administrator's configured address
// would be silently ignored, and the symptom (the console shows one upstream, the
// logs another) is close to unsearchable.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/fallbackpolicy"
)

// chainSkipResponse names the responses that mean "this hop cannot serve THIS
// request" as opposed to "this hop is broken".
//
// 🔴 Task 2.30. A mixed chain (the vendor's own API plus a GLM-compatible
// gateway) has different model maps per hop, and GLM's is `unmatched: reject`.
// Today that rejection is written straight to the client — inside a candidate
// loop that would promote "the SECOND choice does not support this model" into
// "your request failed", while the primary may never even have been asked.
//
// 🚫 It is deliberately NOT folded into `failoverEligibleResponse` (task 2.5):
// that predicate also drives the account axis, and widening it would change
// released oauth-group behavior for a reason that has nothing to do with it.
//
// 🚫 It also does not cool the hop down. The hop is healthy; it simply does not
// speak this model. Cooling it would make an unrelated later request skip a
// working upstream.
func chainSkipResponse(status int, h http.Header) bool {
	return status == http.StatusBadRequest && h.Get(HeaderAikeyErrorSource) == "MODEL_MAPPING_NOT_FOUND"
}

// chainAttemptEligible is the capture predicate for the binding axis: defer both
// genuine upstream faults and "this hop cannot serve this model".
func chainAttemptEligible(status int, h http.Header) bool {
	return failoverEligibleResponse(status, h) || chainSkipResponse(status, h)
}

// serveManagedChain runs one client request down the candidate chain.
//
// Callers pass a chain whose `canFailover()` is true, OR a one-member GROUP whose
// failure must be reported as UNCONFIGURED. A legacy single binding with no group
// must NOT come here — it keeps the pre-upgrade single-shot path byte for byte,
// which is what makes this change safe to ship to installations that never
// configured a chain.
func (p *Proxy) serveManagedChain(
	w http.ResponseWriter, r *http.Request, chain *candidateChain,
	inboundBearer string, startTime time.Time, logger *slog.Logger, traceID string,
	stream string,
) {
	// 🔴 ONE snapshot for the whole chain (task 1b.6). Reading per hop would let a
	// 10-second policy poll landing mid-request give hops 1-2 one timeout and hop
	// 3 another — same inputs, different behavior, nothing in the logs to explain
	// it.
	policy, _ := FallbackPolicyFromContext(r.Context())
	now := time.Now()

	// Body replay (rule 2 of the account axis, reused): buffer ONCE so every
	// attempt forwards a pristine clone. Per-attempt mutations — an injected
	// header, a rewritten URL, a model name rewritten for THIS hop's vendor —
	// must never leak into the next attempt.
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "REQUEST_BODY_UNREADABLE",
			"Failed to read the request body.")
		return
	}
	_ = r.Body.Close()

	key := chainActivityKey{virtualKeyID: chain.primary().VirtualKeyID, protocolType: chain.primary().ProtocolType}
	stick := p.chainActivity.observe(key,
		time.Duration(policy.IdleGap.Value)*time.Millisecond,
		time.Duration(policy.MaxStickiness.Value)*time.Millisecond,
		now)
	// 🔴 The inter-arrival gap is a DERIVED number and may travel (task 2.24 /
	// 1b.8): it is the only calibration data the idle-gap and stickiness defaults
	// will ever have, and F-9b says outright that those defaults are guesses. The
	// timestamps it was computed from stay on this machine.
	if !stick.firstEver {
		ObserveSessionGap(stick.gap)
	}

	order := orderCandidates(chain.candidates, stick.stickTo, p.bindingCooldown, now)
	primaryBindingID := hopKey(chain.primary())

	// Whole-chain budget (task 2.31). 🔴 Checked BEFORE each switch rather than
	// enforced as a hard cancel: cutting an in-flight attempt would abort a
	// request that may be about to succeed, whereas declining to START another
	// hop costs nothing.
	deadline := time.Time{}
	if policy.ChainTotalBudget.Value > 0 {
		deadline = startTime.Add(time.Duration(policy.ChainTotalBudget.Value) * time.Millisecond)
	}

	var (
		lastCaptured *groupFailoverWriter
		attempts     int
		lastReason   string
		lastProvider string
	)

	for i, cand := range order {
		if i > 0 && !deadline.IsZero() && time.Now().After(deadline) {
			// 🔴 A separate code from EXHAUSTED, on purpose (task 2.32). The two
			// point at OPPOSITE next actions: budget = "the upstreams may be fine,
			// we stopped waiting" → raise the number; exhausted = "none of your
			// upstreams worked" → go look at the upstreams. One shared code would
			// send half of the people who see it in the wrong direction.
			p.errors.Add(1)
			logger.Warn("upstream fallback: whole-chain budget exhausted",
				"event.name", observability.EventProxyRouteFallback,
				"error.code", observability.ErrCodeUpstreamFallbackBudgetExceeded,
				"virtual_key_id", key.virtualKeyID,
				"attempts", attempts,
				"budget_ms", policy.ChainTotalBudget.Value,
				"budget_source", string(policy.ChainTotalBudget.Source),
			)
			writeJSONError(w, http.StatusGatewayTimeout, "server_error",
				observability.ErrCodeUpstreamFallbackBudgetExceeded,
				observability.FallbackMessage(observability.ErrCodeUpstreamFallbackBudgetExceeded, "en", attempts))
			return
		}

		realKey, resolveErr := p.resolveChainKey(cand)
		if resolveErr != nil {
			// 🔴 Task 2.8: a revoked or missing credential is skipped WITHOUT
			// counting as an attempt. It consumed no upstream round-trip, so
			// charging it against the try budget would shorten the chain for a
			// reason the administrator cannot see.
			logger.Warn("upstream fallback: skipping a hop whose credential is unavailable",
				"event.name", observability.EventProxyRouteFallback,
				"provider", cand.ProviderCode,
				"binding_id", cand.BindingID,
				"error.message", resolveErr.Error(),
			)
			continue
		}
		adapterKey := cand.ProtocolType
		if adapterKey == "" {
			adapterKey = cand.Provider
		}
		prov, provErr := p.providers.Get(adapterKey)
		if provErr != nil {
			logger.Warn("upstream fallback: skipping a hop with an unknown provider protocol",
				"event.name", observability.EventProxyRouteFallback,
				"provider", cand.ProviderCode,
				"protocol_type", adapterKey,
			)
			continue
		}

		// 🔴 The per-attempt timeout applies ONLY when the organization configured
		// one (contract §11, decided 2026-07-30). Unconfigured means NO CAP, which
		// is byte-identical to the behavior before this change.
		//
		// Why not simply apply the 120000 "default": there is no per-attempt
		// upstream timeout today. `providers.<name>.timeout` is filled in by
		// applyDefaults and read by nothing; streaming is unbounded and
		// non-streaming is capped at ten minutes only after the client has already
		// disconnected. Applying a number nobody ever configured would let a
		// healthy-but-slow long-context generation be judged an upstream failure —
		// then switched away from, then cooled — for the first time, on upgrade.
		// That is using a GUESS to overrule a SUCCESS.
		attemptCtx := r.Context()
		var cancelAttempt context.CancelFunc
		if policy.UpstreamAttemptTimeout.Source == fallbackpolicy.SourceOrg && policy.UpstreamAttemptTimeout.Value > 0 {
			d := time.Duration(policy.UpstreamAttemptTimeout.Value) * time.Millisecond
			attemptCtx, cancelAttempt = context.WithTimeout(attemptCtx, d)
			// The non-streaming path deliberately DETACHES from the request context
			// so a client disconnect cannot abort an in-flight upstream call. Our cap
			// is not the client's cancellation, so it has to travel as a value and be
			// re-applied on the far side — otherwise a configured timeout would be
			// settable, storable, displayable, and inert.
			attemptCtx = withAttemptTimeout(attemptCtx, d)
		}

		attempt := r.Clone(attemptCtx)
		if len(reqBody) > 0 {
			attempt.Body = io.NopCloser(bytes.NewReader(reqBody))
			attempt.ContentLength = int64(len(reqBody))
		} else {
			attempt.Body = http.NoBody
			attempt.ContentLength = 0
		}

		// Per-hop copy — 🚫 never mutate the registry's shared route.
		rc := *cand
		// Stamp THIS hop's attribution on its own copy (task 3.11). Both the local
		// usage event and the uploaded event read the route they are given, so the
		// values can only ever describe the hop that produced the response.
		rc.FallbackAttempt = i + 1
		rc.FallbackReason = lastReason

		// 🔴 Task 2.3: every hop uses ITS OWN address. The binding row carries the
		// administrator's configured base_url; only when it has none does the
		// provider's registered default apply — the same rule both single-shot
		// entries already use, kept in ONE place so a switch cannot silently
		// resolve an address differently from the first attempt.
		//
		// 🚫 Never fall back to the provider default when the row HAS an address:
		// the administrator's gateway would be quietly bypassed, and the symptom
		// (the console shows one upstream, the logs another) is close to
		// unsearchable.
		if rc.BaseURL == "" {
			rc.BaseURL = providerBaseURLForProtocol(rc.ProviderCode, rc.ProtocolType)
		}
		if rc.BaseURL == "" {
			logger.Warn("upstream fallback: skipping a hop with no resolvable upstream address",
				"event.name", observability.EventProxyRouteFallback,
				"provider", rc.ProviderCode,
				"binding_id", rc.BindingID,
			)
			continue
		}

		// Capture stays on for the LAST hop too, unlike the account axis. The
		// chain has a terminal answer of its own to give (EXHAUSTED /
		// UNCONFIGURED), and letting the final upstream error stream straight
		// through would leave the client with a vendor error and no indication
		// that a chain was walked at all.
		fw := newGroupFailoverWriter(w, true)
		fw.eligible = chainAttemptEligible
		if i > 0 {
			// Announce the switch on the response the client will actually get.
			// 🔴 Provider code only, never the resolved base_url (contract §3): an
			// upstream address may be a customer's internal gateway, and echoing it
			// to every key holder broadcasts internal topology.
			fw.Header().Set(observability.HeaderUpstreamFallback,
				observability.FormatFallbackHeader(rc.ProviderCode, lastReason, i+1))
		}

		p.serveRouteWithObserver(fw, attempt, &rc, prov, realKey, inboundBearer, startTime, logger, stream, traceID)
		if cancelAttempt != nil {
			cancelAttempt()
		}
		attempts++

		if !fw.capturedResponse() {
			// Served (or a non-retryable answer the client must see verbatim).
			p.bindingCooldown.noteSuccess(hopKey(&rc))
			p.chainActivity.noteServed(key, hopKey(&rc), hopKey(&rc) == primaryBindingID || i == 0, time.Now())
			return
		}

		// This hop did not serve.
		skipped := chainSkipResponse(fw.status, fw.header)
		if !skipped {
			if until, cooled := p.bindingCooldown.note(hopKey(&rc), fw.status, fw.header, policy.BindingCooldown, time.Now()); cooled {
				logger.Info("upstream fallback: cooling a failed upstream",
					"event.name", observability.EventProxyRouteFallback,
					"provider", rc.ProviderCode,
					"binding_id", rc.BindingID,
					"cool_until", until.Format(time.RFC3339),
				)
			}
			lastCaptured = fw
			lastReason = fw.header.Get(HeaderAikeyErrorSource)
			if lastReason == "" {
				lastReason = httpStatusReason(fw.status)
			}
		} else {
			// 🔴 A mapping rejection is NOT an upstream failure, so it must not
			// become the answer we relay if the chain later runs out. Keep the last
			// genuine upstream error for that.
			logger.Info("upstream fallback: hop does not support the requested model, trying the next",
				"event.name", observability.EventProxyRouteFallback,
				"provider", rc.ProviderCode,
				"binding_id", rc.BindingID,
			)
		}
		lastProvider = rc.ProviderCode

		if i+1 < len(order) {
			p.fallbackSwitches.Add(1)
			logger.Warn("upstream fallback: switching to the next upstream",
				"event.name", observability.EventProxyRouteFallback,
				"virtual_key_id", key.virtualKeyID,
				"from_provider", rc.ProviderCode,
				"to_provider", order[i+1].ProviderCode,
				"from_binding_id", rc.BindingID,
				"to_binding_id", order[i+1].BindingID,
				"reason", lastReason,
				"attempt", i+1,
			)
		}
	}

	// ── The chain is spent ─────────────────────────────────────────────────
	code := chain.exhaustedCode()
	status := http.StatusBadGateway
	if lastCaptured != nil {
		// 🔴 Pass through the last upstream's STATUS CODE (contract §1): a 401
		// chain and a 529 chain need different responses from the client, and
		// flattening both to 502 would erase that.
		status = lastCaptured.status
		logger.Warn("upstream fallback: every candidate failed",
			"event.name", observability.EventProxyRouteFallback,
			"error.code", code,
			"virtual_key_id", key.virtualKeyID,
			"attempts", attempts,
			"last_provider", lastProvider,
			"last_status", lastCaptured.status,
			// The upstream's own error text is preserved HERE rather than relayed to
			// the client, because the client gets the frozen chain-level copy. An
			// administrator debugging "why did all three fail" needs the vendor's
			// words, and this is where they look.
			"last_upstream_body", truncateForLog(lastCaptured.buf.String()),
		)
	} else {
		logger.Warn("upstream fallback: no candidate could be attempted",
			"event.name", observability.EventProxyRouteFallback,
			"error.code", code,
			"virtual_key_id", key.virtualKeyID,
		)
	}
	p.errors.Add(1)
	if lastProvider != "" {
		w.Header().Set(observability.HeaderUpstreamFallback,
			observability.FormatFallbackHeader(lastProvider, code, attempts))
	}
	writeJSONError(w, status, "server_error", code,
		observability.FallbackMessage(code, "en", attempts))
}

// orderCandidates produces the try order for one request.
//
// Three rules, in this order:
//
//  1. A sticky hop goes FIRST (task 2.22 / I17). A conversation in progress keeps
//     the upstream that is serving it: the same model name can behave subtly
//     differently at different vendors — the reason the confidence check exists —
//     so switching mid-conversation makes the model's behavior jump under the user.
//  2. Cooling hops go LAST, not away (task 2.15 / I14). Cooling is a PREFERENCE.
//     When every candidate is cooling the chain is still walked in the
//     administrator's order, so a quietly recovered upstream is found by the next
//     real request instead of the request being refused.
//  3. Everything else keeps the administrator's configured order.
//
// 🚫 The relative order within each band is never re-sorted by anything else — no
// latency, no cost, no health score. Runtime selection was excluded by F-8 for a
// stated reason: it destroys explainability and auditability, and "why did it pick
// that one" stops having an answer.
func orderCandidates(candidates []*vkeys.ResolvedRoute, stickTo string, cooldown *bindingCooldownStore, now time.Time) []*vkeys.ResolvedRoute {
	type banded struct {
		route *vkeys.ResolvedRoute
		band  int // 0 sticky, 1 available, 2 cooling
		idx   int
	}
	out := make([]banded, 0, len(candidates))
	for i, c := range candidates {
		band := 1
		if cooldown != nil {
			if _, cooling := cooldown.cooling(hopKey(c), now); cooling {
				band = 2
			}
		}
		if stickTo != "" && hopKey(c) == stickTo {
			band = 0
		}
		out = append(out, banded{route: c, band: band, idx: i})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].band != out[j].band {
			return out[i].band < out[j].band
		}
		return out[i].idx < out[j].idx
	})
	res := make([]*vkeys.ResolvedRoute, 0, len(out))
	for _, b := range out {
		res = append(res, b.route)
	}
	return res
}

// resolveChainKey produces the real upstream credential for one hop.
//
// Managed bindings carry their key already decrypted (the vault cache holds one
// row per binding, each with its own ciphertext), so the common path is a field
// read. The vault lookup covers rows that reference an alias instead.
func (p *Proxy) resolveChainKey(route *vkeys.ResolvedRoute) (string, error) {
	if route.PlaintextKey != "" {
		return route.PlaintextKey, nil
	}
	if route.KeyAlias == "" {
		return "", errors.New("binding has neither a decrypted key nor a vault alias")
	}
	key, err := p.vault.GetSecret(route.KeyAlias)
	if err != nil {
		if errors.Is(err, vault.ErrSecretNotFound) {
			return "", errors.New("credential '" + route.KeyAlias + "' is not in the vault")
		}
		return "", err
	}
	return key, nil
}

// httpStatusReason gives a stable, low-cardinality reason token for a status that
// carried no aikey error code (a raw upstream failure).
func httpStatusReason(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "UPSTREAM_UNAUTHORIZED"
	case status == http.StatusTooManyRequests:
		return "UPSTREAM_RATE_LIMITED"
	case status >= 500:
		return "UPSTREAM_SERVER_ERROR"
	}
	return "UPSTREAM_ERROR"
}

// truncateForLog bounds a relayed upstream body in a log line.
func truncateForLog(s string) string {
	const max = 512
	if len(s) <= max {
		return s
	}
	return s[:max] + "…(truncated)"
}
