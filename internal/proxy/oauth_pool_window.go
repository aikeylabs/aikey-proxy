// oauth_pool_window.go — N10: window randomized-cap pre-cut (防封).
//
// An account that runs its quota window to 100% looks like abuse to the upstream.
// To stay under the wall, master generates a RANDOMIZED cap per account+window
// (5h 93-97, weekly 87-89, N11) and delivers both in the group material. The
// proxy reads the upstream's live utilization from EVERY response (present on
// 200s too — verified for OAuth subscription, 20260623-OAuth账号池-技术方案 §435)
// and, when utilization ≥ cap/100, pre-cuts the account for that window: cools it
// down until the window resets, so subsequent requests route to another account
// BEFORE the account hits 100%. Reuses N8c's cooldown store.
//
// Headers (verified): anthropic-ratelimit-unified-5h-utilization /
// -7d-utilization (float 0~1), anthropic-ratelimit-unified-reset (epoch seconds,
// or per-window -5h-reset / -7d-reset). http.Header.Get canonicalizes the key,
// so the lowercase form below matches regardless of the wire casing.
package proxy

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// stashWindowCap records the chosen pool account's window_max_util_pct on the
// request so serveRoute's ModifyResponse can pre-cut against the upstream's
// utilization header (N10). Returns the request carrying the stash.
type poolWindowCaps struct {
	FiveHour int
	SevenDay int
}

func intValue(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func stashWindowCaps(r *http.Request, fiveHour, sevenDay int) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyPoolWindowCap, poolWindowCaps{FiveHour: fiveHour, SevenDay: sevenDay}))
}

// stashWindowCap is the rolling-compatible single-cap helper used by older
// tests/callers. It applies the legacy cap to both windows.
func stashWindowCap(r *http.Request, capPct int) *http.Request {
	return stashWindowCaps(r, capPct, capPct)
}

// windowCapFromContext reads the stashed cap (false when absent → no pre-cut).
func windowCapFromContext(req *http.Request) (int, bool) {
	caps, ok := windowCapsFromContext(req)
	return caps.FiveHour, ok
}

func windowCapsFromContext(req *http.Request) (poolWindowCaps, bool) {
	if req == nil {
		return poolWindowCaps{}, false
	}
	switch v := req.Context().Value(ctxKeyPoolWindowCap).(type) {
	case poolWindowCaps:
		return v, true
	case int: // old in-memory generation during a hot upgrade
		return poolWindowCaps{FiveHour: v, SevenDay: v}, true
	default:
		return poolWindowCaps{}, false
	}
}

const (
	hdrUtil5h  = "anthropic-ratelimit-unified-5h-utilization"
	hdrUtil7d  = "anthropic-ratelimit-unified-7d-utilization"
	hdrReset   = "anthropic-ratelimit-unified-reset"
	hdrReset5h = "anthropic-ratelimit-unified-5h-reset"
	hdrReset7d = "anthropic-ratelimit-unified-7d-reset"
)

// windowPreCutDecision reports whether the chosen pool account has reached its
// randomized window cap and should be pre-cut. capPct is the account's delivered
// window_max_util_pct; <=0 or >=100 means "no meaningful cap" → never pre-cut
// (let natural exhaustion / 429 handle it). Returns (cool-until, true) when
// either window's utilization ≥ cap/100.
func windowPreCutDecision(h http.Header, capPct int, now time.Time) (time.Time, bool) {
	return dualWindowPreCutDecision(h, poolWindowCaps{FiveHour: capPct, SevenDay: capPct}, now)
}

func validWindowCap(capPct int) bool { return capPct > 0 && capPct < 100 }

func dualWindowPreCutDecision(h http.Header, caps poolWindowCaps, now time.Time) (time.Time, bool) {
	// Anthropic path (byte-identical to before): the two unified-utilization
	// headers ride on every response including 200s.
	u5h, has5h := parseUtil(h, hdrUtil5h)
	u7d, has7d := parseUtil(h, hdrUtil7d)
	if has5h || has7d {
		var until time.Time
		hit := false
		if has5h && validWindowCap(caps.FiveHour) && u5h >= float64(caps.FiveHour)/100 {
			hit = true
			until = laterTime(until, windowSpecificReset(h, hdrReset5h, now))
		}
		if has7d && validWindowCap(caps.SevenDay) && u7d >= float64(caps.SevenDay)/100 {
			hit = true
			until = laterTime(until, windowSpecificReset(h, hdrReset7d, now))
		}
		return until, hit
	}
	// Codex path: same anti-ban cap, Codex's own X-Codex-* util/reset headers
	// (verified live on the /responses 200, 2026-07-06). The two header families
	// are mutually exclusive (an account is Anthropic OR Codex), so header-sniff
	// dispatch mirrors R34's reactive layer — no provider_code branch.
	return codexDualWindowPreCut(h, caps, now)
}

// successfulWindowPreCutDecision applies the anti-ban cap only to a successful
// upstream response. A confirmed 429 exhaustion carries the same 100%-used
// headers, but it has already been classified by cooldownDecision; treating it
// as a pre-cut as well would overwrite the more precise window_exhausted display
// state with window_protected (and replace the provider reset with a local cap
// time). The routing cooldown is still handled by the reactive 429 path.
func successfulWindowPreCutDecision(resp *http.Response, capPct int, now time.Time) (time.Time, bool) {
	return successfulDualWindowPreCutDecision(resp, poolWindowCaps{FiveHour: capPct, SevenDay: capPct}, now)
}

func successfulDualWindowPreCutDecision(resp *http.Response, caps poolWindowCaps, now time.Time) (time.Time, bool) {
	if resp == nil || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return time.Time{}, false
	}
	return dualWindowPreCutDecision(resp.Header, caps, now)
}

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func windowSpecificReset(h http.Header, specific string, now time.Time) time.Time {
	keys := []string{specific}
	if specific == hdrReset5h {
		// The aggregate header predates explicit dual-window support and is
		// therefore a safe compatibility fallback only for the legacy 5h lane.
		keys = append(keys, hdrReset)
	}
	for _, key := range keys {
		if epoch, err := strconv.ParseInt(h.Get(key), 10, 64); err == nil && epoch > 0 {
			if t := time.Unix(epoch, 0); t.After(now) {
				return t
			}
		}
	}
	if specific == hdrReset7d {
		// Never release a weekly protection line on a 5-minute/default short
		// retry just because the provider omitted its weekly reset timestamp.
		// One week is the conservative upper bound. The account cannot provide a
		// newer reset while it is cooling, so recovery happens at this bound or
		// through an explicit operator/provider state refresh.
		return now.Add(7 * 24 * time.Hour)
	}
	return now.Add(poolCooldownDefault)
}

func codexDualWindowPreCut(h http.Header, caps poolWindowCaps, now time.Time) (time.Time, bool) {
	primaryIs5h := codexPrimaryIs5h(h)
	var until time.Time
	hit := false
	consider := func(is5h bool, usedHdr, resetAtHdr, resetAfterHdr string) {
		capPct := caps.SevenDay
		if is5h {
			capPct = caps.FiveHour
		}
		pct, ok := parseCodexPercent(h.Get(usedHdr))
		if !ok || !validWindowCap(capPct) || pct < float64(capPct) {
			return
		}
		hit = true
		until = laterTime(until, codexWindowReset(h.Get(resetAtHdr), h.Get(resetAfterHdr), now))
	}
	consider(primaryIs5h, "X-Codex-Primary-Used-Percent", "X-Codex-Primary-Reset-At", "X-Codex-Primary-Reset-After-Seconds")
	consider(!primaryIs5h, "X-Codex-Secondary-Used-Percent", "X-Codex-Secondary-Reset-At", "X-Codex-Secondary-Reset-After-Seconds")
	return until, hit
}

func codexPrimaryIs5h(h http.Header) bool {
	pMin := parseCodexInt(h.Get("X-Codex-Primary-Window-Minutes"))
	sMin := parseCodexInt(h.Get("X-Codex-Secondary-Window-Minutes"))
	switch {
	case pMin > 0 && sMin > 0:
		return pMin <= sMin
	case pMin > 0:
		return pMin <= codex5hThresholdMinutes
	case sMin > 0:
		return sMin > codex5hThresholdMinutes
	default:
		return true
	}
}

// codexWindowPreCut pre-cuts when ANY Codex quota window's utilization has
// reached the cap, cooling until that window's reset (the latest among over-cap
// windows). No 5h/7d classification is needed: we cool until the over-cap
// window's OWN reset, comparing per-window (the same insight as codexRateLimitReset
// and the D9 fix — never trust the primary/secondary name). Returns (zero,false)
// when the response carries no X-Codex-* util headers (not Codex traffic) or no
// window is at/over the cap.
func codexWindowPreCut(h http.Header, threshold float64, now time.Time) (time.Time, bool) {
	var coolUntil time.Time
	hit := false
	consider := func(usedHdr, resetAtHdr, resetAfterHdr string) {
		pct, ok := parseCodexPercent(h.Get(usedHdr))
		if !ok || pct/100.0 < threshold {
			return
		}
		hit = true
		if t := codexWindowReset(h.Get(resetAtHdr), h.Get(resetAfterHdr), now); t.After(coolUntil) {
			coolUntil = t
		}
	}
	consider("X-Codex-Primary-Used-Percent", "X-Codex-Primary-Reset-At", "X-Codex-Primary-Reset-After-Seconds")
	consider("X-Codex-Secondary-Used-Percent", "X-Codex-Secondary-Reset-At", "X-Codex-Secondary-Reset-After-Seconds")
	if !hit {
		return time.Time{}, false
	}
	if coolUntil.IsZero() || !coolUntil.After(now) {
		coolUntil = now.Add(poolCooldownDefault)
	}
	return coolUntil, true
}

// codexWindowReset picks the cool-until for one Codex window: prefer the ABSOLUTE
// X-Codex-*-Reset-At epoch (verified present live 2026-07-06 — Codex is NOT
// relative-only as sub2api's data implied), else now + the relative
// X-Codex-*-Reset-After-Seconds, else a conservative default. Never a past time.
func codexWindowReset(resetAtRaw, resetAfterRaw string, now time.Time) time.Time {
	if epoch := parseCodexInt(resetAtRaw); epoch > 0 {
		if t := time.Unix(int64(epoch), 0); t.After(now) {
			return t
		}
	}
	if secs := parseCodexInt(resetAfterRaw); secs > 0 {
		return now.Add(time.Duration(secs) * time.Second)
	}
	return now.Add(poolCooldownDefault)
}

// parseUtil reads a unified utilization header as a fraction 0~1. Returns
// (value, true) only when the header is present and parses to a sane number.
func parseUtil(h http.Header, key string) (float64, bool) {
	v := h.Get(key)
	if v == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return 0, false
	}
	return f, true
}

// observedResetEpoch reads the upstream's raw window-reset epoch (unified, else
// per-window) for Path Z's re-roll signal. Unlike windowResetTime it does NOT
// clamp to the future: master compares the raw epoch to its stored value to
// detect a new window, so a just-passed reset must still report its true epoch.
func observedWindowResetEpochs(h http.Header) (ObservedWindowResets, bool) {
	parse := func(key string) int64 {
		epoch, err := strconv.ParseInt(h.Get(key), 10, 64)
		if err != nil || epoch <= 0 {
			return 0
		}
		return epoch
	}
	resets := ObservedWindowResets{FiveHour: parse(hdrReset5h), SevenDay: parse(hdrReset7d)}
	if unified := parse(hdrReset); unified > 0 {
		// A unified reset has no window identity. Preserve the rolling-compatible
		// interpretation as the legacy/5h window only; copying it into 7d would let
		// a short reset incorrectly re-roll and release weekly protection.
		if resets.FiveHour == 0 {
			resets.FiveHour = unified
		}
	}
	if resets.FiveHour > 0 || resets.SevenDay > 0 {
		return resets, true
	}
	primary, secondary := int64(parseCodexInt(h.Get("X-Codex-Primary-Reset-At"))), int64(parseCodexInt(h.Get("X-Codex-Secondary-Reset-At")))
	if codexPrimaryIs5h(h) {
		resets.FiveHour, resets.SevenDay = primary, secondary
	} else {
		resets.FiveHour, resets.SevenDay = secondary, primary
	}
	return resets, resets.FiveHour > 0 || resets.SevenDay > 0
}

// observedResetEpoch keeps the old scalar test/upgrade contract by returning
// the sooner known boundary. New code must use observedWindowResetEpochs.
func observedResetEpoch(h http.Header) (int64, bool) {
	resets, ok := observedWindowResetEpochs(h)
	if !ok {
		return 0, false
	}
	if resets.FiveHour > 0 && (resets.SevenDay == 0 || resets.FiveHour <= resets.SevenDay) {
		return resets.FiveHour, true
	}
	return resets.SevenDay, true
}

// windowResetTime picks the cool-until time: prefer the unified reset epoch, then
// a per-window reset, else a conservative default. Never returns a past time.
func windowResetTime(h http.Header, now time.Time) time.Time {
	for _, key := range []string{hdrReset, hdrReset5h, hdrReset7d} {
		if v := h.Get(key); v != "" {
			if epoch, err := strconv.ParseInt(v, 10, 64); err == nil && epoch > 0 {
				if t := time.Unix(epoch, 0); t.After(now) {
					return t
				}
			}
		}
	}
	return now.Add(poolCooldownDefault)
}
