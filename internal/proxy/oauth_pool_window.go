// oauth_pool_window.go — N10: window randomized-cap pre-cut (防封).
//
// An account that runs its quota window to 100% looks like abuse to the upstream.
// To stay under the wall, master generates a RANDOMIZED cap per account+window
// (window_max_util_pct, 95-99, N11) and delivers it in the group material. The
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
func stashWindowCap(r *http.Request, capPct int) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyPoolWindowCap, capPct))
}

// windowCapFromContext reads the stashed cap (false when absent → no pre-cut).
func windowCapFromContext(req *http.Request) (int, bool) {
	v, ok := req.Context().Value(ctxKeyPoolWindowCap).(int)
	return v, ok
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
	if capPct <= 0 || capPct >= 100 {
		return time.Time{}, false
	}
	threshold := float64(capPct) / 100.0
	u5h, has5h := parseUtil(h, hdrUtil5h)
	u7d, has7d := parseUtil(h, hdrUtil7d)
	if !has5h && !has7d {
		return time.Time{}, false // no utilization signal → nothing to pre-cut on
	}
	if u5h < threshold && u7d < threshold {
		return time.Time{}, false // both windows below cap → fine
	}
	return windowResetTime(h, now), true
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
func observedResetEpoch(h http.Header) (int64, bool) {
	for _, key := range []string{hdrReset, hdrReset5h, hdrReset7d} {
		if v := h.Get(key); v != "" {
			if epoch, err := strconv.ParseInt(v, 10, 64); err == nil && epoch > 0 {
				return epoch, true
			}
		}
	}
	return 0, false
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
