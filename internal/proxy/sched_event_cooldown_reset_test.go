package proxy

// sched_event_cooldown_reset_test.go — fence for R-oauth-account-pool-4.3
// (UD-98): the proxy.group.account_cooldown scheduling event carries BOTH the
// Worker's local cooldown deadline (`until`) and, whenever the upstream reports
// a concrete window full, that window's reset (`reset_at`, epoch seconds; the
// latest one when several windows are full). `reset_at` is the upstream's raw
// reset whenever the upstream sent a readable one; for a full Codex window with
// no usable reset header, codexWindowReset substitutes now+poolCooldownDefault,
// and that substitute is what both this row and the master get. Every case
// below sends readable resets, so here it is always the raw value.
//
// Why the extra key: a full Codex window cools the Worker for at most one hour
// (the Codex exception in R-oauth-account-pool-4, Ask-2 option 甲), so `until`
// is the capped value. The master is still told the window's reset
// (exhaustedWindowResets → window_statuses) and keeps the account blocked until
// then, but the scheduling log showed only the cap: nobody reading it later
// could tell when the account really came back, and "how long should the cap
// be" had no samples to answer it.
//
// Chain fence, not a field fence (hand-copied-relay lesson): every case sends a
// REAL request through Handle → group lane → upstream 429 → the ModifyResponse
// cooldown hook → the signal reporter → ONE upload to a stand-in master, and
// reads two things out of that single body: the row's `detail`, and the
// `window_statuses` the master blocks the account on. Every case pins:
//   - the exact detail key set: the row is additive-only, so `status` and
//     `until` must survive any rewrite of accountCooldownEventDetail and no
//     stray key may appear;
//   - `reset_at` == the latest reset in those window_statuses: one observation
//     feeds both sinks, and a second computation on either side would let the
//     log and the master's block drift apart without any other test noticing.
//
// The master keeps detail verbatim (json.RawMessage into
// scheduling_event_log.detail) and both log pages render it with
// JSON.stringify, so this body is the last hop where a key can be lost.
//
// spec: R-oauth-account-pool-4.3.S1 冷却调度事件同时记本地冷却截止和真实恢复时间
// roadmap20260320/技术实现/update/20260924-Codex冷却例外补全与提示显示恢复时间.md

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestAccountCooldownEvent_CarriesRawResetAt(t *testing.T) {
	const (
		threeHours = 3 * time.Hour
		fiveDays   = 5 * 24 * time.Hour
	)

	t.Run("codex window full: until is the 1h Worker cap, reset_at the raw 3h reset", func(t *testing.T) {
		before := time.Now()
		upstream := codexUsageHeaders(before,
			codexWindowUsage{usedPct: 100, resetIn: threeHours}, // the full window
			codexWindowUsage{usedPct: 40, resetIn: fiveDays})    // on the wire too, but NOT full
		up, after := coolPoolAccountOnce(t, cooldownFenceCodexLane, upstream, before)

		assertDetailKeys(t, up.detail, "status", "until", "reset_at")
		// The Codex exception in R-oauth-account-pool-4: the local cooldown stops at 1h.
		assertEpochWithin(t, up.detail, "until", before.Add(time.Hour), after.Add(time.Hour))
		// The upstream's own epoch for the full window — not a recomputation, and
		// not the later reset of the window that is not full.
		assertDetailInt(t, up.detail, "reset_at", before.Add(threeHours).Unix())
		assertResetAtMatchesDeliveredWindows(t, up)
	})

	t.Run("codex both windows full: reset_at is the later of the two raw resets", func(t *testing.T) {
		before := time.Now()
		upstream := codexUsageHeaders(before,
			codexWindowUsage{usedPct: 100, resetIn: threeHours},
			codexWindowUsage{usedPct: 100, resetIn: fiveDays})
		up, after := coolPoolAccountOnce(t, cooldownFenceCodexLane, upstream, before)

		assertDetailKeys(t, up.detail, "status", "until", "reset_at")
		assertEpochWithin(t, up.detail, "until", before.Add(time.Hour), after.Add(time.Hour))
		assertDetailInt(t, up.detail, "reset_at", before.Add(fiveDays).Unix())
		assertResetAtMatchesDeliveredWindows(t, up)
	})

	t.Run("anthropic window full: reset_at is written for every provider, not only Codex", func(t *testing.T) {
		before := time.Now()
		resetAt := before.Add(threeHours).Unix()
		upstream := http.Header{}
		upstream.Set("anthropic-ratelimit-unified-status", "rate_limited")
		upstream.Set("anthropic-ratelimit-unified-5h-status", "rate_limited")
		upstream.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(resetAt, 10))
		upstream.Set("anthropic-ratelimit-unified-7d-utilization", "0.4") // not full
		upstream.Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(before.Add(fiveDays).Unix(), 10))
		up, _ := coolPoolAccountOnce(t, cooldownFenceAnthropicLane, upstream, before)

		assertDetailKeys(t, up.detail, "status", "until", "reset_at")
		// Anthropic's concrete window reset is authoritative (no 1h cap), so the
		// two keys agree; reset_at is still written so rows read the same way
		// whichever provider produced them.
		assertDetailInt(t, up.detail, "until", resetAt)
		assertDetailInt(t, up.detail, "reset_at", resetAt)
		assertResetAtMatchesDeliveredWindows(t, up)
	})

	t.Run("BUT NOT: a temporary limit (no window full) writes no reset_at", func(t *testing.T) {
		before := time.Now()
		upstream := codexUsageHeaders(before,
			codexWindowUsage{usedPct: 80, resetIn: threeHours},
			codexWindowUsage{usedPct: 40, resetIn: fiveDays})
		upstream.Set("Retry-After", "20")
		up, _ := coolPoolAccountOnce(t, cooldownFenceCodexLane, upstream, before)

		if raw, present := up.detail["reset_at"]; present {
			t.Fatalf("detail.reset_at = %v on a temporary limit: both windows' resets ride on every "+
				"Codex response, but neither window is full, so there is no recovery wall to record; detail=%v",
				raw, up.detail)
		}
		// Still a cooldown row with its local deadline — otherwise the absence
		// above would prove nothing.
		assertDetailKeys(t, up.detail, "status", "until")
		// The other sink agrees: no window is full, so none is delivered to the master.
		if len(up.windows) != 0 {
			t.Fatalf("window_statuses = %+v on a temporary limit, want none: no window is full", up.windows)
		}
	})
}

type cooldownFenceLane int

const (
	cooldownFenceCodexLane cooldownFenceLane = iota
	cooldownFenceAnthropicLane
)

const (
	cooldownFenceAccountID    = "acc-cool"
	cooldownFenceCredentialID = "cred-cool"
)

type codexWindowUsage struct {
	usedPct int
	resetIn time.Duration
}

// cooldownUpload is what the stand-in master received for one request, read
// out of ONE upload body: the account_cooldown row's detail and the window
// states delivered alongside it.
type cooldownUpload struct {
	detail  map[string]any
	windows []windowStatusSample
}

// codexUsageHeaders mirrors the live Codex wire: each window carries its used
// percent and BOTH reset forms (absolute epoch and seconds-after), full or not.
func codexUsageHeaders(now time.Time, primary, secondary codexWindowUsage) http.Header {
	h := http.Header{}
	for _, w := range []struct {
		prefix string
		usage  codexWindowUsage
	}{{"X-Codex-Primary-", primary}, {"X-Codex-Secondary-", secondary}} {
		h.Set(w.prefix+"Used-Percent", strconv.Itoa(w.usage.usedPct))
		h.Set(w.prefix+"Reset-After-Seconds", strconv.Itoa(int(w.usage.resetIn/time.Second)))
		h.Set(w.prefix+"Reset-At", strconv.FormatInt(now.Add(w.usage.resetIn).Unix(), 10))
	}
	return h
}

// coolPoolAccountOnce sends ONE request through the real group lane of a
// one-account pool, lets the upstream answer 429 with the given headers, and
// flushes the reporter the way signalReporter.loop's ticker does: queued events
// and the live window-status snapshot go to a stand-in master in ONE upload.
// It returns the account_cooldown row's detail (numbers kept as json.Number, so
// an integer epoch can be told from a float or a string) and the
// window_statuses from that same body, after checking that the row still
// carries the upstream status. `after` is read once Handle returns, so
// [before, after] brackets the hook's own time.Now().
func coolPoolAccountOnce(t *testing.T, lane cooldownFenceLane, upstream http.Header, before time.Time) (up cooldownUpload, after time.Time) {
	t.Helper()
	// The Codex lane may write side files (model capture, turn-state ledger)
	// under HOME; keep them out of the developer's real home.
	t.Setenv("HOME", t.TempDir())

	key := grKey()
	var (
		ref     vkeys.GroupAccountRef
		account vkeys.GroupRuntimeAccount
		route   *vkeys.ResolvedRoute
		req     *http.Request
	)
	switch lane {
	case cooldownFenceCodexLane:
		ref = vkeys.GroupAccountRef{AccountID: cooldownFenceAccountID, CredentialID: cooldownFenceCredentialID, ProviderCode: "openai", ProtocolType: "openai_compatible"}
		account = vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ProviderCode: "openai", ProtocolType: "openai_compatible", ExpiresAt: 9_000_000_000}
		route = &vkeys.ResolvedRoute{VirtualKeyID: "vk-grp-cool", ProtocolType: "openai_compatible", RouteSource: "team"}
		req = httptest.NewRequest(http.MethodPost, "/responses",
			strings.NewReader(`{"model":"gpt-5-codex","input":"hi","stream":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer aikey_team_grouptest") // setupGroupProxy's registry key
	case cooldownFenceAnthropicLane:
		ref = vkeys.GroupAccountRef{AccountID: cooldownFenceAccountID, CredentialID: cooldownFenceCredentialID, ProviderCode: "anthropic"}
		account = vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-cool"}
		route = &vkeys.ResolvedRoute{VirtualKeyID: "vk-grp-cool", Provider: "anthropic", ProtocolType: "anthropic", ProviderCode: "anthropic", RouteSource: "team"}
		req, _ = groupReq(groupBody)
	default:
		t.Fatalf("unknown lane %d", lane)
	}
	route.SeatID, route.OauthGroupID = "seat-cool", "grp-cool"
	route.GroupAccounts = mustJSON(t, []vkeys.GroupAccountRef{ref})
	route.GroupRuntime = mustJSON(t, map[string]vkeys.GroupRuntimeAccount{cooldownFenceAccountID: encMat(t, key, account, "oauth-tok-cool")})

	p, tr := setupGroupProxy(t, key, route)
	tr.status = http.StatusTooManyRequests
	tr.respHeader = upstream

	posted := make(chan []byte, 4)
	master := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		posted <- b
	}))
	t.Cleanup(master.Close)
	reporter := looplessSignalReporter()
	reporter.configure(master.URL, "src-cooldown-fence", func(context.Context) (string, error) { return "tok", nil })
	// Same wiring as the proxy constructor: the reporter reads window states
	// straight from the cooldown store that the hook writes.
	reporter.setWindowStatusSource(p.poolCooldown.windowStatusSnapshot)
	p.signalReporter = reporter

	w := httptest.NewRecorder()
	p.Handle(w, req)
	after = time.Now()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("a one-account pool must flush the upstream 429 through, got %d: %s", w.Code, w.Body.String())
	}

	pending := newSignalTrendAccumulator()
drain:
	for {
		select {
		case ev := <-reporter.evIn:
			if !pending.addEvent(ev) {
				t.Fatal("accumulator refused an event below its bound")
			}
		default:
			break drain
		}
	}
	util, revoked, rates, concurrency, events := pending.slices()
	if ok, why := reporter.uploadAllWithObservedResets(util, revoked, nil, rates, concurrency, events,
		reporter.snapshotWindowStatuses(), nil); !ok {
		t.Fatalf("upload to the stand-in master failed: %s", why)
	}
	var body []byte
	select {
	case body = <-posted:
	default:
		t.Fatal("nothing reached the stand-in master after an upstream 429")
	}
	var payload struct {
		Events []struct {
			EventName string         `json:"event_name"`
			Detail    map[string]any `json:"detail"`
		} `json:"events"`
		WindowStatuses []windowStatusSample `json:"window_statuses"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		t.Fatalf("uploaded payload is not JSON: %v", err)
	}
	for _, ev := range payload.Events {
		if ev.EventName != observability.EventProxyGroupAccountCooldown {
			continue
		}
		// The row keeps the upstream status it always carried. status moved from
		// a call-site literal into accountCooldownEventDetail, so pin it here.
		assertDetailInt(t, ev.Detail, "status", http.StatusTooManyRequests)
		return cooldownUpload{detail: ev.Detail, windows: payload.WindowStatuses}, after
	}
	t.Fatalf("no %s row in the uploaded payload: %s", observability.EventProxyGroupAccountCooldown, body)
	return cooldownUpload{}, after
}

// assertDetailKeys pins the row's exact shape. The row is additive-only:
// `status` and `until` must survive any rewrite of accountCooldownEventDetail,
// and no stray key may appear.
func assertDetailKeys(t *testing.T, detail map[string]any, want ...string) {
	t.Helper()
	got := slices.Sorted(maps.Keys(detail))
	want = slices.Sorted(slices.Values(want))
	if !slices.Equal(got, want) {
		t.Fatalf("detail keys = %v, want exactly %v; detail=%v", got, want, detail)
	}
}

// assertResetAtMatchesDeliveredWindows pins "one observation feeds both sinks"
// (the account_cooldown branch in forward_and_resolve.go): the row's reset_at
// must equal the latest reset in the window state that the SAME upload hands
// the master, which is what the master blocks the account on.
func assertResetAtMatchesDeliveredWindows(t *testing.T, up cooldownUpload) {
	t.Helper()
	if len(up.windows) != 1 || up.windows[0].CredentialID != cooldownFenceCredentialID {
		t.Fatalf("window_statuses = %+v, want exactly one sample for %s", up.windows, cooldownFenceCredentialID)
	}
	delivered := max(up.windows[0].WindowResetAt, up.windows[0].Window7dResetAt)
	got, present := detailInt(t, up.detail, "reset_at")
	if !present || got != delivered {
		t.Fatalf("detail.reset_at = %d (present=%v), but the window state delivered to the master in the same "+
			"upload resets at %d: the log row and the master's block must come from one observation; "+
			"windows=%+v detail=%v", got, present, delivered, up.windows, up.detail)
	}
}

// detailInt reads detail[key] as the JSON integer the master stores; a float,
// a string or a quoted number fails loudly instead of reading as absent.
func detailInt(t *testing.T, detail map[string]any, key string) (int64, bool) {
	t.Helper()
	raw, present := detail[key]
	if !present {
		return 0, false
	}
	n, isNumber := raw.(json.Number)
	if !isNumber {
		t.Fatalf("detail.%s = %#v, want a JSON number", key, raw)
	}
	v, err := n.Int64()
	if err != nil {
		t.Fatalf("detail.%s = %s, want an integer: %v", key, n, err)
	}
	return v, true
}

func assertDetailInt(t *testing.T, detail map[string]any, key string, want int64) {
	t.Helper()
	got, present := detailInt(t, detail, key)
	if !present {
		t.Fatalf("detail.%s missing; detail=%v", key, detail)
	}
	if got != want {
		t.Fatalf("detail.%s = %d, want %d (off by %d); detail=%v", key, got, want, got-want, detail)
	}
}

func assertEpochWithin(t *testing.T, detail map[string]any, key string, lo, hi time.Time) {
	t.Helper()
	got, present := detailInt(t, detail, key)
	if !present {
		t.Fatalf("detail.%s missing; detail=%v", key, detail)
	}
	if got < lo.Unix() || got > hi.Unix() {
		t.Fatalf("detail.%s = %d, want within [%d, %d]; detail=%v", key, got, lo.Unix(), hi.Unix(), detail)
	}
}
