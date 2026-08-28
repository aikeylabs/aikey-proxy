package proxy

// license_plane_cache.go — this proxy's view of the deployment's forwarding gate.
//
// # Why this exists (workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md)
//
// The control plane has always computed a forwarding verdict. licstate's plane
// table gives `expired`, `grace_exhausted`, `revoked` and `stale` a
// `Forwarding: deny`, the control service projects that into a two-boolean
// PlaneProjection, and it serves the projection on `GET /v1/license/plane` with a
// comment naming the proxy as its consumer.
//
// Nothing read it. Not this repository, not any other: `ForwardingAllowed()` had
// exactly one caller and it was a test. So a deployment whose licence had expired
// kept forwarding every request, for ever, while the console correctly reported
// `expired` and correctly froze control-plane writes. For a product sold by seat
// that is the difference between an expiry date and a suggestion.
//
// 🔴 The trap worth naming, because it is what kept this invisible: the gate
// FAILS OPEN by design at every layer. PlaneGate starts `allow` so that start-up
// never stops a licensed deployment's traffic, and a nil gate answers `allow`
// too. Both defaults are right. Their consequence is that "nobody wired the
// consumer" and "everything is fine" are the same observable state — there was no
// red anywhere to notice. The fence that now prevents a recurrence is a POSITIVE
// one (hotpath_license_gate_fence_test.go asserts the gate IS reached from
// Proxy.Handle), because the pre-existing negative fence — "the hot path must not
// import licensing" — was green throughout, for the wrong reason.
//
// # What this file may and may not do
//
// 🚫 No licensing logic, and 🚫 no import of aikey-license-core. The whole
// authorization state machine stays in the control plane; what crosses to the
// data path is one word. specs/edition-entitlement requires a forwarding request
// to perform "no licence file read, database query, signature check or
// synchronous control call", and hotpath_callgraph_fence_test.go enforces the
// import half of that. A read here is one atomic load.
//
// 🚫 No file or network IO, in any method, even ones not on the hot path. The
// call-graph fence resolves method calls by NAME across the whole module, so an
// `os.ReadFile` in a hydrate helper on this type would trip the file-IO rule from
// wherever it lived. Persistence belongs to the rail that owns the polling, in
// internal/supervisor — this type is pure memory.

import (
	"sync/atomic"
	"time"
)

// The gate values the control plane sends. They are a WIRE CONTRACT with
// aikey-license-core's licstate.Gate, restated here as plain strings because the
// hot path may not import that module.
//
// 🔴 Restating a contract is normally how two implementations drift. It is
// tolerable here only because the rail REFUSES any third value rather than
// guessing (see supervisor.syncLicensePlane): an unrecognised gate is a failed
// cycle, which makes the rail go stale in /status and eventually trips the
// staleness ceiling below. A silent mapping of "unknown" to either answer is the
// thing that must not happen — allow would disable the gate on a wire change,
// deny would stop a paying fleet on one.
const (
	licenseGateAllow = "allow"
	licenseGateDeny  = "deny"
)

// LicensePlaneStaleCeiling bounds how long this proxy keeps honouring a gate
// value it can no longer refresh.
//
// 🔴 Seven days, and the number is a licensing decision rather than a timeout
// (owner decision 2026-08-27). Keep-last-known with NO ceiling is the obvious
// design and it is the one that makes the whole gate theatre: a customer who
// firewalls their own control plane the day before expiry keeps the last `allow`
// for ever. The ceiling is the proxy-side half of the same idea licstate already
// applies to the vendor relationship, where `stale` — an online deployment past
// its SIGNED check-in budget — also denies forwarding.
//
// Why seven days is the right size: the control plane here is the customer's OWN
// control-master, inside their own network, not a vendor endpoint. A proxy that
// cannot reach it for seven consecutive days is in an outage that has already
// stopped key sync, quota and usage reporting; whether AI forwarding still works
// is not that customer's live problem. Seven days also covers a weekend plus a
// public holiday, which is the realistic shape of "nobody is in the office".
//
// 🚫 Deliberately not configurable, for the reason keyRevocationPollInterval is
// not: how long an unlicensed deployment keeps serving is a property of the
// deployment, not a knob for the operator who benefits from widening it.
const LicensePlaneStaleCeiling = 7 * 24 * time.Hour

// licensePlaneState is one immutable observation. Replaced wholesale, never
// mutated, so a reader either sees the old one or the new one.
type licensePlaneState struct {
	// forwarding is the gate the control plane last gave us. The rail guarantees
	// it is one of the two constants above.
	forwarding string
	// observedAt is when that value was obtained — a live poll, or the timestamp
	// carried in the file a previous process left behind.
	observedAt time.Time
	// hydrated distinguishes "a previous process learned this" from "this process
	// learned this". It changes no decision; it is reported on /status so an
	// operator reading a `deny` can tell whether this proxy has actually spoken to
	// the control plane since it started.
	hydrated bool
}

// LicensePlaneCache holds the last known forwarding gate.
//
// Reads are a single atomic load: no lock, no allocation, no IO, which is what
// makes it safe to consult on every request.
type LicensePlaneCache struct {
	current atomic.Pointer[licensePlaneState]
	// now is injectable so the staleness ceiling can be tested without waiting
	// seven days. Production always uses time.Now.
	now func() time.Time
}

// NewLicensePlaneCache returns a cache that has never been synced.
//
// 🔴 It starts ALLOWING, and this is the one fail-open that must survive review.
// Three populations sit in this state and none of them may be refused:
//
//   - Personal, which has no control plane to ask and no licence to ask about;
//   - every deployment during the moments between process start and the rail's
//     first cycle;
//   - a freshly installed proxy that has not yet reached its control plane.
//
// Denying here would mean a licensing mechanism that stops correctly licensed
// deployments — the exact outcome R8 ("读不到不停服") exists to prevent, and the
// reason PlaneGate on the control-plane side starts allowing too.
//
// The residual escape this leaves is bounded and known: a proxy that NEVER once
// reaches its control plane is never gated. It is also never issued the virtual
// keys it would need to forward anything, because those arrive over that same
// control plane — so the hole is closed by a different mechanism rather than by
// this one. Stated here so the next reader does not mistake it for an oversight.
func NewLicensePlaneCache() *LicensePlaneCache {
	return &LicensePlaneCache{now: time.Now}
}

// Observe records a gate value obtained from a live poll.
func (c *LicensePlaneCache) Observe(forwarding string, at time.Time) {
	if c == nil {
		return
	}
	c.current.Store(&licensePlaneState{forwarding: forwarding, observedAt: at})
}

// Hydrate seeds the cache from state a previous process persisted, and 🚫 never
// overwrites a live observation.
//
// 🔴 Without hydration the ceiling above is worth very little: `deny` would live
// only in memory, and restarting the proxy — which any user may do, and which a
// crash does for them — would reset the cache to never-synced and forward again.
// A gate that a restart clears is not a gate.
func (c *LicensePlaneCache) Hydrate(forwarding string, observedAt time.Time) {
	if c == nil || observedAt.IsZero() {
		return
	}
	if c.current.Load() != nil {
		// A live cycle already answered. It is newer than anything on disk by
		// construction, and the rail hydrates before its first cycle anyway; this
		// guard makes the ordering explicit rather than assumed.
		return
	}
	c.current.Store(&licensePlaneState{forwarding: forwarding, observedAt: observedAt, hydrated: true})
}

// ForwardingAllowed is the one question the request path asks.
//
// 🚫 Do not add a second question here. The narrowness is the contract: a
// consumer that branched on a state name would have re-implemented the licence
// state machine on the hot path, which is what specs/edition-entitlement forbids
// and what keeping only two values on the wire is meant to make impossible.
func (c *LicensePlaneCache) ForwardingAllowed() bool {
	if c == nil {
		return true
	}
	st := c.current.Load()
	if st == nil {
		// Never synced. See NewLicensePlaneCache.
		return true
	}
	if c.now().Sub(st.observedAt) > LicensePlaneStaleCeiling {
		return false
	}
	return st.forwarding == licenseGateAllow
}

// LicensePlaneHealth is the /status projection of this cache.
//
// 🔴 It exists because of the health-signal-surface rule: a gate whose state can
// only be inferred from whether requests are failing is a gate nobody can operate
// or verify. The release E2E asserts against this rather than against a log line,
// and `Source` is the load-bearing field — an operator looking at a `deny` needs
// to know whether it came from the control plane a moment ago or from a file
// written by a process that exited last month.
type LicensePlaneHealth struct {
	Forwarding string `json:"forwarding"`
	Source     string `json:"source"`
	// LastSuccessAt is unix millis, 0 when never synced.
	LastSuccessAt int64 `json:"last_success_at,omitempty"`
	AgeSeconds    int64 `json:"age_seconds,omitempty"`
	// StaleCeilingSeconds is reported so the number in force is readable from
	// outside rather than being a constant a reader has to go and find.
	StaleCeilingSeconds int64 `json:"stale_ceiling_seconds"`
}

// Source values for LicensePlaneHealth.
const (
	// LicensePlaneSourceNeverSynced — no gate value has ever been obtained, so
	// forwarding is allowed. Personal sits here permanently.
	LicensePlaneSourceNeverSynced = "never_synced"
	// LicensePlaneSourceLive — obtained by this process from the control plane.
	LicensePlaneSourceLive = "live"
	// LicensePlaneSourceHydrated — read from the file a previous process left,
	// and not yet refreshed by a live cycle.
	LicensePlaneSourceHydrated = "hydrated"
	// LicensePlaneSourceStaleCeiling — a value exists but is older than the
	// ceiling, so it is no longer honoured and forwarding is refused.
	LicensePlaneSourceStaleCeiling = "stale_ceiling"
)

// Health snapshots the cache for /status.
func (c *LicensePlaneCache) Health() LicensePlaneHealth {
	ceiling := int64(LicensePlaneStaleCeiling / time.Second)
	if c == nil {
		return LicensePlaneHealth{
			Forwarding:          licenseGateAllow,
			Source:              LicensePlaneSourceNeverSynced,
			StaleCeilingSeconds: ceiling,
		}
	}
	st := c.current.Load()
	if st == nil {
		return LicensePlaneHealth{
			Forwarding:          licenseGateAllow,
			Source:              LicensePlaneSourceNeverSynced,
			StaleCeilingSeconds: ceiling,
		}
	}
	age := c.now().Sub(st.observedAt)
	out := LicensePlaneHealth{
		Forwarding:          st.forwarding,
		Source:              LicensePlaneSourceLive,
		LastSuccessAt:       st.observedAt.UnixMilli(),
		AgeSeconds:          int64(age / time.Second),
		StaleCeilingSeconds: ceiling,
	}
	if st.hydrated {
		out.Source = LicensePlaneSourceHydrated
	}
	if age > LicensePlaneStaleCeiling {
		// 🔴 Report the EFFECTIVE answer, not the stored one. A /status that said
		// `forwarding: allow` while every request was being refused would send an
		// operator looking for the fault in the wrong place entirely.
		out.Forwarding = licenseGateDeny
		out.Source = LicensePlaneSourceStaleCeiling
	}
	return out
}

// Synced reports whether any gate value is held. Used by the rail to decide
// whether persisting is worthwhile.
func (c *LicensePlaneCache) Synced() bool {
	return c != nil && c.current.Load() != nil
}

// Snapshot returns the stored observation for persistence. The second return is
// false when there is nothing to persist.
//
// 🔴 Returns the STORED value, not the effective one, and the distinction
// matters: writing the ceiling's `deny` to disk would freeze a deployment into a
// refusal that outlived the outage that caused it, and a later successful poll
// could no longer be told apart from the stale state it replaced.
func (c *LicensePlaneCache) Snapshot() (forwarding string, observedAt time.Time, ok bool) {
	if c == nil {
		return "", time.Time{}, false
	}
	st := c.current.Load()
	if st == nil {
		return "", time.Time{}, false
	}
	return st.forwarding, st.observedAt, true
}
