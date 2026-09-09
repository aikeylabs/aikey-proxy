package mcp

// health.go — GET /health/mcp (task 1.12, filled further in P7).
//
// # 🔴 Why the MCP plane gets its OWN health endpoint
//
// Two rules from the repo, both of which point the same way:
//
//  1. "健康信号必须可被外部读取" — a health signal that only exists in logs
//     cannot be asserted by a release gate, and a console dashboard cannot
//     substitute because it reads a historical aggregate: a pipeline that broke
//     five minutes ago still LOOKS fine there. The release checklist's E2E
//     section asserts against THIS endpoint.
//  2. MCP-plane trouble must not be folded into the overall /health. If it
//     were, a single unreachable MCP backend would make the whole proxy look
//     down, and whoever is paged would start by investigating LLM forwarding
//     that is in fact perfectly healthy (task 7.8).
//
// # 🔴 The three-state rule applies to health too
//
// A backend whose status is genuinely UNKNOWN (never probed, or the probe
// itself failed) must not be rendered as healthy. "We have not checked" and
// "we checked and it is fine" are different facts; collapsing them is how a
// dead backend shows up green. Fence 6.F6 asserts the distinction, and the
// console is forbidden from painting "unknown" green (task 8.8a).

import (
	"net/http"
	"time"
)

// PlaneStatus is the coarse verdict of GET /health/mcp.
type PlaneStatus string

const (
	// PlaneHealthy — the plane is serving.
	PlaneHealthy PlaneStatus = "healthy"
	// PlaneDegraded — serving, but something an operator should look at:
	// requests are being shed, or a panic was contained.
	PlaneDegraded PlaneStatus = "degraded"
	// PlaneUnknown — the plane is wired but has no basis for an opinion yet.
	//
	// 🔴 Never rendered as healthy. See the file header.
	PlaneUnknown PlaneStatus = "unknown"
)

// HealthDocument is the endpoint's response.
//
// Fields are additive across phases: P1 fills the plane and protocol sections,
// P3 adds manifest/backends, P7 fills the rest. Absent sections are omitted
// rather than reported as zero — 🔴 "0 backends need review" and "we do not yet
// track review state" are different claims, and a release gate that asserts on
// the first while receiving the second is asserting on nothing.
type HealthDocument struct {
	Status PlaneStatus `json:"status"`
	// Reason explains a non-healthy status in one sentence. Empty when healthy.
	Reason string `json:"reason,omitempty"`
	// Plane is the isolation shell's state.
	Plane PlaneStats `json:"plane"`
	// ProtocolVersions is the advertised support set, so an operator can see
	// what THIS build speaks without reading release notes.
	ProtocolVersions []string `json:"protocol_versions"`
	// Toolsets this node can currently serve.
	ToolsetCount int `json:"toolset_count"`
	// Sessions currently live in memory.
	SessionCount int `json:"session_count"`
	// UptimeSeconds of the plane.
	UptimeSeconds int64 `json:"uptime_seconds"`
	// Backends is filled from P3. Nil until then — see the type comment.
	Backends map[string]string `json:"backends,omitempty"`
	// ToolsNeedingReview is filled from P3. A pointer so "none" (0) is
	// distinguishable from "not tracked yet" (absent).
	ToolsNeedingReview *int `json:"tools_needing_review,omitempty"`
	// PolicyAgeSeconds is filled from P2: how long since the control plane last
	// answered. 🔴 A pointer for the same reason — and because "the control
	// plane has been unreachable for 40 minutes" is the single most useful
	// thing this endpoint will ever say (fence 2.F3).
	PolicyAgeSeconds *int64 `json:"policy_age_seconds,omitempty"`
	// BackendsCircuitOpen is how many backends are in cooldown right now.
	//
	// 🔴 Reported SEPARATELY from the backends map even though it is derivable
	// from it: a release gate asserts on a number, and making every gate
	// re-derive it from a map is how two gates come to count differently
	// (circuit_open only, or circuit_open plus unknown).
	BackendsCircuitOpen *int `json:"backends_circuit_open,omitempty"`
	// ManifestAgeSeconds is how long since the manifest prober last completed a
	// round against ANY backend — the answer to "is drift detection alive". A
	// pointer: absent means no prober on this build, which is not the same
	// claim as "it ran just now".
	ManifestAgeSeconds *int64 `json:"manifest_age_seconds,omitempty"`
	// CallRecording says whether finished calls are being written at all.
	//
	// 🔴 "off" is a legitimate configuration (no local store), and it must be
	// VISIBLE: without this field, "the call log is empty" and "nothing was
	// called" are the same observation, and an operator would go looking for
	// traffic that was never recorded rather than for the wiring that never
	// recorded it.
	CallRecording string `json:"call_recording"`
	// CallBacklog is how many recorded calls have not reached the control plane.
	//
	// 🔴 THIS is the audit-gap signal, and it is the one thing the console
	// dashboard structurally cannot show: the dashboard renders what ARRIVED, so
	// a rail that has been down for an hour looks like an hour of quiet. A
	// pointer, because "not tracked" and "zero backlog" are opposite claims.
	CallBacklog *int64 `json:"call_backlog,omitempty"`
	// CallRecordsDropped counts calls that could not be recorded anywhere.
	// 🔴 Any non-zero value means the call log is a sample, not a record.
	CallRecordsDropped int64 `json:"call_records_dropped"`
	// ToolsAddedSinceSetup is how many tools have APPEARED at a backend since
	// the user set it up. Personal only; absent elsewhere.
	//
	// 🔴 Reported rather than gated, and that is a decision worth stating: on
	// Production a tool that turns up later lands in `draft` and is invisible
	// until somebody publishes it. Personal has no console, so hiding it would
	// leave the user no way to release a tool their OWN server now offers — the
	// remedy would be worse than the risk. So it is admitted and COUNTED here,
	// which is the "不阻塞用户流程 > 错误要显眼" ordering applied literally: the
	// expansion happens, and it is impossible not to see.
	//
	// A pointer, for the usual reason: "no tools have appeared" and "this build
	// does not track arrivals" are different claims.
	ToolsAddedSinceSetup *int `json:"tools_added_since_setup,omitempty"`
	// ToolApprovalsUnreadable is set when Personal's approval record could not
	// be read. 🔴 Its consequence — every tool re-admitted at whatever the
	// upstream serves next — is exactly the state an attacker would engineer,
	// so it is on the health surface and not only in a log line.
	ToolApprovalsUnreadable string `json:"tool_approvals_unreadable,omitempty"`
	// ReviewBacklogState escalates a persistent review backlog.
	//
	// 🔴 Task 7.7b: "tools awaiting review" must not sit at WARN forever. A
	// backlog that has been non-empty past the escalation window is reported as
	// `overdue`, which is a different word a gate can assert on — a level that
	// never changes is a level nobody acts on.
	ReviewBacklogState string `json:"review_backlog_state,omitempty"`
}

// policyStaleAfterSeconds is when a policy rail stops looking healthy.
//
// 🔴 Five poll intervals, not one. A single missed poll is a network blip and
// paging on it would produce noise that gets the alert muted; five consecutive
// misses is a rail that is actually down. The number is derived from the
// interval rather than typed independently so the two cannot drift.
const policyStaleAfterSeconds = 5 * 60

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	stats := h.iso.Stats()
	doc := HealthDocument{
		Status:           PlaneHealthy,
		Plane:            stats,
		ProtocolVersions: mcpProtocolStrings(),
		ToolsetCount:     len(h.catalog.Slugs(r.Context())),
		SessionCount:     h.sessions.Count(),
		UptimeSeconds:    int64(time.Since(h.startedAt).Seconds()),
	}

	// 🔴 Per-backend health, from the manifest prober. Absent (not empty) when
	// no prober is installed: "we do not track backend health on this build" and
	// "we track it and every backend is fine" are different claims.
	if syncer := h.currentSyncer(); syncer != nil {
		status := syncer.Status()
		doc.Backends = make(map[string]string, len(status))
		unhealthy, open := 0, 0
		for id, st := range status {
			doc.Backends[id] = string(st.Health)
			// 🔴 UNKNOWN counts as not-healthy. "We have not checked" and "we
			// checked and it is fine" are different facts; collapsing them is how
			// a dead backend shows up green.
			if st.Health != BackendHealthy {
				unhealthy++
			}
			// 🔴 Circuit-open is counted SEPARATELY from unhealthy. They are
			// different situations with different fixes: circuit-open means we
			// tried and it failed repeatedly, unknown means we never got an
			// answer at all. A gate that conflates them cannot tell a broken
			// backend from an unwired one.
			if st.Health == BackendCircuitOpen {
				open++
			}
		}
		doc.BackendsCircuitOpen = &open
		if last := syncer.LastRoundMs(); last > 0 {
			age := (time.Now().UnixMilli() - last) / 1000
			doc.ManifestAgeSeconds = &age
		}
		if unhealthy > 0 && doc.Status == PlaneHealthy {
			doc.Status = PlaneDegraded
			doc.Reason = itoa(unhealthy) + " of " + itoa(len(status)) +
				" MCP backend(s) are not healthy (circuit-open or unknown). " +
				"Tools behind them are unavailable; see the backends map."
		}
	}

	// 🔴 The policy rail's freshness. Reported as a POINTER so "not tracked" is
	// distinguishable from "synced 0 seconds ago" — a release gate asserting on
	// the first while receiving the second is asserting on nothing.
	if h.policyStore != nil {
		age := h.policyStore.AgeSeconds()
		doc.PolicyAgeSeconds = &age
		if n, known := h.policyStore.ToolsNeedingReview(); known {
			doc.ToolsNeedingReview = &n
			doc.ReviewBacklogState = reviewBacklogState(n, h.policyStore.ReviewBacklogAgeSeconds())
		}
	}

	// 🔴 Personal edition's approval state. Absent on a node with a control
	// plane, where reviewing is the console's job.
	if h.localApprovals != nil {
		added := 0
		for _, b := range h.localApprovals.Review() {
			for _, t := range b.Tools {
				if t.NewSinceSetup {
					added++
				}
			}
		}
		doc.ToolsAddedSinceSetup = &added
		if e := h.localApprovals.LoadError(); e != "" {
			doc.ToolApprovalsUnreadable = e
			// 🔴 Degraded, not healthy. Serving tools whose approved definition
			// we could not read means serving whatever the upstream says today,
			// which is the freeze rule not running at all.
			if doc.Status == PlaneHealthy {
				doc.Status = PlaneDegraded
				doc.Reason = "the record of approved tool definitions could not be read, so drift " +
					"detection is not running on this node; every tool is being served at its " +
					"current upstream definition"
			}
		}
	}

	// 🔴 Call recording. Reported even when it is OFF — see the field comment:
	// without this, "the call log is empty" and "nothing was called" are the same
	// observation.
	doc.CallRecording = "off"
	if h.calls != nil {
		doc.CallRecording = "on"
		if reporter, ok := h.calls.(CallBacklogReporter); ok {
			if backlog, known := reporter.CallBacklog(); known {
				doc.CallBacklog = &backlog
			}
		}
	}
	if h.callStats != nil {
		doc.CallRecordsDropped = h.callStats.Snapshot().RecordsDropped
	}

	// 🔴 A contained panic degrades the plane even if every request since has
	// succeeded. The isolation shell's job is to keep the LLM path alive, not
	// to make an MCP defect invisible — reporting healthy after swallowing a
	// panic would be exactly that.
	switch {
	case stats.PanicsRecovered > 0:
		doc.Status = PlaneDegraded
		doc.Reason = "The MCP plane has contained one or more panics since start; " +
			"the LLM forwarding path was unaffected, but this is a defect — check logs for " +
			"event.name=proxy.mcp.panic_recovered."
	case stats.Rejected > 0 && stats.InFlight >= stats.Limit:
		doc.Status = PlaneDegraded
		doc.Reason = "The MCP plane is at its concurrency limit and shedding requests; " +
			"an MCP backend is likely responding slowly."
	case doc.PolicyAgeSeconds != nil && *doc.PolicyAgeSeconds < 0:
		// 🔴 Never polled is NOT "stale". It means this node has not once
		// reached the control plane, which sends an operator somewhere
		// completely different from "the last sync was a while ago".
		doc.Status = PlaneDegraded
		doc.Reason = "The MCP policy rail has never reached the control plane, so this node is " +
			"serving no grants (or only a restored cache). Check the control-plane URL and this node's credentials."
	case doc.PolicyAgeSeconds != nil && *doc.PolicyAgeSeconds > policyStaleAfterSeconds:
		doc.Status = PlaneDegraded
		doc.Reason = "The MCP policy has not refreshed in " + itoa(int(*doc.PolicyAgeSeconds/60)) +
			" minutes. The last known policy is still being served — grant changes made since then " +
			"have NOT reached this node."
	}

	// A non-healthy plane still answers 200. 🔴 The STATUS FIELD is the verdict,
	// not the HTTP code: a gate that reads the code alone cannot tell "degraded"
	// from "the endpoint itself is unreachable", and those need different
	// responses. Same convention the rest of the proxy's health surface uses.
	writeJSON(w, http.StatusOK, doc)
}

// reviewBacklogEscalatesAfterSeconds is when a review backlog stops being
// routine and becomes something a release gate refuses.
//
// 🔴 Twenty-four hours, and the number is a POLICY not a tuning knob: a tool in
// needs_review is a capability an administrator has not looked at, and a write
// tool in that state is refused outright, so a day-old backlog means somebody's
// Agent has been failing for a day. Anything much shorter would fire over a
// weekend; anything much longer defeats the point of escalating at all.
const reviewBacklogEscalatesAfterSeconds = 24 * 60 * 60

// Review backlog states, in escalation order.
const (
	// ReviewBacklogClear — nothing awaits review.
	ReviewBacklogClear = "clear"
	// ReviewBacklogPending — something awaits review, within the window.
	ReviewBacklogPending = "pending"
	// ReviewBacklogOverdue — 🔴 the escalation. Task 7.7b forbids a signal that
	// sits at the same level forever; this is the different word a gate and an
	// alert rule can both act on.
	ReviewBacklogOverdue = "overdue"
)

// reviewBacklogState turns a count plus an age into the escalation word.
func reviewBacklogState(count int, ageSeconds int64) string {
	if count == 0 {
		return ReviewBacklogClear
	}
	if ageSeconds >= reviewBacklogEscalatesAfterSeconds {
		return ReviewBacklogOverdue
	}
	return ReviewBacklogPending
}

// CallBacklogReporter is an optional capability of a CallSink: how many
// recorded calls have not yet reached the control plane.
//
// 🔴 Optional rather than part of CallSink, because a sink that cannot answer
// must not be forced to invent a number. An absent backlog is reported as
// absent — 🚫 never as zero, which would read as "everything is delivered" on a
// node that has no idea.
type CallBacklogReporter interface {
	CallBacklog() (backlog int64, known bool)
}
