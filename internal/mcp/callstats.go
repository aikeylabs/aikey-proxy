package mcp

// callstats.go — the in-memory counters behind GET /metrics.
//
// # 🔴 Metrics and health answer DIFFERENT questions, and must not be mixed
//
//	metrics  a TREND, for the customer's monitoring system. "How many calls,
//	         what share failed, how slow." Read on a schedule, graphed, alerted
//	         on when it MOVES.
//	health   a FACT, right now, for the release gate. "Is the policy rail fresh,
//	         is any backend circuit-open, how many tools await review." Read once
//	         and asserted on.
//
// Task 7.6a exists because collapsing them is a real failure: a counter cannot
// say "the control plane has been unreachable for 40 minutes", and a health
// document cannot say "error rate doubled at 03:00". Two surfaces, two purposes.
//
// 🔴 And neither of them is the console dashboard. The dashboard reads a
// historical aggregate, so a reporting pipeline that broke five minutes ago
// still LOOKS fine there — which is precisely why the release checklist asserts
// against /health/mcp instead (task 7.6b, and the repo's health-signal rule).
//
// # Why counters and not a histogram library
//
// The proxy's /metrics is a JSON document, not a Prometheus exposition, and
// pulling in a metrics library for one plane would give this plane a different
// vocabulary from every other counter on that endpoint. Latency is bucketed
// into fixed bands, which is what an operator actually reads off a dashboard.

import (
	"sync"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// CallStats accumulates call counters for the life of the process.
//
// 🔴 Process-lifetime totals, never rates. A rate computed here would be a
// second opinion about a number the customer's monitoring system is already
// computing from these totals, and the two would disagree at every scrape
// boundary.
type CallStats struct {
	mu sync.Mutex
	// byStatus is keyed by the mcp_call_event status domain, so "how many were
	// refused, and refused HOW" is answerable without a second counter set.
	byStatus map[string]int64
	byTool   map[string]int64
	// bySession counts distinct sessions seen, which is task 7.5's "session
	// dimension": it is what distinguishes one agent making 500 calls from 500
	// agents making one each — the same total, very different situations.
	bySession map[string]int64
	latency   latencyBands
	total     int64
	// dropped counts records that could not be recorded at all. 🔴 Exposed, not
	// swallowed: "we lost audit rows" must be a number an operator can see, or
	// the audit trail silently becomes a sample.
	dropped int64
}

// latencyBands are fixed duration buckets, in milliseconds.
//
// 🔴 Cumulative-free plain counts, and the bucket EDGES are part of the metric
// name so a dashboard cannot silently re-bucket. Edges chosen around what an
// MCP backend actually is: a local process (single-digit ms), a service on the
// customer's network (tens), a third-party SaaS (hundreds), and trouble.
type latencyBands struct {
	Under10   int64 `json:"lt_10ms"`
	Under100  int64 `json:"lt_100ms"`
	Under1000 int64 `json:"lt_1000ms"`
	Under5000 int64 `json:"lt_5000ms"`
	Over5000  int64 `json:"gte_5000ms"`
}

// NewCallStats builds an empty counter set.
func NewCallStats() *CallStats {
	return &CallStats{
		byStatus:  make(map[string]int64),
		byTool:    make(map[string]int64),
		bySession: make(map[string]int64),
	}
}

// Observe folds one finished record into the counters.
func (s *CallStats) Observe(rec mcpwire.CallRecord) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	s.byStatus[rec.Status]++
	if rec.ToolName != "" {
		s.byTool[rec.ToolName]++
	}
	if rec.SessionID != "" {
		s.bySession[rec.SessionID]++
	}
	switch {
	case rec.DurationMs < 10:
		s.latency.Under10++
	case rec.DurationMs < 100:
		s.latency.Under100++
	case rec.DurationMs < 1000:
		s.latency.Under1000++
	case rec.DurationMs < 5000:
		s.latency.Under5000++
	default:
		s.latency.Over5000++
	}
}

// NoteDropped records that one call could not be persisted anywhere.
func (s *CallStats) NoteDropped() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.dropped++
	s.mu.Unlock()
}

// CallMetrics is the /metrics view of this plane.
//
// 🔴 Field names come from MetricNames below rather than being typed here as
// literals — task 7.6c. A metric name is a contract with whatever alerts on it,
// and renaming one by editing a struct tag is how an alert goes quiet without
// anybody's alert going off.
type CallMetrics struct {
	CallsTotal      int64            `json:"mcp_calls_total"`
	CallsByStatus   map[string]int64 `json:"mcp_calls_by_status"`
	CallsByTool     map[string]int64 `json:"mcp_calls_by_tool"`
	SessionsSeen    int              `json:"mcp_sessions_seen"`
	CallsPerSession map[string]int64 `json:"mcp_calls_per_session"`
	LatencyMs       latencyBands     `json:"mcp_call_latency_ms"`
	// SuccessRatio is served pre-computed because every consumer would otherwise
	// compute it from the same two numbers, and half of them would divide by
	// zero on a quiet node. -1 means "no calls yet" — 🔴 not 0, which would read
	// as "everything is failing" on a node that has simply not been used.
	SuccessRatio float64 `json:"mcp_call_success_ratio"`
	// RecordsDropped is the audit-gap counter. 🔴 Any non-zero value here means
	// the call log is incomplete.
	RecordsDropped int64 `json:"mcp_call_records_dropped_total"`
	// BackendsCircuitOpen and ToolsNeedingReview are repeated from health on
	// purpose: an operator graphing "how often are we circuit-open" needs the
	// series, and the release gate needs the instantaneous fact. Same number,
	// two audiences — but 🔴 the GATE reads /health/mcp, never this (7.6b).
	BackendsCircuitOpen int `json:"mcp_backends_circuit_open"`
	ToolsNeedingReview  int `json:"mcp_tools_needing_review"`
}

// MetricNames is the central enumeration of every metric this plane publishes.
//
// 🔴 Task 7.6c: no metric name may appear as a literal in code. The fence
// (TestMetricNamesAreNotLiteralsInCode) reads the JSON tags off CallMetrics and
// asserts each one is listed here, so adding a field without registering its
// name goes red — and so a rename shows up as a deliberate edit to a list
// somebody has to look at.
var MetricNames = []string{
	"mcp_calls_total",
	"mcp_calls_by_status",
	"mcp_calls_by_tool",
	"mcp_sessions_seen",
	"mcp_calls_per_session",
	"mcp_call_latency_ms",
	"mcp_call_success_ratio",
	"mcp_call_records_dropped_total",
	"mcp_backends_circuit_open",
	"mcp_tools_needing_review",
}

// Snapshot renders the counters. Maps are copied: handing out the live map
// would let a JSON encoder read it while Observe writes.
func (s *CallStats) Snapshot() CallMetrics {
	if s == nil {
		return CallMetrics{SuccessRatio: -1}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := CallMetrics{
		CallsTotal:      s.total,
		CallsByStatus:   copyCounts(s.byStatus),
		CallsByTool:     copyCounts(s.byTool),
		SessionsSeen:    len(s.bySession),
		CallsPerSession: copyCounts(s.bySession),
		LatencyMs:       s.latency,
		RecordsDropped:  s.dropped,
		SuccessRatio:    -1,
	}
	if s.total > 0 {
		m.SuccessRatio = float64(s.byStatus[mcpwire.CallStatusOK]) / float64(s.total)
	}
	return m
}

func copyCounts(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// CallMetrics exposes the plane's counters for GET /metrics.
//
// Returns nil when this handler has no counter set, so the endpoint OMITS the
// block rather than rendering zeros — 🔴 "this build has no MCP plane" and "it
// has one and nobody has used it" are different facts.
func (h *Handler) CallMetrics() *CallMetrics {
	if h == nil || h.callStats == nil {
		return nil
	}
	m := h.callStats.Snapshot()
	// 🔴 The two operational numbers are folded in HERE rather than tracked by
	// the counter set: they are facts about the CURRENT world (how many
	// backends are circuit-open, how many tools await review), and a counter
	// that remembered them would report a state that has since changed.
	if syncer := h.currentSyncer(); syncer != nil {
		for _, st := range syncer.Status() {
			if st.Health == BackendCircuitOpen {
				m.BackendsCircuitOpen++
			}
		}
	}
	if h.policyStore != nil {
		if n, known := h.policyStore.ToolsNeedingReview(); known {
			m.ToolsNeedingReview = n
		}
	}
	return &m
}
