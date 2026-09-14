package asyncscan

import (
	"time"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// Event is one asynchronous compliance event, in the shape master's intake
// expects (aikey-control-master service/internal/compliance/handler.go).
//
// 🔴 Declared here rather than reusing the detector's intake.Event because that
// type lives in ai-compliance-detector/internal and is unreachable by import —
// and because these events are built by the PROXY, from a remote result, with
// fields the detector never sets. The JSON tags are the contract; the fence
// TestAsyncScanEvents_CarryProxyStampedIdentityAndNoContent checks them by name.
//
// 🚫 There is deliberately NO snippet field of any kind. A remote result carries
// no content (design §3.1), and adding somewhere to put content here is how it
// would start travelling.
type Event struct {
	EventID      string    `json:"event_id"`
	CreatedAt    time.Time `json:"created_at"`
	TenantID     string    `json:"tenant_id"`
	Scenario     string    `json:"scenario"`
	ActionTaken  string    `json:"action_taken"`
	PromptLength int       `json:"prompt_length"`

	// Identity the PROXY resolved. The receiver never saw any of it.
	VirtualKeyID string `json:"virtual_key_id,omitempty"`
	SeatID       string `json:"seat_id,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	TraceID      string `json:"trace_id,omitempty"`

	Findings []Finding `json:"findings"`

	// ScanCoverage is attached only when master advertised support for it
	// (design §4b.12). A nil pointer is how an older master sees no new field.
	ScanCoverage *Coverage `json:"scan_coverage,omitempty"`
}

// Finding is one hit in the master intake wire shape.
type Finding struct {
	FindingID   string `json:"finding_id"`
	RuleID      string `json:"rule_id,omitempty"`
	Category    string `json:"category"`
	EntityType  string `json:"entity_type"`
	Severity    string `json:"severity"`
	Confidence  int    `json:"confidence"`
	StartOffset int    `json:"start_offset"`
	EndOffset   int    `json:"end_offset"`
	Detector    string `json:"detector,omitempty"`
}

// BuildEvents turns a merged result into the events to upload.
//
// One event per ENGINE, never per finding: the audit unit is "this piece of
// content, as seen by this engine". Per-finding events would multiply one
// violation into a page of rows, which is the flood the content-derived event id
// exists to prevent in the first place.
//
// Identity is stamped HERE. It is the last point in the pipeline that knows the
// seat, the session and the trace — the receiver was deliberately never told
// them, and master cannot infer them.
func BuildEvents(m MergedResult, id RequestIdentity) []Event {
	if len(m.Findings) == 0 {
		return nil
	}
	byEngine := map[string][]deepscan.Finding{}
	for _, f := range m.Findings {
		engine := f.Engine
		if engine == "" {
			engine = deepscan.EngineRules
		}
		byEngine[engine] = append(byEngine[engine], f)
	}

	now := time.Now().UTC()
	out := make([]Event, 0, len(byEngine))
	// Deterministic order so a batch is byte-stable across runs: rules, then bge.
	for _, engine := range []string{deepscan.EngineRules, deepscan.EngineBGE} {
		fs := byEngine[engine]
		if len(fs) == 0 {
			continue
		}
		ev := Event{
			CreatedAt:    now,
			TenantID:     id.TenantID,
			ActionTaken:  m.ActionTaken,
			PromptLength: len(m.Job.Text),
			VirtualKeyID: id.VirtualKeyID,
			SeatID:       id.SeatID,
			SessionID:    id.SessionID,
			TraceID:      id.TraceID,
		}
		// Coverage is attached to every event and stripped at ENCODE time when the
		// target master has not advertised support (EncodeForMaster). Attaching it
		// here keeps one built event usable against both an old and a new master —
		// which is what a dead-letter replay after an upgrade needs.
		if m.Coverage.Status != "" {
			cov := m.Coverage
			ev.ScanCoverage = &cov
		}
		switch engine {
		case deepscan.EngineBGE:
			ev.EventID = DeepScanEventID(m.Job.AuditUnitID)
			ev.Scenario = ScenarioAsyncDeepAudit
			// bge findings are advisory by construction — a semantic match is a
			// prompt to review, never a statement that something was blocked.
			ev.ActionTaken = "warn"
		default:
			ev.EventID = RuleScanEventID(m.Job.AuditUnitID)
			ev.Scenario = m.Scenario
		}
		ev.Findings = make([]Finding, 0, len(fs))
		for i, f := range fs {
			ev.Findings = append(ev.Findings, Finding{
				// Derived from the event id and the position, so a re-scan of the
				// same content produces the same finding ids too — otherwise the
				// event dedups and its findings still pile up.
				FindingID:   derivedEventID("af_", ev.EventID, itoa(i)),
				RuleID:      f.RuleID,
				Category:    f.Category,
				EntityType:  f.EntityType,
				Severity:    f.Severity,
				Confidence:  f.Confidence,
				StartOffset: f.Start,
				EndOffset:   f.End,
				Detector:    f.Detector,
			})
		}
		out = append(out, ev)
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
