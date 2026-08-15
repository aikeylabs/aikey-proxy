// Package apphook defines a GENERIC interface between aikey-proxy and any
// first-party AiKey app (ai-compliance-detector, degrade-detector, etc.) that
// wants to hook into the main LLM request path via spawned-child IPC.
//
// CRITICAL DESIGN INVARIANT (方案 §6 不变量 #16 / 用户原话 2026-05-29):
//
//	proxy MUST NOT know what business the app is doing.
//
// The hook interface deliberately uses neutral names (Request, Response, Action)
// instead of business-specific names (ComplianceRequest, ScanFinding, etc.).
// proxy treats every AppHook the same — spawn child, send request, get
// action verdict, apply.
//
// Concretely this means:
//   - ai-compliance-detector  → AppHook implementation that runs Stage 1 detection
//   - degrade-detector        → AppHook implementation that runs trust check
//   - future apps (e.g. quality-evaluator, safety-classifier) → just add another
//     AppHook implementation, proxy unchanged
//
// Anti-patterns that violate this (and MUST be rejected in code review):
//   - naming the interface ComplianceHook
//   - putting compliance-specific fields (FindingsJSON, RuleID, Severity) in Request/Response
//   - making proxy decide what to do based on app type
//
// Cross-references:
//   - 方案 §5.1.7 进程模型决策 (process model)
//   - 方案 §6 不变量 #11-#19 (esp #13 #16 #17)
//   - 实施计划 §3.2 A3 (this scope)
package apphook

import (
	"context"
	"time"
)

// Action is the verdict from a child app. Generic — not compliance-specific.
type Action uint8

const (
	ActionAllow Action = 0 // pass through unchanged
	ActionMask  Action = 1 // payload mutated in-place by app (e.g. PII redacted), forward mutated version
	ActionBlock Action = 2 // refuse the request, return error to user
	ActionWarn  Action = 3 // pass through but record warning event
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionMask:
		return "mask"
	case ActionBlock:
		return "block"
	case ActionWarn:
		return "warn"
	default:
		return "unknown"
	}
}

// Direction is the side of the LLM call (request inbound vs response outbound).
// Apps may choose to inspect one or both.
type Direction uint8

const (
	DirectionInbound  Direction = 0 // user → LLM
	DirectionOutbound Direction = 1 // LLM → user
)

// RouteClass values for Request.RouteClass (v2). Mirrors the detector's
// pipe.RouteClass* — kept as plain uint8 here to avoid a cross-module import.
const (
	RouteClassPersonal uint8 = 0 // child uploads locally (self-view)
	RouteClassTeam     uint8 = 1 // child returns the event; proxy forwards to master
)

// Request is what proxy sends to the child app.
// Fields are deliberately generic — payload is a byte slice (could be prompt
// text, JSON, even binary). Apps that want structured access decode it
// themselves.
type Request struct {
	// Optional metadata (apps may ignore):
	UserRole    string    // e.g. "customer-service" (used by compliance to pick pack)
	TargetModel string    // e.g. "claude-sonnet-4-6"
	RequestID   string    // for tracing
	Payload     []byte    // raw payload, app-interpreted
	Direction   Direction // inbound (prompt) or outbound (response)
	// RouteClass tells the child where this request's event should be reported:
	// 0 = personal (child uploads locally, current behavior), 1 = team (child
	// returns the event in Response.Event for the proxy to forward to master).
	// Only the class travels the pipe — never the credential/URL. (v2 protocol,
	// update doc 20260603 §2.3.)
	RouteClass uint8
}

// Response is what the child app returns to proxy.
type Response struct {
	Reason         string // human-readable (for error messages, logs)
	MutatedPayload []byte // present iff Action == ActionMask
	// Event is the compliance event JSON the child hands back for the proxy to
	// forward to master, populated ONLY for team-routed requests (RouteClass=1).
	// Empty for personal-routed (child uploaded locally) and non-Detect ops.
	// (v2 protocol, update doc 20260603 §2.2/§3.2.)
	Event []byte
	// Restorables (v4 protocol, 2026-08-08) describes placeholder tokens the app
	// substituted into MutatedPayload that the proxy MAY renumber into
	// per-request labels and restore back to the original text on the RESPONSE
	// path. GENERIC contract — the proxy never learns what the token stands for
	// business-wise (invariant #16 holds): it only sees "token T replaced these
	// spans of the payload I sent". Empty for non-restorable masks.
	Restorables     []RestorableMask
	LatencyObserved time.Duration // measured by proxy, set by Hook.Detect not by child
	Action          Action
	Degraded        bool // true if child unreachable / timed out — proxy already fell back to Allow
}

// RestorableMask is one restorable placeholder token in a Mask verdict.
// Occurrences of Token appear in MutatedPayload in the same order as Spans.
type RestorableMask struct {
	// Token is the literal placeholder string in MutatedPayload (one per span).
	Token string
	// NumberedPrefix/NumberedSuffix compose the per-request numbered label the
	// proxy substitutes for the k-th token occurrence: prefix + N + suffix.
	// Owned by the app (single source of truth with its mask policy).
	NumberedPrefix string
	NumberedSuffix string
	// Spans are [start,end) byte offsets into the ORIGINAL Request.Payload the
	// proxy sent — offsets only; the proxy slices the original text locally.
	// The derived placeholder↔original mapping is per-request memory ONLY:
	// never persisted, never logged (B3 拍板 2026-08-06).
	Spans [][2]int
}

// Hook is the contract between aikey-proxy main loop and a first-party app.
//
// Implementations spawn and manage a child process, handle the binary
// protocol IPC, and surface degraded state when the child is unavailable.
//
// IMPORTANT CONTRACT (方案 §6 不变量 #11):
//   - Detect MUST return within the configured timeout (default 1ms).
//   - On any error / timeout / unreachable child, return Response{Action: Allow, Degraded: true}.
//   - NEVER block the main LLM request path. degraded ≠ fail.
type Hook interface {
	// Name is the app identifier (e.g. "ai-compliance-detector",
	// "degrade-detector"). Used for status reporting and logs only.
	// Proxy code MUST NOT branch on Name.
	Name() string

	// Detect performs one inspection of the given request payload.
	//
	// Hard requirement: returns within ctx deadline (default 1ms enforced
	// internally even if caller passes a longer deadline).
	//
	// MUST NOT panic — implementations defer-recover internally.
	// MUST NOT mutate req.
	Detect(ctx context.Context, req *Request) *Response

	// Status returns current child health for proxy status banner +
	// `aikey app status <name>` CLI output.
	//
	// Cheap and non-blocking — reads cached state, does not query child.
	Status() *Status
}

// Status describes a hook's current health.
// Stable across reads — implementations update this from background goroutines.
//
// 🔴 EVERY FIELD HERE IS AN EXTERNALLY READABLE HEALTH SIGNAL, not a log line.
// This struct is projected onto GET /v1/diagnostics/pipeline (`filter_hook`), so
// adding a state that only appears in a `slog` call is the health-signal-surface
// violation this type exists to prevent: `DegradedReason` distinguishes "the
// child wedged mid-write" (write_timeout) from "the child was never started"
// (not_started), and until 2026-08-13 neither could be read from outside the
// process — `ak doctor` had to infer both from a single `available:false`.
type Status struct {
	LastSpawnedAt  time.Time // wall-clock of last spawn
	LastDetectAt   time.Time // wall-clock of last successful Detect roundtrip
	LastErrorAt    time.Time // wall-clock of last failed Detect (any reason)
	DegradedReason string    // populated when Healthy == false: crash | timeout | not_installed | protocol_mismatch | unauthorized | write_timeout | not_started | restarting
	BinaryPath     string    // absolute path to child binary (e.g. ~/.aikey/apps/ai-compliance-detector/bin/detector)
	Version        string    // protocol version + binary version from child's ready sentinel
	// ContentVersion is the token this unit currently reports for its
	// hot-swappable content set (see contentversion.go), or "" when it cannot
	// state one. ContentVersionReason names WHY it is empty — one of the
	// contentVersionReason* constants, never a free-form string.
	//
	// WHY they live on Status rather than behind another accessor: "which ruleset
	// is live" and "is this child healthy" are read by the same operator in the
	// same breath, and the answer to "why did the verdict cache switch off?" is a
	// per-unit fact. Additive fields on a struct that is already the health
	// projection, rather than a second parallel surface (慎重新建 API/接口协议).
	//
	// They are DERIVED at Status() read time, not stored in the snapshot: every
	// markDegraded/restart/spawn path rebuilds the snapshot from scratch, so a
	// stored copy would be silently dropped by whichever path a future change
	// forgets to update.
	ContentVersion       string
	ContentVersionReason string
	RestartCount         uint64 // cumulative restart count since proxy start
	Healthy              bool   // true iff child reachable and last detect succeeded
}

// MultiUnit is implemented by a Hook that fronts MORE THAN ONE independently
// failing unit (FilterPool: M child processes).
//
// Implementing it is a STATEMENT: "my aggregate Status() collapses several
// health states into one, so do not report it as if it were a single unit".
//
// 🔴 WHY THIS EXISTS (2026-08-13, review finding B39/B5). FilterPool.Status()
// answers Healthy=true whenever ≥1 worker survives and buries the rest in a
// formatted DegradedReason ("1/2 workers healthy"). That is correct for the
// "should the pool keep serving?" question it was written for, and a FALSE GREEN
// for every health surface: a 2-worker pool with one dead process reported
// healthy while half of all Detect calls fail open and forward content
// un-inspected. A health surface that cannot see the dead worker cannot warn
// about it.
type MultiUnit interface {
	// WorkerStatuses returns one Status per underlying unit, in dispatch order.
	// Cheap and non-blocking, same contract as Status().
	WorkerStatuses() []*Status
}

// WorkerStatuses is the ONE sanctioned way to enumerate a hook's independently
// failing units. Callers must not type-assert MultiUnit themselves — a hook that
// is a single unit is NOT an error case to be branched on at each call site, it
// is a pool of one, and re-deriving that at every reader is how the pool branch
// gets lost (same posture as CacheEpoch's tri-state).
//
//	hook implements MultiUnit → its per-worker statuses, in dispatch order
//	hook does not            → a 1-element slice holding its own Status
//	hook is nil              → nil (no filter installed; not a fault)
func WorkerStatuses(h Hook) []*Status {
	if h == nil {
		return nil
	}
	if m, ok := h.(MultiUnit); ok {
		return m.WorkerStatuses()
	}
	return []*Status{h.Status()}
}

// Disabled is the no-op Hook used when no app is registered for a slot.
// Allows proxy main loop to call Detect unconditionally without nil checks.
type Disabled struct{ name string }

func NewDisabled(name string) *Disabled { return &Disabled{name: name} }

func (d *Disabled) Name() string { return d.name }

func (d *Disabled) Detect(ctx context.Context, req *Request) *Response {
	return &Response{Action: ActionAllow, Degraded: false}
}

func (d *Disabled) Status() *Status {
	return &Status{Healthy: true, DegradedReason: "no_hook_registered"}
}
