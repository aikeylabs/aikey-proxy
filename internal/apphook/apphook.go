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
//                              AppHook implementation, proxy unchanged
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

// Request is what proxy sends to the child app.
// Fields are deliberately generic — payload is a byte slice (could be prompt
// text, JSON, even binary). Apps that want structured access decode it
// themselves.
type Request struct {
	Direction Direction // inbound (prompt) or outbound (response)
	Payload   []byte    // raw payload, app-interpreted
	// Optional metadata (apps may ignore):
	UserRole    string // e.g. "customer-service" (used by compliance to pick pack)
	TargetModel string // e.g. "claude-sonnet-4-6"
	RequestID   string // for tracing
}

// Response is what the child app returns to proxy.
type Response struct {
	Action          Action
	MutatedPayload  []byte        // present iff Action == ActionMask
	Reason          string        // human-readable (for error messages, logs)
	LatencyObserved time.Duration // measured by proxy, set by Hook.Detect not by child
	Degraded        bool          // true if child unreachable / timed out — proxy already fell back to Allow
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
type Status struct {
	Healthy        bool      // true iff child reachable and last detect succeeded
	DegradedReason string    // populated when Healthy == false: crash | timeout | not_installed | protocol_mismatch | unauthorized
	BinaryPath     string    // absolute path to child binary (e.g. ~/.aikey/apps/ai-compliance-detector/bin/detector)
	Version        string    // protocol version + binary version from child's ready sentinel
	LastSpawnedAt  time.Time // wall-clock of last spawn
	RestartCount   uint64    // cumulative restart count since proxy start
	LastDetectAt   time.Time // wall-clock of last successful Detect roundtrip
	LastErrorAt    time.Time // wall-clock of last failed Detect (any reason)
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
