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
	// ActionAnswer refuses the request like ActionBlock and serves an
	// administrator-authored canned answer in its place (代答). Appended, never
	// renumbered: the value travels the child pipe as a raw byte, so reordering
	// the rungs would reinterpret every verdict already in flight.
	ActionAnswer Action = 4
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
	case ActionAnswer:
		return "answer"
	default:
		return "unknown"
	}
}

// Recognized reports whether a is an Action value THIS proxy build understands.
//
// The action byte comes off the child pipe unvalidated (ChildHook.Detect does a
// straight Action(resp.action) conversion), so a child built against a newer
// enum — or a tampered one — can hand back a value that is not in the set above.
// This is the ONE definition of "in the set"; every consumer derives from it
// rather than writing its own switch, so adding a rung cannot leave one reader
// behind.
func (a Action) Recognized() bool {
	switch a {
	case ActionAllow, ActionMask, ActionBlock, ActionWarn, ActionAnswer:
		return true
	}
	return false
}

// NormalizeAction maps an unrecognized action onto ActionBlock, and leaves every
// recognized one alone. FAIL-CLOSED, and that direction is the whole point.
//
// spec (PROPOSAL layer, 需求包 .../博时基金合规能力融合/openspec/changes/
// add-compliance-grading-fusion/specs/compliance-canned-answer/spec.md):
//
//	R-compliance-canned-answer-6  proxy 收到无法识别的动作值时 SHALL 按 ActionBlock
//	                              处理（fail-safe），SHALL NOT 按放行处理
//
// 🔴 DO NOT "restore" the old fail-open here. Two different failures were
// conflated until 2026-09-13 and they point opposite ways:
//
//   - The child could not ANSWER (timeout, crash, not installed). §6 #11: never
//     block the main path. Those paths return an explicit ActionAllow with
//     Degraded=true (childhook.go) — they never reach this function, and this
//     change did not touch them.
//   - The child ANSWERED with a verdict we cannot read. The action value is a
//     policy the master handed down. Not recognizing it means either this proxy
//     is older than the policy, or the policy was tampered with. Forwarding on
//     either is a version skew silently switching the compliance policy off.
//
// 围栏: internal/apphook TestUnknownAction_TreatedAsBlock (enum level) ·
// internal/proxy TestApplyInboundFilter_UnknownAction_FailsClosedBlocked
// (403 COMPLIANCE_BLOCKED, nothing forwarded).
func NormalizeAction(a Action) Action {
	if a.Recognized() {
		return a
	}
	return ActionBlock
}

// SupportsCannedAnswer reports whether this proxy build can SERVE a canned
// answer (代答) — not merely whether it knows the enum value.
//
// The detector reads this declaration to decide what to hand down: 代答 only
// when true, plain ActionBlock when false (design.md §4b). Declaring a
// capability this build cannot serve is the same defect as failing open on an
// unknown action, reached from the other side — the policy says "answer", the
// proxy cannot, and the difference shows up as behaviour nobody configured.
//
// 🔴 FALSE ON PURPOSE, and this is the task seam. Task 3.5 added the enum rung
// and the fail-closed direction; the response synthesizer (writeCannedAnswer,
// three protocol families × streaming/non-streaming) is task 3.6. Until it
// exists this build can only refuse, which is exactly what
// R-compliance-canned-answer-6.S1 prescribes for a proxy that has not declared
// the capability — so the intermediate state is correct, just not the feature.
//
// ✅ FLIPPED TO TRUE BY TASK 3.6 (2026-09-13), together with
// internal/proxy/canned_answer.go (writeCannedAnswer — three protocol families ×
// streaming/non-streaming) and the `case ActionAnswer` dispatch branch. The
// sentence above now reads in the past tense: this build CAN synthesize.
//
// 🔴 WHAT THIS DOES AND DOES NOT CLAIM. It claims one thing: given an Answer
// verdict AND a text, this binary can produce a protocol-legal reply without
// contacting a provider. It does NOT claim the end-to-end feature works — the
// detector cannot yet READ this bit (TODO-68: the handshake is child → proxy
// only, and the ruling is to carry the declaration on the existing spawn env),
// and no carrier hands the resolved text BACK (see Response.AnswerText). Both
// are cross-boundary contracts owned outside task 3.6's file list. Until they
// land, a real Answer verdict still ends as a loud block — which is the same
// safe outcome as before, reached one step later.
//
// The fence that used to pin this false is inverted, not deleted:
// TestSupportsCannedAnswer_TrueOnceWriterLanded (task 3.5 handed the inversion
// over explicitly; the controller signed off on 2026-09-13). Task 3.7's
// TestCannedAnswer_UnconfiguredPathsByteIdentical also asserts it is true.
//
// A function rather than a const so the dispatch guard reads as a capability
// question at the call site, and so it can derive from configuration if the
// canned answer ever becomes opt-in per deployment.
func SupportsCannedAnswer() bool { return true }

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

	// AnswerText is the administrator-authored canned answer (代答) the proxy
	// serves INSTEAD of forwarding, populated iff Action == ActionAnswer. It is
	// emitted VERBATIM — see internal/proxy/canned_answer.go, red line 1
	// (R-compliance-canned-answer-3).
	//
	// ✅ CARRIER LANDED (task 3.12, 2026-09-14). The three-tier fallback that
	// produces this text lives in the DETECTOR (actionpolicy.ResolveAnswerText,
	// task 2.11) and it reaches here through the `findings` SLOT of the v4 pipe,
	// which is free on an Answer verdict because there is no masked payload —
	// the slot's per-op meanings are tabulated on childResponse in childhook.go.
	// Zero new wire fields, zero version bump. 围栏:
	// TestCannedAnswerTextReachesProxy (apphook) ·
	// TestCannedAnswerTextNeverLeavesInUploadedEvent (proxy).
	//
	// 🔴 STILL UNREACHABLE IN PRODUCTION, and NOT because of this side. The
	// detector degrades every `answer` to `block` inside answerOrBlock until it
	// can learn whether this proxy declares SupportsCannedAnswer(), and that
	// capability bit has no carrier yet (TODO-68, ruled: reuse the existing
	// spawn env). Both halves of the text carrier are complete and fenced; the
	// remaining hop is the capability bit, not the text.
	//
	// The rule-level tier of the fallback is separately empty in production
	// (TODO-76: types.Finding.AnswerText has no producer), so the tiers that can
	// actually appear here today are `level` and `org`.
	AnswerText string
	// AnswerSource names WHICH tier supplied AnswerText — `rule` / `level` /
	// `org`, spelled identically to actionpolicy.AnswerSource and to the
	// `events[].answer_source` wire field (design §4b). `none` never appears
	// here: it means no tier had a text, and that request's action_taken is
	// `block`, not an answer. Carried in the same pipe slot as AnswerText (task
	// 3.12); the same reachability caveat applies.
	AnswerSource string
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
