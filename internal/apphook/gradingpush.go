// gradingpush.go — push a new org policy document into a RUNNING child
// (pipewire.OpSetGrading), TODO-188 方案 C.
//
// # What problem this solves
//
// The document used to reach the child only through its spawn environment, so
// the supervisor re-spawned the whole filter pool on every ladder edit: a new
// generation of M detectors was started before the old one was drained. On a
// 1.6 GB Cluster worker 2×M detectors crossed the unit's MemoryHigh and the
// node livelocked (task-execution/runs/todo-188-triage.md §3.1). Pushing the
// document over the pipe keeps the processes.
//
// # The ordering contract (用户拍板 2026-09-21, C.7-3)
//
// Nothing on this side moves until the child CONFIRMS: parse_ok=true AND the
// token it echoes is pipewire.GradingToken of the exact bytes sent. Only then
//
//  1. the respawn environment (cfg.ExtraEnv[envKey]) is rewritten — so a later
//     crash-restart is born with the document the child is enforcing; and
//  2. the verdict-cache epoch's policy half (policyToken) moves.
//
// The design draft had it the other way round (env first, then push). That was
// right while a refusal meant "grading off" on both paths; once the user chose
// "keep the previous document" on refusal, env-first would make the next crash
// cold-parse the refused document and switch grading off — exactly what the
// refusal exists to prevent.
//
// This package stays business-blind (不变量 #16): the caller names the env key,
// and the token is the shared pipewire digest, never re-spelled here.
package apphook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/AiKeyLabs/pkg/pipewire"
)

// GradingPushOutcome says what one child did with a pushed document. ONE enum,
// because the supervisor's decision (done / roll back / fall back to reload) is
// a function of it, and per-call-site booleans would drift.
type GradingPushOutcome uint8

const (
	// GradingPushApplied: the child confirmed the exact bytes; env and token moved.
	GradingPushApplied GradingPushOutcome = iota + 1
	// GradingPushRefused: the child could not parse the document and KEPT the
	// one it had (parse_ok=false). Nothing moved on this side.
	GradingPushRefused
	// GradingPushUnsupported: an empty ack — a child that predates OpSetGrading
	// (its default arm). Nothing moved; the caller falls back to a full reload.
	GradingPushUnsupported
	// GradingPushFailed: no usable answer (degraded child, timeout, IPC error, an
	// undecodable or mismatching ack, or the child was respawned mid-push).
	// Nothing moved; the caller falls back to a full reload.
	GradingPushFailed
)

func (o GradingPushOutcome) String() string {
	switch o {
	case GradingPushApplied:
		return "applied"
	case GradingPushRefused:
		return "refused"
	case GradingPushUnsupported:
		return "unsupported"
	case GradingPushFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// GradingPushResult is one child's answer. Token is the token the child says it
// is enforcing after the call (empty when there was no usable answer).
type GradingPushResult struct {
	Outcome GradingPushOutcome
	Token   string
	Err     error
}

// gradingPushTimeout bounds one push. Same value and same reasoning as
// adminQueryTimeout: on a K=1 child the frame queues behind every in-flight
// Detect, so the latency is queueing, not child health. A push that times out
// concludes nothing about the worker (callAdminQuery) — the caller falls back
// to the reload path, which replaces the pool anyway.
const gradingPushTimeout = adminQueryTimeout

var errGradingAckMismatch = errors.New("apphook: child acknowledged a different document than the one sent")

// SetGrading pushes doc to this child and, only on a confirmed apply, rewrites
// envKey in the respawn environment and moves the policy token. See the file
// comment for why the order is push → confirm → env → token.
// spec: R-compliance-grading-5.1
func (h *ChildHook) SetGrading(ctx context.Context, envKey string, doc []byte) GradingPushResult {
	ctx, cancel := context.WithTimeout(ctx, gradingPushTimeout)
	defer cancel()
	want := pipewire.GradingToken(doc)
	// A respawn between the push and the env write would be a NEW process born
	// with the OLD env that we then label with the NEW token. Detected by the
	// spawn generation and reported as a failure (the caller reloads).
	genBefore := h.gen.Load()

	resp, err := h.roundtrip(ctx, callAdminQuery, pipewire.OpSetGrading, pipewire.RouteClassPersonal, doc)
	if err != nil {
		return GradingPushResult{Outcome: GradingPushFailed, Err: err}
	}
	if resp.oversize || len(resp.findings) == 0 {
		return GradingPushResult{Outcome: GradingPushUnsupported}
	}
	var ack pipewire.GradingApplied
	if err := json.Unmarshal(resp.findings, &ack); err != nil {
		return GradingPushResult{Outcome: GradingPushFailed, Err: fmt.Errorf("apphook: undecodable grading ack: %w", err)}
	}
	if !ack.ParseOK {
		return GradingPushResult{Outcome: GradingPushRefused, Token: ack.GradingToken}
	}
	if ack.GradingToken != want {
		return GradingPushResult{Outcome: GradingPushFailed, Token: ack.GradingToken, Err: errGradingAckMismatch}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gen.Load() != genBefore {
		return GradingPushResult{Outcome: GradingPushFailed, Token: ack.GradingToken,
			Err: errors.New("apphook: child was respawned while the grading push was in flight")}
	}
	// A NEW slice: cfg.ExtraEnv shares its backing array with every worker built
	// from the same ChildHookConfig, so an in-place write would rewrite siblings.
	h.cfg.ExtraEnv = withEnv(h.cfg.ExtraEnv, envKey, string(doc))
	h.policyToken.Store(&want)
	return GradingPushResult{Outcome: GradingPushApplied, Token: want}
}

// currentPolicyToken is the token folded into ContentVersion. "" = none.
func (h *ChildHook) currentPolicyToken() string {
	if p := h.policyToken.Load(); p != nil {
		return *p
	}
	return ""
}

// withEnv returns a copy of env with key set to value: every existing entry for
// key is replaced in place in the copy (spawnLocked appends ExtraEnv after
// os.Environ and exec keeps the LAST occurrence, so dropping duplicates would
// change nothing but the order), and the entry is appended if absent.
func withEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	prefix := key + "="
	found := false
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			out = append(out, prefix+value)
			found = true
			continue
		}
		out = append(out, kv)
	}
	if !found {
		out = append(out, prefix+value)
	}
	return out
}

// SetGrading pushes doc to every worker, in dispatch order, and reports each
// outcome. It does not decide anything: rolling back the workers that applied
// when another refused, or falling back to a reload, is the supervisor's call.
func (p *FilterPool) SetGrading(ctx context.Context, envKey string, doc []byte) []GradingPushResult {
	out := make([]GradingPushResult, len(p.workers))
	for i, w := range p.workers {
		out[i] = w.SetGrading(ctx, envKey, doc)
	}
	return out
}
