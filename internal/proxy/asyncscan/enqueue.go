package asyncscan

import "github.com/AiKeyLabs/aikey-proxy/internal/apphook"

// RequestIdentity is everything the proxy resolved about the request, and it
// stays HERE — it is stamped onto the event after a result comes back, and never
// travels to a scan node (design §3.3).
type RequestIdentity struct {
	TenantID     string
	SeatID       string
	VirtualKeyID string
	SessionID    string
	TraceID      string
	ScopeKey     string
}

// CommittedPiece is one content piece that actually went upstream.
type CommittedPiece struct {
	Text string
	// HeadBytes is how much of it the synchronous fast layer inspected.
	HeadBytes int
	// Source is request / response.
	Source string
	// Personal is true when the piece belongs to a personal route, which never
	// leaves the machine (R-scan-node-deepscan-16.S1).
	Personal bool
	// Ceiling is the most this KIND of content may be acted on: plain text is
	// block-capable (apphook.ActionBlock); tool_result / tool_use are capped at
	// audit (apphook.ActionWarn). The lane clamps its "would have blocked" verdict
	// with it (R-scan-node-deepscan-20.S2). Remembered by the proxy, never sent in
	// a frame — a node has no business knowing what kind of block content came from.
	//
	// 🔴 The zero value (ActionAllow) is the WEAKEST rung on purpose, the same
	// choice actionCeiling makes: a caller that forgets to set it under-reports
	// high risk; the opposite default would file every agent file read as a leak.
	// bugfix: workflow/CI/bugfix/20260914-async-scan-verdict-ignores-content-and-deploy-ceilings.md
	Ceiling apphook.Action
}

// SubmitFunc hands one piece to the lane. It must not block.
type SubmitFunc func(CommittedPiece, RequestIdentity) bool

// Enqueuer is the commit-point hook.
type Enqueuer struct {
	submit SubmitFunc
	lru    *ScannedLRU
}

// NewEnqueuer wires the commit point to a submit function and the already-scanned record.
func NewEnqueuer(submit SubmitFunc, lru *ScannedLRU) *Enqueuer {
	return &Enqueuer{submit: submit, lru: lru}
}

// OnCommit is called at the request-forwarding COMMIT POINT: after the piece
// loop, once the request is known to be going upstream.
//
// 🔴 WHY THE COMMIT POINT AND NOWHERE ELSE (baseline-forensics §F1):
// internal/proxy/filter_dispatch.go returns early at :631 on an ActionBlock, so
// code placed after the piece loop is structurally unreachable for a blocked
// request. That is not a happy accident to rely on quietly — it is the cheapest
// possible implementation of "a refused request's bytes are never sent to a scan
// node", with no flag to forget to check. A blocked request's content was
// REFUSED: forwarding it to a node afterwards would push off the machine exactly
// the bytes the policy just decided must not leave it, and then file an audit row
// implying it was forwarded upstream.
//
// Cache-hit pieces ARE passed in: the fast layer skipped the detector for them,
// but the async lane's already-scanned record is a different question with a
// different key (whole content vs scanned head), so the filtering happens there.
//
// spec: R-scan-node-deepscan-23.S1
func (e *Enqueuer) OnCommit(pieces []CommittedPiece, id RequestIdentity) {
	if e == nil || e.submit == nil {
		return
	}
	for _, p := range pieces {
		if p.Text == "" {
			continue
		}
		e.submit(p, id)
	}
}
