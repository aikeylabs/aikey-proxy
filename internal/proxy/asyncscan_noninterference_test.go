package proxy

import (
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/asyncscan"
)

// TestAsyncScan_CommitPointNeverAltersTheForwardedRequest is the fence that
// actually covers the asynchronous lane's non-interference.
//
// 🔴 WHY A SEPARATE TEST FROM TestApplyInboundFilter_Warn. The existing warn
// fence runs with p.asyncEnqueuer nil, so the whole commit-point block is behind
// a nil check it never satisfies — a mutation injected there does not make that
// test red. Discovered while trying to red-prove task 3.5 on 2026-09-12: the
// "proof" passed with the bug installed, which is a green fence pointed at
// nothing. This test installs a real enqueuer so the block executes.
//
// What it guards: the async lane is a SIDE CHANNEL. It observes what was
// forwarded; it must never change it. If the commit point could write back, a
// background scan would be altering bytes that were already decided on — and the
// alteration would land after every policy check had run.
func TestAsyncScan_CommitPointNeverAltersTheForwardedRequest(t *testing.T) {
	var mu sync.Mutex
	var seen []asyncscan.CommittedPiece
	var seenID asyncscan.RequestIdentity

	enq := asyncscan.NewEnqueuer(func(p asyncscan.CommittedPiece, id asyncscan.RequestIdentity) bool {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, p)
		seenID = id
		return true
	}, asyncscan.NewScannedLRU(16))

	for _, tc := range []struct {
		name   string
		action apphook.Action
		body   string
	}{
		{"warn", apphook.ActionWarn, `{"messages":[{"content":"borderline"}]}`},
		{"allow", apphook.ActionAllow, `{"messages":[{"content":"perfectly fine"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			seen = nil
			mu.Unlock()

			hook := &stubHook{resp: &apphook.Response{Action: tc.action, Reason: "r"}}
			p := &Proxy{filterHook: hook}
			p.SetAsyncEnqueuer(enq)

			r := newReq(tc.body)
			w := httptest.NewRecorder()
			if proceed := p.applyInboundFilter(w, r, "m", "team", "org_a", "vk1", "seat1", "sess1", "trace1", discardLogger()); !proceed {
				t.Fatal("must proceed")
			}
			// ⚠️ HONEST NOTE ON THIS ASSERTION'S STRENGTH. It is defence in depth, and
			// it CANNOT be made red by a mutation at the commit point: when nothing
			// was masked, applyInboundFilter restores the original bodyBytes
			// unconditionally on its way out (`if maskedCount == 0 { r.Body = ...
			// bodyBytes }`), so a rewrite at the commit point is overwritten before
			// the request leaves. Verified by injection on 2026-09-12 — the injected
			// rewrite did NOT turn this red.
			//
			// It is kept because that upstream restore is not a promise this lane
			// controls: if the dispatcher ever stops restoring (say a future change
			// makes the async lane able to request a re-marshal), this assertion is
			// already in place. The claim that IS red-provable, and the one that
			// actually guards content, is
			// TestAsyncScan_BlockedRequestReachesNoCommitPoint below.
			if got := readReqBody(t, r); got != tc.body {
				t.Errorf("the asynchronous lane altered the forwarded body:\n got: %s\nwant: %s", got, tc.body)
			}

			mu.Lock()
			n := len(seen)
			id := seenID
			mu.Unlock()
			if n == 0 {
				t.Fatal("the commit point did not run — this fence would be vacuous, which is exactly why it exists")
			}
			// Identity is carried to the LANE (so the proxy can stamp the event
			// later) and, per the frame fence, never onto the wire.
			if id.TenantID != "org_a" || id.SeatID != "seat1" || id.SessionID != "sess1" || id.TraceID != "trace1" {
				t.Errorf("the lane did not receive the resolved identity: %+v", id)
			}
		})
	}
}

// TestAsyncScan_BlockedRequestReachesNoCommitPoint proves the structural claim
// the commit point's placement rests on: a blocked request returns before it.
func TestAsyncScan_BlockedRequestReachesNoCommitPoint(t *testing.T) {
	var mu sync.Mutex
	called := 0
	enq := asyncscan.NewEnqueuer(func(asyncscan.CommittedPiece, asyncscan.RequestIdentity) bool {
		mu.Lock()
		called++
		mu.Unlock()
		return true
	}, asyncscan.NewScannedLRU(16))

	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionBlock, Reason: "private key"}}
	p := &Proxy{filterHook: hook}
	p.SetAsyncEnqueuer(enq)

	r := newReq(`{"messages":[{"content":"-----BEGIN RSA PRIVATE KEY-----"}]}`)
	w := httptest.NewRecorder()
	if proceed := p.applyInboundFilter(w, r, "m", "team", "org_a", "vk1", "seat1", "sess1", "trace1", discardLogger()); proceed {
		t.Fatal("a blocked request must not proceed")
	}
	mu.Lock()
	defer mu.Unlock()
	if called != 0 {
		t.Errorf("the commit point ran %d times for a BLOCKED request — those bytes were refused; "+
			"handing them to a scan node would push off the machine exactly the content the policy just stopped", called)
	}
}
