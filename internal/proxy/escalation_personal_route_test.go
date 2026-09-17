package proxy

// escalation_personal_route_test.go — TODO-87: an organization's cumulative
// escalation follows the PERSON, so a team member's personal-route traffic
// counts toward it too (user decision 2026-09-15; the Personal EDITION, which
// has no org and therefore no rules, is out of scope).
//
// Design a2 「计数投影」 (需求包 roadmap20260320/技术实现/阶段9-商业化版本/
// 博时基金合规能力融合/task-execution/runs/design-todo-87.md):
//   - on the personal route the detector keeps uploading its own content event to
//     the local self-view, and ALSO hands the proxy a content-free count
//     projection (pipewire.CountProjection) in Response.Event;
//   - the proxy counts from it, never uploads it, and records the request-verdict
//     row on the LOCAL self-view only (user decision V1 — master gets nothing from
//     the personal route; the 2026-05-10 personal/team isolation is unchanged).
//
// rules (PROPOSED as R-compliance-grading-24 — not yet in the spec, hence
// referenced by id in prose and not as anchors; same convention as
// escalation_wiring_test.go):
//
//	R-compliance-grading-24.S1  成员个人 key 跨片段触发升级（403、计数 3、本机裁决行）
//	R-compliance-grading-24.S2  [回归] 不重复上报（master 0 请求；本机只有一条裁决行）
//	R-compliance-grading-24.S3  [回归] 无升级规则时零变化（无裁决行、无上报）
//	R-compliance-grading-24.S4  缓存命中的历史片段同样计入
//	BUT NOT                     探测器过旧不回传投影时只告警不拦截

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/pipewire"
)

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

// personalVK is the virtual key id a personal BYOK route carries
// (supervisor/route_builders.go personalTokenToRoute: "personal:<alias>"). A
// personal route has NO org id and NO seat id, which is why every call below
// passes "" for both.
const personalVK = "personal:my-openai"

// projectionJSON renders the personal-route Event slot the detector hands back.
//
// 🔴 Keys are written by hand rather than marshaled from pipewire.CountProjection
// for the reason eventJSON gives: a fixture encoded with the type under test
// agrees with it by construction. The keys are the ones pkg/pipewire pins in
// TestCountProjectionWireBytes.
func projectionJSON(t *testing.T, eventID, text string, hits []gradedHit) []byte {
	t.Helper()
	findings := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		start := strings.Index(text, h.value)
		if start < 0 {
			t.Fatalf("fixture is wrong: piece %q does not contain %q", text, h.value)
		}
		f := map[string]any{
			"start_offset": start,
			"end_offset":   start + len(h.value),
			"category":     h.category,
			"confirmed":    h.confirmed,
		}
		if h.level > 0 {
			f["level"] = h.level
		}
		findings = append(findings, f)
	}
	raw, err := json.Marshal(map[string]any{"event_id": eventID, "findings": findings})
	if err != nil {
		t.Fatalf("marshal projection fixture: %v", err)
	}
	return raw
}

// projectionMint hands out detector-style event ids, one per Detect CALL, and
// remembers which piece each went to. Minting per call (not per text) is what
// lets the cache fence prove a verdict row names the id of the scan that
// actually populated the cache.
type projectionMint struct {
	mu  sync.Mutex
	n   int
	ids map[string][]string
}

func (m *projectionMint) next(text string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	id := fmt.Sprintf("%032x", m.n) // same shape as the detector's newEventID
	if m.ids == nil {
		m.ids = map[string][]string{}
	}
	m.ids[text] = append(m.ids[text], id)
	return id
}

func (m *projectionMint) idsFor(text string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.ids[text]...)
}

func (m *projectionMint) minted() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n
}

// personalPiece is one content piece, the hit the detector finds in it and the
// verdict the detector gives it.
type personalPiece struct {
	text   string
	hit    gradedHit
	action apphook.Action
}

// personalHook answers the way a post-TODO-87 detector does on the personal
// route: its own verdict, plus (withProjection) a count projection. With
// withProjection=false it is a detector that predates TODO-87.
func personalHook(t *testing.T, pieces []personalPiece, mint *projectionMint, withProjection bool) *contentScriptedHook {
	t.Helper()
	byText := make(map[string]personalPiece, len(pieces))
	for _, pc := range pieces {
		byText[pc.text] = pc
	}
	return &contentScriptedHook{answer: func(payload string) *apphook.Response {
		pc, ok := byText[payload]
		if !ok {
			return &apphook.Response{Action: apphook.ActionAllow}
		}
		resp := &apphook.Response{Action: pc.action}
		if pc.action == apphook.ActionMask {
			resp.MutatedPayload = []byte(strings.ReplaceAll(payload, pc.hit.value, "{{IDCARD}}"))
		}
		if withProjection {
			resp.Event = projectionJSON(t, mint.next(payload), payload, []gradedHit{pc.hit})
		}
		return resp
	}}
}

func personalRequest(t *testing.T, pieces []personalPiece) *http.Request {
	t.Helper()
	msgs := make([]string, 0, len(pieces))
	for _, pc := range pieces {
		msgs = append(msgs, `{"role":"user","content":`+mustJSON(t, pc.text)+`}`)
	}
	return newReq(`{"messages":[` + strings.Join(msgs, ",") + `]}`)
}

func filterPersonal(p *Proxy, w http.ResponseWriter, r *http.Request, traceID string, logger *slog.Logger) bool {
	return p.applyInboundFilter(w, r, "m", "personal", "", personalVK, "", "sess-personal", traceID, logger)
}

// threeMembers is R-compliance-grading-24.S1's fixture: three pieces, each with
// one distinct CONFIRMED L4 value, each masked on its own.
func threeMembers() []personalPiece {
	const (
		idA = "110101199003071234"
		idB = "310101198807153695"
		idC = "440305197502289517"
	)
	return []personalPiece{
		{"请核对客户 " + idA + " 的资料", gradedHit{idA, "pii", escalationMinLevel, true}, apphook.ActionMask},
		{"另外 " + idB + " 也要一起处理", gradedHit{idB, "pii", escalationMinLevel, true}, apphook.ActionMask},
		{idC + " 是第三位客户", gradedHit{idC, "pii", escalationMinLevel, true}, apphook.ActionMask},
	}
}

func escalationRulesFixture() []EscalationRule {
	return []EscalationRule{{MinLevel: escalationMinLevel, MinCount: escalationMinCount, Action: "block"}}
}

// routeSinks stands up BOTH collector routes a member's machine has: "team"
// (control-master) and "personal" (the local self-view store). Every personal
// route fence watches both, because the property under test is as much "the
// team sink saw NOTHING" as "the local sink saw the row".
type routeSinks struct {
	rep   *events.Reporter
	team  chan []byte
	local chan []byte
}

func newRouteSinks(t *testing.T) *routeSinks {
	t.Helper()
	s := &routeSinks{team: make(chan []byte, 16), local: make(chan []byte, 16)}
	mk := func(ch chan<- []byte) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			ch <- b
			_, _ = w.Write([]byte(`{"accepted_ids":[]}`))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	team, local := mk(s.team), mk(s.local)
	rep, err := events.NewReporter(&events.ReporterConfig{
		CollectorRoutes: map[string]string{"team": team.URL, "personal": local.URL},
		CollectorRouteCredentials: map[string]events.Credential{
			"team": &events.StaticTokenCredential{Token: "member-jwt"},
		},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	s.rep = rep
	return s
}

// firstBatch waits for one batch on ch, or returns nil after wait.
//
//nolint:unparam // wait is a per-call budget; every current caller happens to use 3s
func firstBatch(ch <-chan []byte, wait time.Duration) []byte {
	select {
	case b := <-ch:
		return b
	case <-time.After(wait):
		return nil
	}
}

// batchesWithin returns every batch that arrives on ch within wait.
func batchesWithin(ch <-chan []byte, wait time.Duration) [][]byte {
	var out [][]byte
	deadline := time.After(wait)
	for {
		select {
		case b := <-ch:
			out = append(out, b)
		case <-deadline:
			return out
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-24.S1 — a member's personal key trips the org rule
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_PersonalRouteCountsForOrgMember
//
// GIVEN the org's rule 「≥L4 命中 ≥3 条 → 拦截」 is installed on this machine (it
//
//	is pulled per machine, independent of which route a request takes)
//
// WHEN  a member sends, on a PERSONAL key, one request whose three pieces each
//
//	carry a distinct confirmed L4 value and the detector returns a count
//	projection for each
//
// THEN  the request is refused (403 COMPLIANCE_BLOCKED), the counter reads 3,
//
//	and the refusal is recorded as a request-verdict row on the member's
//	local self-view.
func TestEscalation_PersonalRouteCountsForOrgMember(t *testing.T) {
	sinks := newRouteSinks(t)
	pieces := threeMembers()
	mint := &projectionMint{}
	p := &Proxy{filterHook: personalHook(t, pieces, mint, true), reporter: sinks.rep}
	mustSetGrading(t, p, escalationRulesFixture())

	w := httptest.NewRecorder()
	if filterPersonal(p, w, personalRequest(t, pieces), "trace-todo87-s1", discardLogger()) {
		t.Fatal("three distinct confirmed L4 hits on a member's personal key were forwarded; the org's " +
			"cumulative rule follows the person (TODO-87, 2026-09-15)")
	}
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "COMPLIANCE_BLOCKED") {
		t.Fatalf("response = %d %s, want 403 COMPLIANCE_BLOCKED", w.Code, w.Body.String())
	}
	esc := p.escalationSnapshot()
	if esc.evaluated != 1 || esc.triggered != 1 || esc.counted != escalationMinCount {
		t.Fatalf("evaluated/triggered/counted = %d/%d/%d, want 1/1/%d", esc.evaluated, esc.triggered,
			esc.counted, escalationMinCount)
	}

	body := firstBatch(sinks.local, 3*time.Second)
	if body == nil {
		t.Fatal("the member's local self-view received no request-verdict row: the request was refused by " +
			"an accumulation and nothing on this machine says why (R-compliance-grading-18, TODO-87 V1)")
	}
	v := findRequestVerdict(t, body)
	if v.ActionTaken != "block" || v.Escalation.Counted != escalationMinCount || v.Escalation.Rule == "" {
		t.Errorf("local verdict row = action %q counted %d rule %q, want block / %d / the rule text",
			v.ActionTaken, v.Escalation.Counted, v.Escalation.Rule, escalationMinCount)
	}
	if v.TraceID != "trace-todo87-s1" {
		t.Errorf("local verdict row trace_id = %q, want the turn's trace", v.TraceID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-24.S2 — nothing is uploaded twice, nothing reaches master
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_PersonalRouteNoDoubleUpload
//
// The detector has ALREADY uploaded each piece's content row to the local store.
// So on the personal route the proxy's local batch must hold the verdict row and
// nothing else, the verdict must name exactly the three projection event ids
// (the ids of the rows the detector uploaded), and the team sink must receive
// ZERO requests — the 2026-05-10 personal/team isolation is unchanged (V1).
func TestEscalation_PersonalRouteNoDoubleUpload(t *testing.T) {
	sinks := newRouteSinks(t)
	pieces := threeMembers()
	mint := &projectionMint{}
	p := &Proxy{filterHook: personalHook(t, pieces, mint, true), reporter: sinks.rep}
	mustSetGrading(t, p, escalationRulesFixture())

	if filterPersonal(p, httptest.NewRecorder(), personalRequest(t, pieces), "trace-todo87-s2", discardLogger()) {
		t.Fatal("the request must be refused — three distinct confirmed L4 hits")
	}
	if got := mint.minted(); got != len(pieces) {
		t.Fatalf("detector calls = %d, want %d", got, len(pieces))
	}

	local := firstBatch(sinks.local, 3*time.Second)
	if local == nil {
		t.Fatal("local sink received nothing — the verdict row this fence inspects was never written")
	}
	extraLocal := batchesWithin(sinks.local, 500*time.Millisecond)
	team := batchesWithin(sinks.team, 200*time.Millisecond)

	if len(team) != 0 {
		t.Errorf("the TEAM sink (control-master) received %d request(s) for a personal-route request.\n"+
			"TODO-87 V1 (2026-09-15): the personal route's verdict row is written to the local self-view "+
			"ONLY; master gets nothing and the personal/team isolation of 2026-05-10 stands.\nfirst: %s",
			len(team), team[0])
	}
	if len(extraLocal) != 0 {
		t.Errorf("local sink received %d extra batch(es); one request produces one verdict batch: %s",
			len(extraLocal), extraLocal[0])
	}

	evs := decodeBatch(t, local)
	if len(evs) != 1 {
		t.Fatalf("local batch carries %d events, want exactly 1 (the verdict row). The detector already "+
			"uploaded every content row itself; a content row here is a SECOND copy.\nbody: %s", len(evs), local)
	}
	if evs[0].Scenario != scenarioRequestVerdict {
		t.Fatalf("the one local event is scenario %q, want %q\nbody: %s", evs[0].Scenario, scenarioRequestVerdict, local)
	}
	want := make([]string, 0, len(pieces))
	for _, pc := range pieces {
		ids := mint.idsFor(pc.text)
		if len(ids) != 1 {
			t.Fatalf("piece %q was scanned %d times, want 1", pc.text, len(ids))
		}
		want = append(want, ids[0])
	}
	if !reflect.DeepEqual(evs[0].Escalation.UnitIDs, want) {
		t.Errorf("verdict unit_ids = %v, want the three projection event ids %v — on the personal route the "+
			"verdict must name the rows the DETECTOR uploaded, or every id in it dangles", evs[0].Escalation.UnitIDs, want)
	}

	var raw struct {
		Events []map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(local, &raw); err != nil {
		t.Fatalf("decode local batch: %v", err)
	}
	if rs, ok := raw.Events[0]["route_source"]; ok {
		t.Errorf("local verdict row carries route_source=%s; on the local store that key labels a MIRROR of a "+
			"team event, and this row is the personal lane's own", rs)
	}
	for _, pc := range pieces {
		for _, probe := range derivations(pc.hit.value) {
			if strings.Contains(string(local), probe.text) {
				t.Errorf("local verdict batch carries %s of %q (R-compliance-grading-16)", probe.what, pc.hit.value)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-24.S4 — history served from cache still counts
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_PersonalRouteCacheHitStillCounts
//
// Turn 1 carries A and B (two values, under the threshold). Turn 2 resends A and
// B as history and adds C. A and B are served from the verdict cache — the
// detector is called ONCE on turn 2 — and still count, so turn 2 is refused. The
// verdict names A's and B's ids from the TURN-1 scans (the rows that exist).
func TestEscalation_PersonalRouteCacheHitStillCounts(t *testing.T) {
	sinks := newRouteSinks(t)
	pieces := threeMembers()
	mint := &projectionMint{}
	hook := personalHook(t, pieces, mint, true)
	p := &Proxy{filterHook: hook, reporter: sinks.rep}
	p.SetFilterCacheEnabled(true, 5)
	mustSetGrading(t, p, escalationRulesFixture())

	if !filterPersonal(p, httptest.NewRecorder(), personalRequest(t, pieces[:2]), "trace-todo87-s4-t1", discardLogger()) {
		t.Fatal("turn 1 carries two distinct values, under the threshold, and must be forwarded")
	}
	if esc := p.escalationSnapshot(); esc.counted != 2 || esc.triggered != 0 {
		t.Fatalf("turn 1 counted/triggered = %d/%d, want 2/0", esc.counted, esc.triggered)
	}

	callsBefore := hook.count()
	if filterPersonal(p, httptest.NewRecorder(), personalRequest(t, pieces), "trace-todo87-s4-t2", discardLogger()) {
		t.Fatal("turn 2 (A, B from history + C) reaches three distinct values and must be refused")
	}
	if got := hook.count() - callsBefore; got != 1 {
		t.Fatalf("detector calls on turn 2 = %d, want 1 — A and B must be served from the verdict cache, or "+
			"this fence says nothing about cache hits", got)
	}
	if esc := p.escalationSnapshot(); esc.counted != escalationMinCount || esc.triggered != 1 {
		t.Fatalf("turn 2 counted/triggered = %d/%d, want %d/1 — a history piece served from cache must still "+
			"participate in this turn's count (R-compliance-grading-18.S3)", esc.counted, esc.triggered, escalationMinCount)
	}

	body := firstBatch(sinks.local, 3*time.Second)
	if body == nil {
		t.Fatal("local sink received no verdict row for turn 2")
	}
	v := findRequestVerdict(t, body)
	if v.TraceID != "trace-todo87-s4-t2" {
		t.Fatalf("verdict row trace_id = %q, want turn 2's", v.TraceID)
	}
	want := []string{mint.idsFor(pieces[0].text)[0], mint.idsFor(pieces[1].text)[0], mint.idsFor(pieces[2].text)[0]}
	if !reflect.DeepEqual(v.Escalation.UnitIDs, want) {
		t.Errorf("verdict unit_ids = %v, want %v — cache-served pieces must be named by the id of the scan that "+
			"populated the cache", v.Escalation.UnitIDs, want)
	}
	if team := batchesWithin(sinks.team, 300*time.Millisecond); len(team) != 0 {
		t.Errorf("team sink received %d request(s) across two personal-route turns", len(team))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-18 on the personal route — the verdict lists what counted
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_PersonalRouteRefusedRequestListsOnlyCounted mirrors
// TestEscalation_RefusedRequestStillRecordsUncountedPieces on the personal
// route: five pieces, three counted, one below min_level, one unconfirmed. The
// verdict row lists the three counted pieces' projection ids and nothing else.
func TestEscalation_PersonalRouteRefusedRequestListsOnlyCounted(t *testing.T) {
	const (
		idA       = "110101199003071234"
		idB       = "310101198807153695"
		idC       = "440305197502289517"
		idLow     = "320102198001011237"
		idUnconfd = "510104199512127890"
	)
	pieces := []personalPiece{
		{"请核对客户 " + idA + " 的资料", gradedHit{idA, "pii", escalationMinLevel, true}, apphook.ActionMask},
		{"另外 " + idB + " 也要一起处理一下", gradedHit{idB, "pii", escalationMinLevel, true}, apphook.ActionMask},
		{idC + " 是第三位客户", gradedHit{idC, "pii", escalationMinLevel, true}, apphook.ActionMask},
		{"备注里顺带提到 " + idLow + " 这个号码,仅供参考", gradedHit{idLow, "pii", escalationMinLevel - 2, true}, apphook.ActionMask},
		{"未核实的号码 " + idUnconfd + " 请忽略", gradedHit{idUnconfd, "pii", escalationMinLevel, false}, apphook.ActionMask},
	}
	sinks := newRouteSinks(t)
	mint := &projectionMint{}
	p := &Proxy{filterHook: personalHook(t, pieces, mint, true), reporter: sinks.rep}
	mustSetGrading(t, p, escalationRulesFixture())

	if filterPersonal(p, httptest.NewRecorder(), personalRequest(t, pieces), "trace-todo87-only-counted", discardLogger()) {
		t.Fatal("the request must be refused — three distinct confirmed L4 hits")
	}
	if esc := p.escalationSnapshot(); esc.counted != escalationMinCount || esc.triggered != 1 {
		t.Fatalf("counted/triggered = %d/%d, want %d/1 — if counted is higher the uncounted pieces were counted "+
			"and this fence proves nothing", esc.counted, esc.triggered, escalationMinCount)
	}
	if got := mint.minted(); got != len(pieces) {
		t.Fatalf("detector calls = %d, want %d — the trailing uncounted pieces must be scanned", got, len(pieces))
	}

	body := firstBatch(sinks.local, 3*time.Second)
	if body == nil {
		t.Fatal("local sink received no verdict row")
	}
	v := findRequestVerdict(t, body)
	want := []string{mint.idsFor(pieces[0].text)[0], mint.idsFor(pieces[1].text)[0], mint.idsFor(pieces[2].text)[0]}
	if !reflect.DeepEqual(v.Escalation.UnitIDs, want) {
		t.Errorf("verdict unit_ids = %v, want exactly the counted pieces' ids %v (R-compliance-grading-18)",
			v.Escalation.UnitIDs, want)
	}
	if team := batchesWithin(sinks.team, 300*time.Millisecond); len(team) != 0 {
		t.Errorf("team sink received %d request(s) for a personal-route request", len(team))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-24.S3 — no rules, no change
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_PersonalRouteEmptyRulesNoVerdictNoUpload: with no escalation
// rules (an org that never configured them, and every Personal-edition box), a
// refused personal-route request behaves exactly as before: the per-piece
// refusal stands, the verdict path runs and concludes nothing, and the proxy
// uploads NOTHING to either sink.
func TestEscalation_PersonalRouteEmptyRulesNoVerdictNoUpload(t *testing.T) {
	const (
		idA = "110101199003071234"
		idB = "310101198807153695"
	)
	pieces := []personalPiece{
		{"请核对客户 " + idA + " 的资料", gradedHit{idA, "pii", escalationMinLevel, true}, apphook.ActionBlock},
		{"另外 " + idB + " 也要一起处理", gradedHit{idB, "pii", escalationMinLevel, true}, apphook.ActionMask},
	}
	sinks := newRouteSinks(t)
	mint := &projectionMint{}
	p := &Proxy{filterHook: personalHook(t, pieces, mint, true), reporter: sinks.rep}
	h := newLogCapture()

	w := httptest.NewRecorder()
	if filterPersonal(p, w, personalRequest(t, pieces), "trace-todo87-s3", correlatedLogger(h)) {
		t.Fatal("a piece the detector blocked must still refuse the request")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if esc := p.escalationSnapshot(); esc.evaluated != 1 || esc.triggered != 0 {
		t.Errorf("evaluated/triggered = %d/%d, want 1/0 — the verdict path must RUN and conclude nothing",
			esc.evaluated, esc.triggered)
	}
	if local := batchesWithin(sinks.local, 700*time.Millisecond); len(local) != 0 {
		t.Errorf("local sink received %d batch(es) with no rules configured: %s", len(local), local[0])
	}
	if team := batchesWithin(sinks.team, 100*time.Millisecond); len(team) != 0 {
		t.Errorf("team sink received %d batch(es) for a personal-route request: %s", len(team), team[0])
	}
	if recs := h.withEvent(observability.EventProxyFilterPersonalProjectionMissing); len(recs) != 0 {
		t.Errorf("missing-projection WARN fired with no rules installed")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BUT NOT — an old detector only warns, never blocks
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_PersonalRouteMissingProjectionWarns: rules are installed, a
// personal-route piece comes back flagged, and the detector handed back no
// projection (a detector older than this proxy). The piece cannot count; the
// request is NOT failed over it; and exactly one WARN, carrying the request
// correlation ids, says so — on the transition, not per request.
func TestEscalation_PersonalRouteMissingProjectionWarns(t *testing.T) {
	flagged := threeMembers()[:2] // two masked pieces — under the threshold either way

	run := func(t *testing.T, p *Proxy, pieces []personalPiece, withProjection bool, h *logCapture) bool {
		t.Helper()
		p.filterHook = personalHook(t, pieces, &projectionMint{}, withProjection)
		return filterPersonal(p, httptest.NewRecorder(), personalRequest(t, pieces), "trace-todo87-warn", correlatedLogger(h))
	}

	t.Run("rules installed, flagged pieces without a projection → one WARN, request forwarded", func(t *testing.T) {
		p := &Proxy{}
		mustSetGrading(t, p, escalationRulesFixture())
		h := newLogCapture()
		if !run(t, p, flagged, false, h) {
			t.Fatal("a missing projection must never refuse a request (fail-open, §6 #11)")
		}
		recs := h.withEvent(observability.EventProxyFilterPersonalProjectionMissing)
		if len(recs) != 1 {
			t.Fatalf("%d %q records, want exactly 1 — an old detector silently disables the org rule on "+
				"personal keys, and this line is the only thing that says so", len(recs),
				observability.EventProxyFilterPersonalProjectionMissing)
		}
		rec := recs[0]
		if rec.level != slog.LevelWarn {
			t.Errorf("level = %v, want WARN", rec.level)
		}
		for _, key := range []string{"request_id", "trace_id", "span_id"} {
			if rec.str(key) == "" {
				t.Errorf("the WARN carries no %s (日志规范); attrs: %v", key, rec.attrs)
			}
		}
		if got := rec.num("pieces_without_projection"); got != int64(len(flagged)) {
			t.Errorf("pieces_without_projection = %d, want %d", got, len(flagged))
		}

		// Latched: the same condition on the next request logs nothing more.
		if !run(t, p, flagged, false, h) {
			t.Fatal("second request refused")
		}
		if n := len(h.withEvent(observability.EventProxyFilterPersonalProjectionMissing)); n != 1 {
			t.Errorf("after a second affected request there are %d WARNs, want still 1 (transition only)", n)
		}
		// A projection arriving again closes the bracket with one INFO.
		if !run(t, p, flagged, true, h) {
			t.Fatal("third request refused")
		}
		restored := h.withEvent(observability.EventProxyFilterPersonalProjectionRestored)
		if len(restored) != 1 || restored[0].level != slog.LevelInfo {
			t.Errorf("restored records = %d, want exactly 1 INFO once projections are back", len(restored))
		}
	})

	t.Run("projections present → no WARN", func(t *testing.T) {
		p := &Proxy{}
		mustSetGrading(t, p, escalationRulesFixture())
		h := newLogCapture()
		run(t, p, flagged, true, h)
		if n := len(h.withEvent(observability.EventProxyFilterPersonalProjectionMissing)); n != 0 {
			t.Errorf("%d missing-projection WARNs with every projection present", n)
		}
	})

	t.Run("no rules installed → no WARN (the Personal edition, an org without rules)", func(t *testing.T) {
		p := &Proxy{}
		h := newLogCapture()
		run(t, p, flagged, false, h)
		if n := len(h.withEvent(observability.EventProxyFilterPersonalProjectionMissing)); n != 0 {
			t.Errorf("%d missing-projection WARNs with no rules — nothing is being under-enforced", n)
		}
	})

	t.Run("an allow verdict without a projection → no WARN", func(t *testing.T) {
		p := &Proxy{}
		mustSetGrading(t, p, escalationRulesFixture())
		h := newLogCapture()
		clean := []personalPiece{{"nothing sensitive here", gradedHit{"nothing", "pii", 1, false}, apphook.ActionAllow}}
		run(t, p, clean, false, h)
		if n := len(h.withEvent(observability.EventProxyFilterPersonalProjectionMissing)); n != 0 {
			t.Errorf("%d missing-projection WARNs for a clean piece, which legitimately has no projection", n)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// The projection's field names and the proxy's reader are one contract
// ─────────────────────────────────────────────────────────────────────────────

// TestCountProjection_TagsMatchProxyFinding pins proxy.Finding — the reader the
// counter decodes BOTH a team event's findings and a personal-route projection
// with — against pipewire.CountedFinding, the single definition of the
// projection's JSON tags. A tag on one side that the other lacks decodes to a
// zero value: an uncounted hit, silently, in the permissive direction.
func TestCountProjection_TagsMatchProxyFinding(t *testing.T) {
	proj := jsonFieldTypes(reflect.TypeOf(pipewire.CountedFinding{}))
	reader := jsonFieldTypes(reflect.TypeOf(Finding{}))
	for name, pt := range proj {
		rt, ok := reader[name]
		if !ok {
			t.Errorf("pipewire.CountedFinding carries %q but proxy.Finding does not read it", name)
			continue
		}
		if derefType(pt) != derefType(rt) {
			t.Errorf("%q is %v on the projection but %v on proxy.Finding", name, pt, rt)
		}
	}
	for name := range reader {
		if _, ok := proj[name]; !ok {
			t.Errorf("proxy.Finding reads %q, which the personal-route projection never carries — it would "+
				"always decode to zero there", name)
		}
	}
}

func jsonFieldTypes(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = f.Type
	}
	return out
}

func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}
