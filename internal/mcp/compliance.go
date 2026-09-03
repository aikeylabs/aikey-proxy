package mcp

// compliance.go — running tool arguments and tool RESULTS past the same DLP
// filter the LLM path uses (P7 task 7.3, invariant 2).
//
// # 🔴 Why both directions
//
// Arguments carry customer data ("look up 张三's orders"). Results carry more of
// it — a tool that queries a database returns whole rows. Scanning only the
// request would mean the backend hands the Agent an entire table, the Agent
// feeds it to the model, and the data is out. Scanning only the response would
// let the argument itself carry a credential to a third-party MCP server.
//
// # 🔴 What is reused, and one correction to the task text
//
// The task says "reuse filterpipe". `internal/proxy/filterpipe` is NOT the
// pipeline — it is a frozen reason-code enum with ZERO call sites, a
// placeholder for a protocol that was never built. The thing that actually runs
// DLP in this product is `apphook.Hook`: the spawned-child dispatcher behind
// `internal/proxy/filter_*.go`.
//
// So this file reuses `apphook.Hook` — the SAME hook instance, the same child
// process, the same rule packs. 🚫 It does NOT reuse `applyInboundFilter`: that
// function extracts content from Anthropic/OpenAI message bodies, rewrites the
// request body in place, and manages a verdict cache keyed on conversation
// scope. None of that is meaningful for a JSON-RPC tool call, and calling it
// would mean teaching it a third body shape.
//
// # 🔴 Why each string is scanned SEPARATELY
//
// The LLM path concatenates content into large pieces because a conversation
// has hundreds of them and the round-trip dominates. A tool call has a handful
// of argument values. Scanning them one at a time costs a few more round trips
// and buys the thing that matters: when the filter returns a MASK, the mutated
// text belongs to exactly one known field, so putting it back is a map
// assignment rather than an offset-mapping problem.
//
// That is what makes masking possible here at all. The alternative — scan the
// whole payload, then try to map the mutated bytes back into the JSON — is the
// restorable-offset machinery the LLM path needs, and getting it wrong would
// either corrupt the arguments or silently forward the unmasked ones.
//
// spec:  workflow/CI/requirements/2026-08-20-mcp-gateway.md R28 (this reuses
//        apphook.Hook — filterpipe is a zero-call-site placeholder)
// drill: make -C workflow/CI verify-mcp-observability (mutations I1–I7)
//
// # 🔴 Degraded means ALLOW, and it must be visible
//
// If the filter child is unreachable the verdict is Allow with Degraded set,
// exactly as on the LLM path: a filter that cannot run must not fail the user's
// request. But the degradation is counted and surfaced — a DLP that is silently
// not running is worse than one that is loudly off.

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// maxScanValueBytes caps one value handed to the filter.
//
// 🔴 A cap at all, because a tool result can be megabytes and the filter child
// has a latency budget measured in milliseconds. Oversized values are scanned
// up to the cap and the truncation is REPORTED — 🚫 never silently skipped,
// which would make a large payload the way to smuggle anything past DLP.
const maxScanValueBytes = 16 << 10

// ComplianceVerdict is what the gateway decides to do with one call.
type ComplianceVerdict struct {
	// Blocked is set when the filter refused the payload.
	Blocked bool
	// Reason is the filter's human-readable explanation.
	//
	// 🔴 It carries the filter's reason, 🚫 never the matched content. Echoing
	// what was detected would send the sensitive value back out in an error
	// message — one more copy of exactly the data the block exists to contain.
	Reason string
	// Mutated is the payload after masking, when anything was masked.
	Mutated json.RawMessage
	// Masked reports whether Mutated differs from the input.
	Masked bool
	// Degraded reports that the filter could not run and the payload was
	// allowed through unscanned.
	Degraded bool
	// Truncated reports that at least one value exceeded the scan cap.
	Truncated bool
	// Events are the audit events the filter handed back for team-routed
	// traffic, to be uploaded by the caller. Empty otherwise.
	Events [][]byte
}

// complianceScanner runs one call's payloads past the filter hook.
type complianceScanner struct {
	// hookFn is read PER REQUEST, not captured. The filter child belongs to a
	// config generation; a captured value would point at the previous
	// generation's child after the first reload, and every scan would come back
	// degraded on a proxy whose filter is running perfectly.
	hookFn func() apphook.Hook
	logger *slog.Logger
	// upload delivers the audit events the filter hands back for team-routed
	// traffic. nil is tolerated and logged — see uploadEvents.
	upload func(ctx context.Context, events [][]byte)
	// routeClass tells the child where its own audit event should go. Only the
	// CLASS crosses the pipe — 🚫 never a credential or a URL.
	routeClass uint8
}

// scanArguments checks a tool call's arguments before anything is contacted.
//
// 🔴 It runs AFTER authorisation and schema validation and BEFORE the credential
// is resolved. After authorisation, so an ungranted caller cannot use DLP
// verdicts as an oracle for what a tool accepts; before the credential, so a
// blocked call never causes a secret to be decrypted into process memory.
func (c *complianceScanner) scanArguments(ctx context.Context, args json.RawMessage) ComplianceVerdict {
	if c.hook() == nil {
		return ComplianceVerdict{}
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(args, &obj); err != nil || len(obj) == 0 {
		// Not a JSON object (the spec permits any value) or empty. Scan the raw
		// text as one value rather than skipping: 🔴 "we could not parse it" must
		// not become "we did not look at it".
		v, mutated := c.scanOne(ctx, string(args), apphook.DirectionInbound)
		if v.Blocked || !v.Masked {
			return v
		}
		// 🔴 Re-marshalled as a JSON value, not spliced in as raw bytes: the
		// filter returns TEXT, and writing text where JSON belongs would produce
		// an arguments payload the backend cannot parse.
		if raw, err := json.Marshal(mutated); err == nil {
			v.Mutated = raw
		} else {
			v.Masked = false
		}
		return v
	}

	// 🔴 Keys sorted, so a blocked call blocks on the same field every time.
	// Map order would make the reported field vary between identical calls, and
	// a support engineer comparing two reports would think they differ.
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := ComplianceVerdict{}
	changed := false
	for _, k := range keys {
		var s string
		if err := json.Unmarshal(obj[k], &s); err != nil {
			// Not a string. Nested objects and arrays are flattened to their
			// string leaves so a value cannot hide one level down.
			nested := flattenStrings(obj[k])
			if nested == "" {
				continue
			}
			s = nested
		}
		v, mutated := c.scanOne(ctx, s, apphook.DirectionInbound)
		out.Degraded = out.Degraded || v.Degraded
		out.Truncated = out.Truncated || v.Truncated
		out.Events = append(out.Events, v.Events...)
		if v.Blocked {
			v.Events = out.Events
			v.Degraded = out.Degraded
			return v
		}
		if v.Masked {
			// 🔴 Only a value that was scanned WHOLE may be replaced. Writing a
			// mask computed from a truncated view back over the full value would
			// delete the unscanned tail — a data-destroying "fix".
			if v.Truncated {
				continue
			}
			raw, err := json.Marshal(mutated)
			if err != nil {
				continue
			}
			obj[k] = raw
			changed = true
		}
	}
	if changed {
		if raw, err := json.Marshal(obj); err == nil {
			out.Mutated, out.Masked = raw, true
		}
	}
	return out
}

// scanResult checks what the backend returned before it reaches the Agent.
//
// 🔴 The RESULT is where the volume is. A tool that answers "select * from
// orders" returns the rows themselves, and an unscanned result path would mean
// the gateway's DLP stops at the door it is cheapest to walk around.
func (c *complianceScanner) scanResult(ctx context.Context, res *mcpwire.CallToolResult) ComplianceVerdict {
	if c.hook() == nil || res == nil {
		return ComplianceVerdict{}
	}
	out := ComplianceVerdict{}
	for i := range res.Content {
		if res.Content[i].Text == "" {
			continue
		}
		v, mutated := c.scanOne(ctx, res.Content[i].Text, apphook.DirectionOutbound)
		out.Degraded = out.Degraded || v.Degraded
		out.Truncated = out.Truncated || v.Truncated
		out.Events = append(out.Events, v.Events...)
		if v.Blocked {
			v.Events = out.Events
			v.Degraded = out.Degraded
			return v
		}
		if v.Masked && !v.Truncated {
			res.Content[i].Text = mutated
			out.Masked = true
		}
	}
	return out
}

// scanOne is the single round trip. It returns the verdict plus, when the
// verdict is a mask, the replacement text for THIS value.
//
// 🔴 The replacement is returned separately rather than stuffed into the
// verdict's Mutated field: at this level the unit is one string, and at the
// caller's level it is the whole arguments object. Using one field for both
// would let the caller forward a bare string where a JSON object belongs.
func (c *complianceScanner) scanOne(ctx context.Context, text string, dir apphook.Direction) (ComplianceVerdict, string) {
	payload := text
	truncated := false
	if len(payload) > maxScanValueBytes {
		payload = payload[:capRunes(payload, maxScanValueBytes)]
		truncated = true
		// 🔴 WARN, not silence. A value big enough to be truncated is exactly
		// the shape an exfiltration takes, and "the filter looked at the first
		// 16 KiB" must be a fact somebody can read.
		c.logger.WarnContext(ctx, "an MCP payload exceeded the compliance scan cap and was scanned only up to it",
			"event.name", observability.EventProxyMCPComplianceTruncated,
			"bytes", len(text), "cap", maxScanValueBytes, "direction", int(dir))
	}
	hook := c.hook()
	if hook == nil {
		return ComplianceVerdict{Truncated: truncated}, ""
	}
	resp := hook.Detect(ctx, &apphook.Request{
		Payload:    []byte(payload),
		Direction:  dir,
		RouteClass: c.routeClass,
	})
	if resp == nil {
		// 🔴 A nil response is treated as DEGRADED, not as allow-and-fine. The
		// difference is whether anybody finds out that nothing was scanned.
		c.logger.WarnContext(ctx, "the compliance filter returned no verdict for an MCP payload; "+
			"the payload was forwarded UNSCANNED",
			"event.name", observability.EventProxyMCPComplianceDegraded)
		return ComplianceVerdict{Degraded: true, Truncated: truncated}, ""
	}
	v := ComplianceVerdict{Degraded: resp.Degraded, Truncated: truncated}
	if len(resp.Event) > 0 {
		v.Events = [][]byte{resp.Event}
	}
	if resp.Degraded {
		c.logger.WarnContext(ctx, "the compliance filter is degraded; an MCP payload was forwarded UNSCANNED",
			"event.name", observability.EventProxyMCPComplianceDegraded, "reason", resp.Reason)
	}
	switch resp.Action {
	case apphook.ActionBlock:
		v.Blocked = true
		v.Reason = resp.Reason
		return v, ""
	case apphook.ActionMask:
		mutated := string(resp.MutatedPayload)
		if mutated != "" && mutated != payload {
			v.Masked = true
			return v, mutated
		}
	case apphook.ActionWarn:
		// Recorded by the filter itself; the call proceeds.
	}
	return v, ""
}

// hook resolves the live filter, tolerating a nil scanner and a nil getter.
//
// 🔴 nil means "no filter app is installed on this node", which is the common
// default — 🚫 not an error, and 🚫 not a reason to refuse the call. A gateway
// that refused every tool call because no DLP app was installed would make the
// optional feature mandatory by accident.
func (c *complianceScanner) hook() apphook.Hook {
	if c == nil || c.hookFn == nil {
		return nil
	}
	return c.hookFn()
}

// uploadEvents hands the filter's own audit events to the caller's uploader.
//
// 🔴 A dropped event is an audit gap and is logged as one. It is NOT allowed to
// fail the request: the tool call's own outcome has already been decided, and
// turning a reporting failure into a user-visible error would make the audit
// trail a availability dependency of the main path.
func (c *complianceScanner) uploadEvents(ctx context.Context, events [][]byte) {
	if c == nil || len(events) == 0 {
		return
	}
	if c.upload == nil {
		c.logger.WarnContext(ctx, "the compliance filter produced audit events for an MCP call but "+
			"no uploader is wired on this node; the events were dropped",
			"event.name", observability.EventProxyMCPComplianceDegraded, "events", len(events))
		return
	}
	c.upload(ctx, events)
}

// flattenStrings collects the string leaves of a nested JSON value.
//
// 🔴 Nested values are scanned, not skipped. A rule that only looked at
// top-level strings would be satisfied by putting the payload one level down,
// which is not a threat model so much as an accident waiting to happen — plenty
// of tools take a `filter` object.
func flattenStrings(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	var sb strings.Builder
	appendStrings(v, 0, &sb)
	return sb.String()
}

// maxFlattenDepth bounds recursion. Deeper values are not scanned, and that is
// a deliberate trade: unbounded recursion on attacker-shaped JSON is a stack
// exhaustion, and 16 levels is far past any real tool schema.
const maxFlattenDepth = 16

func appendStrings(v any, depth int, sb *strings.Builder) {
	if depth > maxFlattenDepth {
		return
	}
	switch t := v.(type) {
	case string:
		if sb.Len() > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(t)
	case []any:
		for _, e := range t {
			appendStrings(e, depth+1, sb)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			appendStrings(t[k], depth+1, sb)
		}
	}
}

// capRunes finds the largest cut <= limit that does not split a UTF-8
// character. 🔴 A byte-slice cut would hand the filter an invalid string, and a
// detector that cannot decode its input reports nothing found.
func capRunes(s string, limit int) int {
	if len(s) <= limit {
		return len(s)
	}
	for i := limit; i > 0; i-- {
		if s[i]&0xC0 != 0x80 {
			return i
		}
	}
	return 0
}
