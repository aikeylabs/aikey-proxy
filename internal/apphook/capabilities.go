package apphook

// capabilities.go — what THIS proxy binary declares it can process from a child
// it spawns (TODO-114, user decision 2026-09-15 方案 A; 需求包
// roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/runs/design-todo-114.md §2.3).
//
// The wire spelling, the token list and the parser live ONCE, in pkg/pipewire
// (capabilities.go), which both repositories import through a go.mod replace.
// This file is only the proxy's answer to "what can I do?".
//
// # WHY THE SET IS DERIVED FROM COMPILED CODE, AND FROM NOTHING ELSE
//
// 🔴 NO VAULT, NO CONFIG, NO os.Getenv. A capability is a property of this
// BINARY: whether the code that decodes a personal-route count projection, or
// the code that synthesizes a canned answer, is linked into the process. It
// changes only when the binary changes, which is exactly the granularity a spawn
// env has (the child is re-spawned when the proxy restarts).
//
// The moment it could come from configuration, every channel that writes the
// proxy's environment — ~/.aikey/proxy.env (aikey-cli commands_proxy.rs),
// /etc/aikey/cluster-node.env (the cluster systemd unit's EnvironmentFile), the
// Lobster de-proxy.env, a developer's shell — could assert "I can receive count
// projections" on behalf of a process that cannot. That is the precise defect
// TODO-114 exists to prevent, reached from the inside instead of from an old
// release. It is the same fence filter_hook.go puts on the privacy tier: "READ
// THE ATOMIC, NEVER THE ENVIRONMENT … if this ever grows an os.Getenv fallback
// 'for testing', that is the fence gone."
//
// Fenced by TestProxyNeverReadsCapabilitiesFromItsOwnEnvironment
// (internal/supervisor), which scans internal/** for a Getenv/LookupEnv on this
// env name.
//
// # WHY THE ENV LINE IS ALWAYS EMITTED, EVEN WHEN THE SET IS EMPTY
//
// childhook.go builds the child environment as append(os.Environ(),
// cfg.ExtraEnv...), and Go's os/exec de-duplicates keeping the LAST occurrence.
// So an entry in ExtraEnv always wins over anything inherited. That only helps
// if the entry is THERE: omitting it when the set is empty would let a residue
// value from any of the channels above reach the child unchallenged. One
// unconditional line is the entire defense, so ProxyCapabilitiesEnv returns
// `AIKEY_PROXY_CAPABILITIES=` rather than "" for an empty set, and
// filter_hook.go puts it in the RESIDENT extraEnv slice, never in a branch.

import "github.com/AiKeyLabs/pkg/pipewire"

// SupportsCountProjection reports whether this build counts a PERSONAL-routed
// Detect's Response.Event as a pipewire.CountProjection.
//
// TRUE since TODO-87: internal/proxy/filter_dispatch.go decodes resp.Event with
// decodeEventFindings on every route and feeds the request-level escalation
// counter, and internal/proxy/escalation.go notePersonalProjectionState warns
// when a flagged personal piece arrives without one.
//
// 🔴 WHAT IT CLAIMS: this binary can READ a projection and count it without
// uploading it. A build that declares this and does not do it is worse than one
// that never declared: the detector will hand over bytes that get counted by
// nothing, or — the TODO-114 defect in mirror image — counted by something that
// writes no audit row.
func SupportsCountProjection() bool { return true }

// DeclaredCapabilities is the set this binary declares, derived ONLY from the
// compiled Supports* predicates above, sorted and de-duplicated by
// pipewire.FormatProxyCapabilities' contract (the sort happens there; this
// returns the raw membership).
//
// Adding a capability = adding a Supports* function and one line here. There is
// deliberately no table, no registry and no init(): a capability that is not
// answered by a compiled predicate has no business being declared.
func DeclaredCapabilities() []string {
	caps := make([]string, 0, 2)
	if SupportsCountProjection() {
		caps = append(caps, pipewire.CapCountProjection)
	}
	if SupportsCannedAnswer() {
		// Declared truthfully even though NO child consumes it yet (TODO-68: the
		// detector does not read this token until TODO-91 closes). Declaring what
		// the binary can actually do means the later detector release needs no
		// proxy change — see design §2.5.
		caps = append(caps, pipewire.CapCannedAnswer)
	}
	return caps
}

// ProxyCapabilitiesEnv renders the single "KEY=VALUE" entry the supervisor puts
// in the child's ExtraEnv.
//
// 🔴 ALWAYS ONE LINE. Never "" and never omitted — see the file comment: the
// unconditional line is what overrides an inherited residue value.
func ProxyCapabilitiesEnv() string {
	return capabilitiesEnvLine(DeclaredCapabilities())
}

// capabilitiesEnvLine composes the entry from an arbitrary set. It exists so the
// EMPTY-set shape (`AIKEY_PROXY_CAPABILITIES=`, a line, not "") can be asserted
// even while this build happens to declare two capabilities — the day a
// Supports* goes false, that shape is the whole residue defense and nothing
// would otherwise be watching it.
func capabilitiesEnvLine(capabilities []string) string {
	return pipewire.EnvProxyCapabilities + "=" + pipewire.FormatProxyCapabilities(capabilities)
}
