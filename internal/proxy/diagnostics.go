// diagnostics.go — read-only pipeline diagnostics endpoint (task 7.9) and the
// single source-of-truth model-mapping health judgment (task 3.5).
//
// GET /v1/diagnostics/pipeline exposes, WITHOUT mutating anything:
//   - registry provenance: the embedded provider_fingerprint digest, the route
//     row count, and which providers carry a model_map ("mapping comes from
//     registry vX" — the read-only visibility that replaced the deleted P5 UI).
//   - model-mapping runtime health: a 3-state verdict + the counters + the last
//     "configured but not effective" occurrence, so the four surfaces (web
//     banner / aikey doctor / aikey test / ak use) can all answer "was a mapping
//     configured but not taking effect?" from ONE function (mappingHealth), never
//     an inlined marker string per caller (3.5 hard rule).
//   - compliance mask-placeholder fidelity (P2, 方案 20260808 §3.2 L3): issued
//     vs restored placeholder counts + a 3-state verdict. This is the only
//     signal that surfaces "some model started rewriting our placeholders" —
//     every such request still returns 200, so without an externally readable
//     counter the degradation is invisible (health-signal-surface §H1).
//
// 🔴 GET-only + read-only (design P5-deletion note: status endpoints must not
// mutate). Health signals must be externally readable (observability §H1/H2).
package proxy

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// MappingStatus is the 3-state model-mapping verdict. Stable string values so
// every surface (web/doctor/test/ak use) renders the same three states.
type MappingStatus string

const (
	// MappingInactive: no model_map is configured in the live registry at all —
	// mapping simply isn't in play (not an error; the banner stays silent).
	MappingInactive MappingStatus = "inactive"
	// MappingOK: mappings are configured and applying cleanly (no recent misses).
	MappingOK MappingStatus = "ok"
	// MappingDegraded: a model_map IS configured but the MOST RECENT relevant
	// event was a passthrough-miss (a request slipped past unchanged) newer than
	// the last successful apply — the "配置了但没生效" case the four surfaces warn
	// on. Recoverable: a later successful apply clears it. A reject does NOT
	// count (unmatched=reject policy WORKING is not a degradation).
	MappingDegraded MappingStatus = "degraded"
)

// PipelineDiagnostics is the read-only payload of /v1/diagnostics/pipeline.
//
// MaskRestore was ADDED here rather than behind a new endpoint (慎重新建
// API/接口协议): this endpoint already is the proxy's read-only "is the request
// pipeline behaving?" surface, an additive field costs no new route, no new
// auth posture and no new client contract, and the two blocks are read by the
// same operator in the same breath.
type PipelineDiagnostics struct {
	Registry     RegistryProvenance `json:"registry"`
	ModelMapping MappingHealth      `json:"model_mapping"`
	MaskRestore  MaskRestoreHealth  `json:"mask_restore"`
}

// MaskRestoreStatus is the 3-state compliance-placeholder fidelity verdict.
// Same three string values as MappingStatus so every surface renders both
// blocks with one switch.
type MaskRestoreStatus string

const (
	// MaskRestoreInactive: this process has never issued a mask placeholder —
	// compliance masking is off, or no traffic hit a restorable entity.
	MaskRestoreInactive MaskRestoreStatus = "inactive"
	// MaskRestoreOK: placeholders are coming back and being restored.
	MaskRestoreOK MaskRestoreStatus = "ok"
	// MaskRestoreDegraded: enough placeholders have been issued to judge, and
	// the models are returning too few of them intact — i.e. users are seeing
	// `{{ADDR_1}}` instead of their own text. NOT an error path: the request
	// succeeded, the mask worked, only the convenience half is failing.
	MaskRestoreDegraded MaskRestoreStatus = "degraded"
)

const (
	// maskFidelityMinSample: below this many issued placeholders the ratio is
	// noise (one unlucky answer would read as 0%), so the verdict stays `ok`.
	maskFidelityMinSample = 20
	// maskFidelityDegradedPct: the L3 defenses (template-syntax placeholder +
	// tolerant matching) are designed to make near-100% the normal reading; a
	// sustained drop below this means some model started rewriting placeholders
	// and the mask/restore feature is silently degrading for its users.
	maskFidelityDegradedPct = 80
)

// MaskRestoreHealth is the externally-readable 保真率 signal (方案 20260808
// §3.2 L3). Issued/Restored are cumulative for the process lifetime; the
// verdict is derived, never latched — a model that starts behaving again pulls
// the cumulative ratio back up (health-signal-surface: report the current
// state, not a terminal one).
//
// Privacy: counts only. No label, no entity code, no length, no text — the
// placeholder↔original mapping never leaves request memory (B3 拍板).
type MaskRestoreHealth struct {
	Status MaskRestoreStatus `json:"status"`
	Reason string            `json:"reason"`
	// ScanRoles is the effective inbound scan-role policy (方案 §3.4). It lives in
	// THIS block — not a config dump — because restore and scan-scope are one
	// safety property: restoration hands the plaintext back to the client, and it
	// only stays out of the upstream on the next turn because `assistant` is
	// scanned. An operator (or the release E2E) must be able to READ that from
	// outside the process, not infer it from a startup log line
	// (health-signal-surface). Counts + this list answer "is mask/restore whole?".
	ScanRoles   []string `json:"scan_roles"`
	Issued      int64    `json:"placeholders_issued"`
	Restored    int64    `json:"placeholders_restored"`
	FidelityPct int      `json:"fidelity_pct"`
}

// maskRestoreHealth is the ONE function every surface consults for placeholder
// fidelity (same posture as mappingHealth). Pure read; safe to call concurrently.
func (p *Proxy) maskRestoreHealth() MaskRestoreHealth {
	issued := p.maskFidelity.issued.Load()
	restored := p.maskFidelity.restored.Load()
	h := MaskRestoreHealth{Issued: issued, Restored: restored, ScanRoles: p.filterScanRoles.list()}
	if issued <= 0 {
		h.Status = MaskRestoreInactive
		h.Reason = "No compliance mask placeholder has been issued by this proxy."
		return h
	}
	h.FidelityPct = int(restored * 100 / issued)
	if issued >= maskFidelityMinSample && h.FidelityPct < maskFidelityDegradedPct {
		h.Status = MaskRestoreDegraded
		h.Reason = "Models are returning too few mask placeholders intact — users are seeing placeholders instead of their own text."
		return h
	}
	h.Status = MaskRestoreOK
	h.Reason = "Mask placeholders are being returned by the models and restored."
	return h
}

// RegistryProvenance proves WHICH embedded registry is live (P7.14: the digest
// changes only when the binary does — editing a mapping line is a re-release).
type RegistryProvenance struct {
	Digest                string   `json:"digest"`
	RouteRows             int      `json:"route_rows"`
	ProvidersWithModelMap []string `json:"providers_with_model_map"`
}

// MappingHealth is the single source-of-truth verdict + evidence. `Reason` is a
// terse, surface-agnostic sentence the callers render verbatim.
type MappingHealth struct {
	Status             MappingStatus  `json:"status"`
	Reason             string         `json:"reason"`
	Applied            int64          `json:"applied"`
	Rejected           int64          `json:"rejected"`
	PassthroughMissing int64          `json:"passthrough_missing"`
	LastMiss           *mapMissRecord `json:"last_miss,omitempty"`
}

// mappingHealth is the ONE function every surface consults (3.5: 🚫 no per-caller
// inlined marker strings). It reads the live registry + the runtime counters and
// returns the 3-state verdict. Pure read; safe to call concurrently.
func (p *Proxy) mappingHealth() MappingHealth {
	applied := p.mapApplied.Load()
	rejected := p.mapRejected.Load()
	passthrough := p.mapPassthrough.Load()
	last := p.lastMapMiss.Load()
	missNano := p.lastMapMissNano.Load()
	applyNano := p.lastMapApplyNano.Load()

	hasMappings := len(provider.Routes().AllModelMaps()) > 0
	h := MappingHealth{
		Applied:            applied,
		Rejected:           rejected, // kept for visibility; deliberately OUT of the verdict
		PassthroughMissing: passthrough,
		LastMiss:           last,
	}
	switch {
	case !hasMappings:
		h.Status = MappingInactive
		h.Reason = "No model mapping is configured in this build's registry."
	case missNano > applyNano:
		// RECOVERABLE, not a monotonic latch (health-signal-surface: assert
		// transition, not terminal): degraded only while the most-recent
		// passthrough-miss is newer than the most-recent successful apply — the
		// CURRENT state. A later apply (applyNano advances) flips this back to
		// ok. A `reject` (unmatched=reject policy WORKED) never stamps missNano,
		// so a working reject policy is NOT degraded.
		h.Status = MappingDegraded
		h.Reason = "A model mapping is configured but recent requests did not match it — the mapping may not be taking effect for this client."
	default:
		h.Status = MappingOK
		h.Reason = "Model mapping is configured and applying."
	}
	return h
}

// handleDiagnosticsPipeline serves GET /v1/diagnostics/pipeline. Read-only.
func (p *Proxy) handleDiagnosticsPipeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			"METHOD_NOT_ALLOWED", "This diagnostics endpoint is read-only (GET).")
		return
	}

	tbl := provider.Routes()
	provs := make([]string, 0)
	for _, m := range tbl.AllModelMaps() {
		if m.Provider != "" {
			provs = append(provs, m.Provider)
		}
	}
	sort.Strings(provs)

	out := PipelineDiagnostics{
		Registry: RegistryProvenance{
			Digest:                providerroutes.Digest(),
			RouteRows:             tbl.Len(),
			ProvidersWithModelMap: provs,
		},
		ModelMapping: p.mappingHealth(),
		MaskRestore:  p.maskRestoreHealth(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}
