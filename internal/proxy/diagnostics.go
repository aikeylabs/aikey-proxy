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
	// MappingDegraded: a model_map IS configured but requests are NOT matching it
	// (reject/passthrough seen) — the "配置了但没生效" case the four surfaces warn on.
	MappingDegraded MappingStatus = "degraded"
)

// PipelineDiagnostics is the read-only payload of /v1/diagnostics/pipeline.
type PipelineDiagnostics struct {
	Registry     RegistryProvenance `json:"registry"`
	ModelMapping MappingHealth      `json:"model_mapping"`
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

	hasMappings := len(provider.Routes().AllModelMaps()) > 0
	h := MappingHealth{
		Applied:            applied,
		Rejected:           rejected,
		PassthroughMissing: passthrough,
		LastMiss:           last,
	}
	switch {
	case !hasMappings:
		h.Status = MappingInactive
		h.Reason = "No model mapping is configured in this build's registry."
	case rejected+passthrough > 0:
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
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}
