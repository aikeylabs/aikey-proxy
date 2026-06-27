// routing_override_policy.go — I-side §6.5 keystone (supervisor poll). Mirror of
// group_runtime_policy.go: the always-on proxy pulls the account-level routing
// override endpoint from master (GET /accounts/me/routing, account-JWT) every
// ~60s and stores the sparse seat→account assignments in the shared in-memory
// RoutingOverrideCache. The group-route resolver (group_serve.go → group_resolve.go
// §6.5) reads it at request time to redirect a seat off an unhealthy default.
//
// WHY proxy (not CLI): the engine recomputes overrides as account health drifts;
// the CLI isn't always running. Same master-poll rail compliance/quota/group-runtime
// already use.
//
// MAIN-LINK SAFETY: on master error / non-200 / timeout / no-auth this returns
// without touching the cache (keep-last-known, never flap), and the cache is a
// pure redirect layer the resolver always falls back from. A poll panic is
// isolated by GoSafe in supervisor.New — it can never affect the data path.
package supervisor

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

const routingOverridePollInterval = 60 * time.Second

var routingOverrideHTTPClient = &http.Client{Timeout: 10 * time.Second}

// pollRoutingOverrides runs until ctx is canceled, pulling the account's routing
// overrides every routingOverridePollInterval (plus once at start). No-op unless
// the oauth-group feature is enabled (without group VKs there is no seat to
// redirect). The account-JWT credential is built ONCE and reused across cycles —
// same scoping as pollGroupRuntime (one Bearer refresh window). The endpoint is
// single-account ("me") scoped, matching the local proxy which serves exactly the
// one logged-in account's seats — the same scoping group-runtime already relies on.
func (s *Supervisor) pollRoutingOverrides(ctx context.Context) {
	if !oauthGroupRoutingEnabled() {
		return // feature off → no group VKs → nothing to redirect
	}
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return
	}
	cred := buildCollectorCredentials(s.cfg.Events.CollectorCredentials, gen.vault)["team"]
	if cred == nil {
		// Pre-login / no team credential → nothing to pull with. A reload after
		// `aikey account login` re-runs startup and picks it up.
		return
	}

	s.syncRoutingOverrides(ctx, cred)
	ticker := time.NewTicker(routingOverridePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncRoutingOverrides(ctx, cred)
		}
	}
}

// syncRoutingOverrides pulls the account's routing overrides and, only when the
// routing_version actually advanced, replaces the shared cache. On any error it
// returns leaving the last-known assignments in place (don't flap). Mirrors
// syncGroupRuntime's version-skip + keep-last-known shape.
func (s *Supervisor) syncRoutingOverrides(ctx context.Context, cred events.Credential) {
	if s.routingOverrides == nil {
		return
	}
	masterURL := readControlPanelURL()
	if masterURL == "" {
		return
	}
	bearer, err := cred.Bearer(ctx)
	if err != nil {
		return // can't auth → keep last-known
	}
	version, assignments, ok := fetchRoutingOverrides(ctx, masterURL, bearer)
	if !ok {
		return // unreachable / bad response → keep last-known (don't clear)
	}
	// Skip only once we've ALREADY stored at this version. The Stored() guard
	// closes the first-pull-at-version-0 hole: the cache's version atomic starts
	// at 0, so without it master's first non-empty assignments carrying
	// routing_version:0 would match Version()==0 and be skipped forever (the
	// override never applied, no signal). After the first Store, steady-state
	// re-pulls of the same version skip as before (no churn, no log spam).
	if s.routingOverrides.Stored() && s.routingOverrides.Version() == version {
		return // unchanged → no churn (empty map skip is harmless: lookups miss either way)
	}
	s.routingOverrides.Store(version, assignments)
	slog.Info("routing overrides updated",
		"event.name", "proxy.routing_override.changed",
		"routing_version", version, "seats", len(assignments))
}

// routingOverrideResp mirrors master's GET /accounts/me/routing body. Assignments
// is SPARSE: only seats the engine redirects away from an unhealthy default appear;
// an empty/absent map = nothing to redirect.
type routingOverrideResp struct {
	RoutingVersion int64             `json:"routing_version"`
	Assignments    map[string]string `json:"assignments"`
}

// fetchRoutingOverrides GETs the routing endpoint with an account-JWT Bearer.
// Returns (version, assignments, ok); ok=false on ANY error so the caller keeps
// the last-known cache (don't flap). A nil assignments is normalized to an empty
// map so an ok=true pull always carries a concrete (possibly empty) map.
func fetchRoutingOverrides(ctx context.Context, masterURL, bearer string) (int64, map[string]string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, masterURL+"/accounts/me/routing", http.NoBody)
	if err != nil {
		return 0, nil, false
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := routingOverrideHTTPClient.Do(req)
	if err != nil {
		return 0, nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, false
	}
	var out routingOverrideResp
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, nil, false
	}
	if out.Assignments == nil {
		out.Assignments = map[string]string{}
	}
	return out.RoutingVersion, out.Assignments, true
}
