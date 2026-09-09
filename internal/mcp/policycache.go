package mcp

// policycache.go — the on-disk copy of the last policy the control plane sent.
//
// # What it is for, precisely
//
// ONE scenario: the proxy restarts while the control plane is unreachable.
// Without a cache, the fleet comes back with no policy, so every Agent's tools
// vanish — and they stay vanished until the control plane returns. With it, the
// proxy serves the last known policy immediately and converges on the first
// successful poll.
//
// That is a real scenario for this product: a self-hosted deployment where the
// control plane and the developer machines fail independently, and where a
// laptop rebooting during a maintenance window must not lose its tooling.
//
// # 🔴 Deviation from the plan, stated rather than hidden
//
// tasks 2.6 specifies "a local cache TABLE (SQLite)". This is a FILE instead,
// and the reason is the project's own "慎重建表" rule:
//
//	the quota rail's precedent (quota_rules_cache) lives in the VAULT schema,
//	which is owned by aikey-cli/src/migrations.rs — a released, one-way-door
//	schema in another repository and another language.
//
//	this data is a CACHE. It is never authoritative, it is reconstructible from
//	the control plane in one poll interval, and deleting it is a supported
//	operation (fence 2.F5 deletes it on purpose). Committing a permanent
//	migrated schema to hold something disposable is the trade that rule exists
//	to prevent.
//
//	the repo already has a precedent for proxy-local run state as a file under
//	~/.aikey/run/ (group-login-required.json, proxy-runtime.json), with the same
//	atomic temp+rename discipline used here.
//
// Behaviourally the two are indistinguishable to every fence in P2. If a future
// requirement needs to QUERY this data rather than load it whole, that is the
// moment a table earns its keep — and it can be added then, with the query as
// the evidence.
//
// # The three disciplines tasks 2.6 requires, all honoured
//
//	read fails   → empty state, INFO not ERROR. A missing or corrupt cache is
//	               not a fault; the next poll fixes it.
//	write fails  → WARN and carry on. The policy in memory is already correct;
//	               only the restart shortcut is lost.
//	main path    → zero dependency. Nothing in the request path reads this file.
//	               It is written after a successful poll and read once at boot.

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// policyCacheFilename is the file under the run directory.
const policyCacheFilename = "mcp-policy-cache.json"

// cachedPolicy is the file's body.
type cachedPolicy struct {
	// OrgID guards against serving one organisation's policy to another after a
	// re-registration. 🔴 A cache keyed by nothing is a cache that can answer
	// the wrong tenant.
	OrgID string `json:"org_id"`
	// WrittenAtMs lets a reader reject an implausibly old file.
	WrittenAtMs int64 `json:"written_at_ms"`
	// Policy is the snapshot verbatim.
	Policy *Policy `json:"policy"`
}

// PolicyCache persists and restores the last known policy.
type PolicyCache struct {
	logger *slog.Logger
	// maxAge bounds how stale a restored policy may be. Beyond it the cache is
	// ignored and the proxy waits for a real poll.
	//
	// 🔴 A bound is necessary, not decorative: a laptop that was shut for three
	// weeks would otherwise come back serving three-week-old grants, including
	// ones revoked in the meantime. Seven days is chosen to cover a holiday
	// weekend plus a maintenance window while staying far short of "we forgot
	// this machine existed".
	maxAge time.Duration
	now    func() time.Time
}

// DefaultPolicyCacheMaxAge is how stale a restored policy may be.
const DefaultPolicyCacheMaxAge = 7 * 24 * time.Hour

// NewPolicyCache builds the cache. maxAge <= 0 selects the default.
func NewPolicyCache(logger *slog.Logger, maxAge time.Duration) *PolicyCache {
	if logger == nil {
		logger = slog.Default()
	}
	if maxAge <= 0 {
		maxAge = DefaultPolicyCacheMaxAge
	}
	return &PolicyCache{logger: logger, maxAge: maxAge, now: time.Now}
}

// path mirrors the runtime snapshot's: $AIKEY_RUN_DIR for tests, else
// ~/.aikey/run/.
func (c *PolicyCache) path() (string, error) {
	if dir := os.Getenv("AIKEY_RUN_DIR"); dir != "" {
		return filepath.Join(dir, policyCacheFilename), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aikey", "run", policyCacheFilename), nil
}

// Load restores the last known policy, or nil when there is nothing usable.
//
// 🔴 Every failure path returns nil and logs at INFO — never ERROR, and never a
// startup failure. A missing cache is the normal first-boot state; a corrupt one
// is fixed by the next poll 60 seconds later. Refusing to start over a
// disposable file would convert a non-event into an outage.
func (c *PolicyCache) Load(orgID string) *Policy {
	path, err := c.path()
	if err != nil {
		c.logger.Info("MCP policy cache: cannot resolve the run directory; starting with no cached policy",
			"error", err)
		return nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is derived from the run dir, not from input
	if err != nil {
		if !os.IsNotExist(err) {
			c.logger.Info("MCP policy cache: unreadable; starting with no cached policy until the first poll",
				"path", path, "error", err)
		}
		return nil
	}
	var body cachedPolicy
	if err := json.Unmarshal(raw, &body); err != nil {
		c.logger.Info("MCP policy cache: unparseable; starting with no cached policy until the first poll",
			"path", path, "error", err)
		return nil
	}
	if body.Policy == nil {
		return nil
	}
	if body.OrgID != orgID {
		// 🔴 Not an error — a machine legitimately moves between organisations
		// (a contractor's laptop, a re-provisioned node). Serving the previous
		// org's grants would be the actual defect.
		c.logger.Info("MCP policy cache: belongs to a different organization; ignoring it",
			"cached_org", body.OrgID, "current_org", orgID)
		return nil
	}
	if age := c.now().Sub(time.UnixMilli(body.WrittenAtMs)); age > c.maxAge {
		c.logger.Info("MCP policy cache: too old to trust; waiting for a live policy instead",
			"age_hours", int(age.Hours()), "max_age_hours", int(c.maxAge.Hours()))
		return nil
	}
	return body.Policy
}

// Save writes the policy atomically (temp + rename).
//
// 🔴 Best-effort by construction. The caller has already applied the policy in
// memory, so a write failure costs only the restart shortcut — but it is
// WARN-logged, because a cache that silently never persists turns "the fleet
// recovers across a restart" into a promise nobody notices we stopped keeping.
func (c *PolicyCache) Save(p *Policy) {
	if p == nil {
		return
	}
	path, err := c.path()
	if err == nil {
		err = func() error {
			if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
				return mkErr
			}
			data, mErr := json.Marshal(cachedPolicy{
				OrgID:       p.OrgID,
				WrittenAtMs: c.now().UnixMilli(),
				Policy:      p,
			})
			if mErr != nil {
				return mErr
			}
			tmp := path + ".tmp"
			// 0600: the policy names backends, tool descriptions and grant
			// subjects. No secrets — but no reason for another local account to
			// read the organisation's tool inventory either.
			if wErr := os.WriteFile(tmp, data, 0o600); wErr != nil {
				return wErr
			}
			return os.Rename(tmp, path)
		}()
	}
	if err != nil {
		c.logger.Warn("MCP policy cache: write failed — the policy is applied in memory, "+
			"but this node will start with no tools if it restarts before the control plane is reachable",
			"error", err)
	}
}
