package config

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-config-tool/pkg/configmerge"
	"gopkg.in/yaml.v3"
)

// Config is the top-level aikey-proxy configuration.
//
// Stage C-2.c removed the VirtualKeys / VirtualKeyConfig field. Static
// virtual_keys[] in yaml was the legacy "personal_byok" RouteSource —
// fully superseded by vault-backed routes (managed_virtual_keys_cache,
// personal_route_token, oauth_route_token). Removal record:
// workflow/CD/templates/removed-registry.yaml entry "virtual_keys".
type Config struct {
	Providers map[string]ProviderConfig `yaml:"providers"`
	// Observers is the Phase 4 M2 first-party observer config block.
	// Keyed by observer.Name (e.g. "rhythm"); each value is a free-form
	// map that the observer package's Build callback decodes into its
	// own concrete settings struct (reporter URL, batch size, etc.).
	//
	// Absent block ⇒ no observers built (the default for non-degrade-
	// detector deployments — Notify* hooks become zero-cost no-ops via
	// the Active()==0 fast path).
	//
	// The proxy main code never inspects this block's contents — it
	// just forwards `Observers[obsName]` to BuildObservers, which hands
	// it to the per-observer Build callback. Adding a new observer
	// doesn't require any change here.
	Observers     map[string]map[string]any `yaml:"observers,omitempty"`
	Vault         VaultConfig               `yaml:"vault"`
	UpstreamProxy UpstreamProxyConfig       `yaml:"upstream_proxy"`
	// Cluster is the V3c cluster-node config block. Absent / Enabled=false ⇒
	// standard local proxy (Personal/Trial) — zero behavior change. When
	// Enabled, this proxy is a cluster node: it registers + heartbeats to the
	// aikey-hub name service and (policy) only serves team/managed virtual keys.
	Cluster ClusterConfig `yaml:"cluster,omitempty"`
	Log     LogConfig     `yaml:"log"`
	Listen  ListenConfig  `yaml:"listen"`
	Events  EventsConfig  `yaml:"events"`
}

// ClusterConfig configures cluster-node behavior (V3c). All fields are inert
// unless Enabled is true, so existing single-node configs are unaffected.
type ClusterConfig struct {
	// HubURL is the aikey-hub name-service base, e.g. http://hub:27400.
	HubURL string `yaml:"hub_url,omitempty"`
	// NodeID uniquely identifies this proxy node in the cluster.
	NodeID string `yaml:"node_id,omitempty"`
	// NodeAddr is the address clients connect to for this node (host:port),
	// returned by the hub's /cluster/resolve.
	NodeAddr string `yaml:"node_addr,omitempty"`
	// ServiceToken authenticates this node to the hub's gated /cluster/* endpoints
	// (R1). Config-separate per edition: empty for non-cluster, set for cluster.
	ServiceToken string `yaml:"service_token,omitempty"`
	// Weight scales this node's share of the consistent-hash ring (≥1).
	Weight  int  `yaml:"weight,omitempty"`
	Enabled bool `yaml:"enabled"`
}

type ListenConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// PortDriftMax bounds runtime port drift when Port is occupied at start.
	// Per 20260430-端口偏移能力修复.md: when an external process holds Port,
	// the listener retries Port+1, Port+2, ... up to Port+PortDriftMax before
	// failing. Default is DefaultPortDriftMax (10) when unset / 0. Set
	// negative to disable drift (strict legacy behavior — fail on first
	// EADDRINUSE; used by some E2E tests).
	PortDriftMax int `yaml:"port_drift_max,omitempty"`
}

func (l ListenConfig) Addr() string {
	return fmt.Sprintf("%s:%d", l.Host, l.Port)
}

type VaultConfig struct {
	Path string `yaml:"path"`
}

type ProviderConfig struct {
	// Protocol selects the provider adapter.
	// Accepted values: "openai", "openai_compatible" (alias for "openai"), "anthropic".
	Protocol string        `yaml:"protocol"`
	Timeout  time.Duration `yaml:"timeout"`
}

// CollectorCredential is the per-RouteSource credential bundle written
// by `aikey account login` into aikey-user.yaml's `proxy:` section and
// merged onto EventsConfig at startup. The proxy's supervisor turns
// this into an `events.Credential` (e.g. RefreshableJWT) before passing
// it to the reporter.
//
// `Type == "jwt"` is the only supported value today. Token is the
// current short-lived access_token; ExpiresAt is its unix expiry
// (0 = unknown → refresh on first use); RefreshURL is the absolute
// URL the proxy's auto-refresh loop POSTs to. refresh_token does NOT
// live here — it stays encrypted in the vault.
//
// Added 2026-05-11 (B4 phase). See roadmap update
// 20260511-user-jwt-collector-ingest.md.
type CollectorCredential struct {
	Type       string `yaml:"type"`
	Token      string `yaml:"token"`
	RefreshURL string `yaml:"refresh_url"`
	ExpiresAt  int64  `yaml:"expires_at"`
}

type EventsConfig struct {
	// CollectorRoutes maps RouteSource ("personal" / "team" / "oauth") →
	// upload URL. When the lookup hits, this URL takes precedence over
	// CollectorURL for that event. Misses fall through to CollectorURL.
	// Empty value for a route disables upload for that route source
	// (events are still WAL'd locally).
	//
	// Why this exists: separates per-key-type upload destinations so
	// personal-key usage events stay on the local collector while team-key
	// events go to the remote team server. Set by `aikey login --control-url`
	// for the "team" key; never touches "personal" / "oauth" defaults.
	// See roadmap20260320/技术实现/update/20260510-personal-team-数据隔离与合并显示.md.
	CollectorRoutes map[string]string `yaml:"collector_routes"`
	// CollectorCredentials maps RouteSource → credential bundle. Written
	// by aikey-cli's `aikey account login --control-url <REMOTE>` (B3
	// phase) into the **user** layer of the config split — proxy's Load
	// reads them via configmerge.LoadAndMerge under the `proxy:` section,
	// so they survive `make restart-personal` re-renders just like
	// CollectorRoutes.team does.
	//
	// Today only "team" is populated and only `type: jwt` is supported;
	// `refresh_token` is intentionally NOT in yaml (it lives encrypted
	// in the vault's platform_account table — proxy reads it via the
	// supervisor's already-derived master key).
	//
	// See roadmap20260320/技术实现/update/20260511-user-jwt-collector-ingest.md.
	CollectorCredentials map[string]CollectorCredential `yaml:"collector_credentials"`
	WALDir               string                         `yaml:"wal_dir"` // JSONL WAL directory
	// QueryURL, when set, enables the query-stage canary probe. Canary hits
	// GET {QueryURL}/internal/canary-check to verify query-service can read
	// the projector-acked ODS row. Leave empty in trial (single-port, shared
	// DB — the collector-side DWD ack is already the signal). Set in
	// production to the query-service base URL for full end-to-end coverage.
	QueryURL     string `yaml:"query_url"`
	ServiceToken string `yaml:"service_token"`
	// Usage reporting to collector-service
	CollectorURL   string `yaml:"collector_url"`   // e.g. "http://localhost:27300"
	CollectorToken string `yaml:"collector_token"` // Bearer token for auth
	// Control service URL — historically used for diagnostics/canary-check
	// queries. As of 2026-04-17 diagnostics live on collector-service, so
	// CanaryProbe prefers CollectorURL and only falls back here when it is
	// empty (older trial configs). Kept for backward compatibility.
	ControlURL      string        `yaml:"control_url"`
	DBPath          string        `yaml:"db_path"`
	UploadBatchSize int           `yaml:"upload_batch_size"` // events per upload (default 100)
	UploadInterval  time.Duration `yaml:"upload_interval"`   // max time between uploads (default 5s)
	// Local usage-data retention (费用小票 §11/§12 design; implemented
	// 2026-06-10). WAL files older than wal_retention_days move into the
	// usage-wal-archive/ subdir; archived files older than wal_archive_days
	// are deleted; usage_events rows older than wal_retention_days are
	// pruned. 0 (unset) → defaults 30/90 per the design; negative disables
	// the retention loop entirely (keep everything forever, pre-2026-06
	// behavior).
	WALRetentionDays int           `yaml:"wal_retention_days"`
	WALArchiveDays   int           `yaml:"wal_archive_days"`
	QueueCapacity    int           `yaml:"queue_capacity"` // bounded queue size (default 10000)
	FlushInterval    time.Duration `yaml:"flush_interval"`
	BatchSize        int           `yaml:"batch_size"`
}

type LogConfig struct {
	Level string `yaml:"level"`
	// Dir is the directory for runtime JSONL log files.
	// Defaults to ~/.aikey/logs/aikey-proxy/
	Dir string `yaml:"dir"`
	// SlowRequestMs is the threshold in milliseconds above which a request is
	// logged as a slow request (proxy.request.slow). Default: 2000 ms.
	SlowRequestMs int `yaml:"slow_request_ms"`
	// VerySlowRequestMs is the threshold above which a WARN-level slow-request
	// log is emitted with higher urgency. Default: 10000 ms.
	VerySlowRequestMs int `yaml:"very_slow_request_ms"`
}

// UpstreamProxyConfig configures the outbound proxy used when connecting to AI providers.
// Supports HTTP, HTTPS, and SOCKS5 proxy URLs.
// If empty, the standard HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables are used.
type UpstreamProxyConfig struct {
	// URL is the proxy endpoint, e.g.:
	//   http://127.0.0.1:7890   (Clash HTTP mode)
	//   socks5://127.0.0.1:7891 (Clash SOCKS5 / proxychains)
	URL string `yaml:"url"`
}

// Load reads and parses a YAML config file, applying defaults.
//
// Stage 2026-05-11 (F1 fix for collector_routes.team overwrite):
// also merges `aikey-user.yaml` in the same directory as `path` when present,
// using the `proxy:` section. User-layer values win on field collision per
// configmerge.deepMerge semantics. This makes `aikey login --control-url
// <REMOTE>`'s team-route override survive `make restart-personal` (which
// rm's and re-renders the system yaml from template). Mirrors the
// trial-server Load path (aikey-trial-server/config/config.go:97-110) so
// both services follow the same merge protocol.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	mergedYAML, err := loadAndMaybeMerge(path)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(mergedYAML, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	cfg.applyEnvOverrides()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	cfg.expandPaths()

	return cfg, nil
}

// loadAndMaybeMerge returns the raw yaml bytes that `yaml.Unmarshal` should
// see. When `aikey-user.yaml` exists in the same directory as the system
// path, its `proxy:` subtree is deep-merged on top before re-marshaling.
//
// Why marshal-after-merge: configmerge.LoadAndMerge returns a
// map[string]any (yaml.v3 keeps that path simple). We re-marshal so the
// downstream `yaml.Unmarshal(data, *Config)` path is unchanged — same
// shape, same yaml tags, same struct-validation. Trial-server uses the
// identical pattern; matching it keeps the two loaders behavior-aligned.
//
// Missing user file is the personal-no-team-server case: return the
// system bytes as-is and let the user-layer override stay absent.
func loadAndMaybeMerge(path string) ([]byte, error) {
	systemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	userPath := filepath.Join(filepath.Dir(path), "aikey-user.yaml")
	if _, statErr := os.Stat(userPath); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return systemBytes, nil
		}
		return nil, fmt.Errorf("stat user config: %w", statErr)
	}

	merged, err := configmerge.LoadAndMerge(path, userPath, "proxy")
	if err != nil {
		return nil, fmt.Errorf("merge system+user proxy config: %w", err)
	}
	out, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("re-marshal merged proxy config: %w", err)
	}
	return out, nil
}

// applyEnvOverrides honors selected env vars after yaml + defaults
// have been applied. Currently only AIKEY_PROXY_LOG_LEVEL is supported
// (Stage C-3 scheme §9 step 10) — log level is归 system per scheme v8
// SR8, but ad-hoc debug needs a way to bump verbosity without editing
// the yaml + restart cycle.
func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("AIKEY_PROXY_LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
}

func (c *Config) applyDefaults() {
	if c.Listen.Host == "" {
		c.Listen.Host = DefaultHost
	}
	if c.Listen.Port == 0 {
		c.Listen.Port = DefaultPort
	}
	// 0 (unset / explicit 0) → default 10. Negative is honored as "strict no
	// drift" per ListenConfig.PortDriftMax doc. Non-zero positive is honored.
	if c.Listen.PortDriftMax == 0 {
		c.Listen.PortDriftMax = DefaultPortDriftMax
	}
	if c.Vault.Path == "" {
		c.Vault.Path = DefaultVaultPath
	}
	if c.Events.DBPath == "" {
		c.Events.DBPath = DefaultEventsDBPath
	}
	if c.Events.BatchSize == 0 {
		c.Events.BatchSize = DefaultEventsBatchSize
	}
	if c.Events.FlushInterval == 0 {
		c.Events.FlushInterval = DefaultEventsFlushInterval
	}
	// 0 (unset) → design defaults; negative honored as "retention disabled"
	// (same unset-vs-explicit convention as Listen.PortDriftMax above).
	if c.Events.WALRetentionDays == 0 {
		c.Events.WALRetentionDays = DefaultWALRetentionDays
	}
	if c.Events.WALArchiveDays == 0 {
		c.Events.WALArchiveDays = DefaultWALArchiveDays
	}
	if c.Log.Level == "" {
		c.Log.Level = DefaultLogLevel
	}
	if c.Log.Dir == "" {
		c.Log.Dir = DefaultLogDir
	}
	if c.Log.SlowRequestMs == 0 {
		c.Log.SlowRequestMs = DefaultSlowRequestMs
	}
	if c.Log.VerySlowRequestMs == 0 {
		c.Log.VerySlowRequestMs = DefaultVerySlowRequestMs
	}
	for name, p := range c.Providers {
		if p.Timeout == 0 {
			p.Timeout = DefaultProviderTimeout
			c.Providers[name] = p
		}
	}
}

func (c *Config) validate() error {
	// Loopback-only is a Personal/Trial safety rail (the local proxy must not be
	// network-reachable). A CLUSTER node, by design, IS network-reachable (clients
	// + nginx connect to it) and is protected by VK-token auth + the internal
	// network / mTLS instead — so cluster mode lifts this restriction.
	if !c.Cluster.Enabled &&
		c.Listen.Host != "127.0.0.1" && c.Listen.Host != "localhost" && c.Listen.Host != "::1" {
		return fmt.Errorf("listen.host must be a loopback address (127.0.0.1, localhost, ::1) outside cluster mode, got %q", c.Listen.Host)
	}
	if c.Listen.Port < 1 || c.Listen.Port > 65535 {
		return fmt.Errorf("listen.port must be 1-65535, got %d", c.Listen.Port)
	}

	// virtual_keys[] validation removed in Stage C-2.c. All routes now
	// flow through vault (managed_virtual_keys_cache / personal_route_token /
	// oauth_route_token); see workflow/CD/templates/removed-registry.yaml.

	for name, p := range c.Providers {
		switch p.Protocol {
		case "openai", "openai_compatible", "anthropic", "kimi", "generic":
		default:
			return fmt.Errorf("providers[%s].protocol must be 'openai', 'openai_compatible', or 'anthropic', got %q", name, p.Protocol)
		}
	}

	// Cluster fields are required only when cluster mode is on (inert otherwise,
	// so single-node configs never trip this).
	if c.Cluster.Enabled {
		if c.Cluster.HubURL == "" || c.Cluster.NodeID == "" || c.Cluster.NodeAddr == "" {
			return fmt.Errorf("cluster.enabled requires cluster.hub_url, cluster.node_id, and cluster.node_addr")
		}
	}

	return nil
}

func (c *Config) expandPaths() {
	c.Vault.Path = expandHome(c.Vault.Path)
	c.Events.DBPath = expandHome(c.Events.DBPath)
	// Why: WAL is the v5 canonical event log consumed by `aikey statusline`
	// and `aikey watch`. Historically the template had `wal_dir` commented
	// out, so upgrades from those versions carry an empty WALDir forward
	// and silently lose local usage tracking. Default to the well-known
	// CLI read path (usage_wal::default_wal_dir) so the UI never goes dark
	// because of config rot. Operators who want WAL off must set it to
	// "/dev/null" explicitly — empty means "use the conventional default".
	if c.Events.WALDir == "" {
		c.Events.WALDir = defaultUsageWALDir()
	}
	c.Events.WALDir = expandHome(c.Events.WALDir)
	c.Log.Dir = expandHome(c.Log.Dir)
}

// defaultUsageWALDir returns `~/.aikey/data/usage-wal` expanded, matching the
// CLI reader in aikey-cli/src/usage_wal.rs::default_wal_dir. Both must agree
// or the statusline/watch readers won't find the events the proxy writes.
func defaultUsageWALDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to the un-expanded form; expandHome won't handle it but
		// the reporter's NewWALWriter will at least surface a clear error
		// rather than silently no-op.
		return "~/.aikey/data/usage-wal"
	}
	return filepath.Join(home, ".aikey", "data", "usage-wal")
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

// PipelineConfigHash returns a short hash of the key pipeline configuration fields.
// Used in /status for config drift detection and in ReportableEvent.ProxyConfigVersion.
func (c *Config) PipelineConfigHash() string {
	h := sha256.New()
	h.Write([]byte(c.Events.CollectorURL))
	h.Write([]byte(c.Events.CollectorToken))
	h.Write([]byte(c.Events.WALDir))
	h.Write([]byte(c.Events.DBPath))
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// ConfigSource detects how the config file was generated by scanning for
// marker comments. Returns "config-tool", "installer", or "manual".
func ConfigSource(configPath string) string {
	f, err := os.Open(configPath)
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Only scan first 20 lines for marker comments (they appear at the top).
	for i := 0; i < 20 && scanner.Scan(); i++ {
		line := scanner.Text()
		if strings.Contains(line, "generated by aikey-config-tool") {
			return "config-tool"
		}
		if strings.Contains(line, "patched by installer") {
			return "installer"
		}
	}
	return "manual"
}
