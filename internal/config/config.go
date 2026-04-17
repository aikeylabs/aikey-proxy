package config

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level aikey-proxy configuration.
type Config struct {
	Listen        ListenConfig              `yaml:"listen"`
	Vault         VaultConfig               `yaml:"vault"`
	VirtualKeys   []VirtualKeyConfig        `yaml:"virtual_keys"`
	Providers     map[string]ProviderConfig `yaml:"providers"`
	Events        EventsConfig              `yaml:"events"`
	Log           LogConfig                 `yaml:"log"`
	UpstreamProxy UpstreamProxyConfig       `yaml:"upstream_proxy"`
}

type ListenConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

func (l ListenConfig) Addr() string {
	return fmt.Sprintf("%s:%d", l.Host, l.Port)
}

type VaultConfig struct {
	Path string `yaml:"path"`
}

type VirtualKeyConfig struct {
	ID            string   `yaml:"id"`
	Token         string   `yaml:"token"`
	Provider      string   `yaml:"provider"`
	BaseURL       string   `yaml:"base_url"`
	KeyAlias      string   `yaml:"key_alias"`
	AllowedModels []string `yaml:"allowed_models"`
}

type ProviderConfig struct {
	// Protocol selects the provider adapter.
	// Accepted values: "openai", "openai_compatible" (alias for "openai"), "anthropic".
	Protocol string        `yaml:"protocol"`
	Timeout  time.Duration `yaml:"timeout"`
}

type EventsConfig struct {
	DBPath        string        `yaml:"db_path"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`

	// Usage reporting to collector-service
	CollectorURL   string        `yaml:"collector_url"`    // e.g. "http://localhost:27300"
	CollectorToken string        `yaml:"collector_token"`  // Bearer token for auth
	QueueCapacity  int           `yaml:"queue_capacity"`   // bounded queue size (default 10000)
	UploadBatchSize int          `yaml:"upload_batch_size"` // events per upload (default 100)
	UploadInterval time.Duration `yaml:"upload_interval"`  // max time between uploads (default 5s)
	WALDir         string        `yaml:"wal_dir"`          // JSONL WAL directory

	// Control service URL — historically used for diagnostics/canary-check
	// queries. As of 2026-04-17 diagnostics live on collector-service, so
	// CanaryProbe prefers CollectorURL and only falls back here when it is
	// empty (older trial configs). Kept for backward compatibility.
	ControlURL   string `yaml:"control_url"`
	ServiceToken string `yaml:"service_token"`

	// QueryURL, when set, enables the query-stage canary probe. Canary hits
	// GET {QueryURL}/internal/canary-check to verify query-service can read
	// the projector-acked ODS row. Leave empty in trial (single-port, shared
	// DB — the collector-side DWD ack is already the signal). Set in
	// production to the query-service base URL for full end-to-end coverage.
	QueryURL string `yaml:"query_url"`
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
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	cfg.expandPaths()

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen.Host == "" {
		c.Listen.Host = DefaultHost
	}
	if c.Listen.Port == 0 {
		c.Listen.Port = DefaultPort
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
	if c.Listen.Host != "127.0.0.1" && c.Listen.Host != "localhost" && c.Listen.Host != "::1" {
		return fmt.Errorf("listen.host must be a loopback address (127.0.0.1, localhost, ::1), got %q", c.Listen.Host)
	}
	if c.Listen.Port < 1 || c.Listen.Port > 65535 {
		return fmt.Errorf("listen.port must be 1-65535, got %d", c.Listen.Port)
	}

	tokens := make(map[string]bool)
	for i, vk := range c.VirtualKeys {
		if vk.Token == "" {
			return fmt.Errorf("virtual_keys[%d].token is required", i)
		}
		if vk.Provider == "" {
			return fmt.Errorf("virtual_keys[%d].provider is required", i)
		}
		if vk.BaseURL == "" {
			return fmt.Errorf("virtual_keys[%d].base_url is required", i)
		}
		if vk.KeyAlias == "" {
			return fmt.Errorf("virtual_keys[%d].key_alias is required", i)
		}
		if tokens[vk.Token] {
			return fmt.Errorf("virtual_keys[%d].token is duplicate", i)
		}
		tokens[vk.Token] = true
	}

	for name, p := range c.Providers {
		switch p.Protocol {
		case "openai", "openai_compatible", "anthropic", "kimi", "generic":
		default:
			return fmt.Errorf("providers[%s].protocol must be 'openai', 'openai_compatible', or 'anthropic', got %q", name, p.Protocol)
		}
	}

	return nil
}

func (c *Config) expandPaths() {
	c.Vault.Path = expandHome(c.Vault.Path)
	c.Events.DBPath = expandHome(c.Events.DBPath)
	c.Events.WALDir = expandHome(c.Events.WALDir)
	c.Log.Dir = expandHome(c.Log.Dir)
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
