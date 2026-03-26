package config

import (
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
	Protocol string        `yaml:"protocol"` // "openai" or "anthropic"
	Timeout  time.Duration `yaml:"timeout"`
}

type EventsConfig struct {
	DBPath        string        `yaml:"db_path"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
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
		case "openai", "anthropic", "kimi", "generic":
		default:
			return fmt.Errorf("providers[%s].protocol must be 'openai' or 'anthropic', got %q", name, p.Protocol)
		}
	}

	return nil
}

func (c *Config) expandPaths() {
	c.Vault.Path = expandHome(c.Vault.Path)
	c.Events.DBPath = expandHome(c.Events.DBPath)
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
