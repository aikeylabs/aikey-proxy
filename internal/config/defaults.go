package config

import "time"

const (
	DefaultHost          = "127.0.0.1"
	DefaultPort          = 27200
	DefaultVaultPath     = "~/.aikey/data/vault.db"
	DefaultEventsDBPath  = "~/.aikey/data/events.db"
	DefaultProviderTimeout = 120 * time.Second
	DefaultEventsBatchSize = 100
	DefaultEventsFlushInterval = 5 * time.Second
	DefaultLogLevel      = "info"
	DefaultLogDir        = "~/.aikey/logs/aikey-proxy"
	DefaultSlowRequestMs      = 2000
	DefaultVerySlowRequestMs  = 10000
	// DefaultPortDriftMax bounds runtime port drift when the configured
	// listen port is occupied. See 20260430-端口偏移能力修复.md.
	DefaultPortDriftMax = 10
)
