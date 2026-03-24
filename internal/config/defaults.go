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
)
