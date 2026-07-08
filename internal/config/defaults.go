package config

import "time"

const (
	DefaultHost                = "127.0.0.1"
	DefaultPort                = 27200
	DefaultVaultPath           = "~/.aikey/data/vault.db"
	DefaultEventsDBPath        = "~/.aikey/data/events.db"
	DefaultProviderTimeout     = 120 * time.Second
	DefaultEventsBatchSize     = 100
	DefaultEventsFlushInterval = 5 * time.Second
	// Local usage-data retention defaults — 30d live + 90d archive per the
	// 费用小票 §11 design ("30 天自动清理,超出归档 / 90 天再删").
	DefaultWALRetentionDays  = 30
	DefaultWALArchiveDays    = 90
	DefaultLogLevel          = "info"
	DefaultLogDir            = "~/.aikey/logs/aikey-proxy"
	DefaultSlowRequestMs     = 2000
	DefaultVerySlowRequestMs = 10000
	// DefaultPortDriftMax bounds runtime port drift when the configured
	// listen port is occupied. See 20260430-端口偏移能力修复.md.
	DefaultPortDriftMax = 10
	// DefaultConsoleURL applies when console_url is ABSENT from yaml (pre-
	// 20260703 personal/trial configs preserved across upgrades). 8090 is the
	// local-server user-console port on every default personal/trial install
	// (allocator "trial" key at offset 0). Explicit "" opts out — see
	// Config.ConsoleURL. Known edge: a drifted console port with a preserved
	// old config yields a 404-ing default URL; the message still names the
	// /user/team-oauth page so the member can find it manually.
	DefaultConsoleURL = "http://127.0.0.1:8090"
)
