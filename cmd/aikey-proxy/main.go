package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/server"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "aikey-proxy.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("aikey-proxy", version)
		os.Exit(0)
	}

	// Setup structured logging.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// 1. Load config.
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Set log level from config.
	setupLogging(cfg.Log.Level)

	slog.Info("config loaded",
		"listen", cfg.Listen.Addr(),
		"vault", cfg.Vault.Path,
		"virtual_keys", len(cfg.VirtualKeys),
	)

	// 2. Get vault password.
	password, err := getVaultPassword()
	if err != nil {
		slog.Error("failed to get vault password", "error", err)
		os.Exit(1)
	}

	// 3. Open vault.
	vaultReader, err := vault.Open(cfg.Vault.Path, password)
	if err != nil {
		slog.Error("failed to open vault", "error", err)
		os.Exit(1)
	}
	defer vaultReader.Close()

	// 4. Build virtual key registry, skipping keys whose vault secret is missing.
	var activeKeys []config.VirtualKeyConfig
	for _, vk := range cfg.VirtualKeys {
		if _, err := vaultReader.GetSecret(vk.KeyAlias); err != nil {
			slog.Warn("virtual key skipped: secret not found in vault — add it with 'aikey secret set'",
				"vk_id", vk.ID, "key_alias", vk.KeyAlias)
			continue
		}
		activeKeys = append(activeKeys, vk)
	}
	slog.Info("virtual keys ready", "active", len(activeKeys), "total", len(cfg.VirtualKeys))

	registry := vkeys.NewRegistry()
	registry.Load(activeKeys)

	// 5. Initialize provider registry.
	providers := provider.NewRegistry()

	// 6. Initialize event store and collector.
	eventStore, err := events.OpenStore(cfg.Events.DBPath)
	if err != nil {
		slog.Error("failed to open events store", "error", err)
		os.Exit(1)
	}
	defer eventStore.Close()

	collector := events.NewCollector(eventStore, cfg.Events.BatchSize, cfg.Events.FlushInterval)
	defer collector.Close()

	// 7. Build proxy.
	p := proxy.New(vaultReader, registry, providers, collector)

	// 8. Build admin handler.
	adminHandler := admin.NewHandler(cfg, registry, eventStore)
	adminHandler.TotalRequestsFn = p.TotalRequests
	adminHandler.TotalErrorsFn = p.TotalErrors

	// 9. Start server.
	srv := server.New(cfg.Listen.Addr(), p, adminHandler)

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	fmt.Fprintf(os.Stderr, "\naikey-proxy %s listening on %s\n\n", version, cfg.Listen.Addr())

	// Wait for shutdown signal.
	sig := <-sigCh
	slog.Info("received signal, shutting down", "signal", sig)

	// Graceful shutdown with 30s timeout.
	if err := srv.Shutdown(30 * time.Second); err != nil {
		slog.Error("shutdown error", "error", err)
	}

	slog.Info("aikey-proxy stopped")
}

// getVaultPassword reads the vault password from AIKEY_VAULT_PASSWORD env var
// or prompts on stdin.
func getVaultPassword() (string, error) {
	if pw := os.Getenv("AIKEY_VAULT_PASSWORD"); pw != "" {
		return pw, nil
	}

	fmt.Fprint(os.Stderr, "Enter vault password: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr) // newline after password input
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	return string(pw), nil
}

func setupLogging(level string) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))
}
