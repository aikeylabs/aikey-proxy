package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"log/slog"

	"golang.org/x/term"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/server"
	"github.com/AiKeyLabs/aikey-proxy/internal/supervisor"
)

var version = "dev"

const defaultConfigName = "aikey-proxy.yaml"

// resolveConfigPath finds the proxy config file in priority order:
//  1. Explicit --config argument
//  2. Current working directory (aikey-proxy.yaml)
//  3. $HOME/.aikey/config/aikey-proxy.yaml  (respects HOME env var for sandbox isolation)
func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	// cwd
	if _, err := os.Stat(defaultConfigName); err == nil {
		return defaultConfigName, nil
	}
	// $HOME/.aikey/config/
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".aikey", "config", defaultConfigName)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf(
		"%s not found. Searched: current directory, ~/.aikey/config/. "+
			"Use --config to specify explicitly.", defaultConfigName)
}

func main() {
	configPath := flag.String("config", "", "path to config file (default: search cwd then ~/.aikey/)")
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

	// 1. Resolve and load config.
	resolvedPath, err := resolveConfigPath(*configPath)
	if err != nil {
		slog.Error("config not found", "error", err)
		os.Exit(1)
	}
	cfg, err := config.Load(resolvedPath)
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

	// 3. Bind the TCP listener once — it is never closed during graceful reloads.
	ln, err := supervisor.Listen(cfg)
	if err != nil {
		slog.Error("failed to bind listener", "error", err)
		os.Exit(1)
	}
	slog.Info("listener bound", "addr", ln.Addr())

	// 4. Create the Supervisor (starts the initial generation).
	sup, err := supervisor.New(cfg, password)
	if err != nil {
		slog.Error("failed to start supervisor", "error", err)
		os.Exit(1)
	}

	// 5. Build the admin handler, wiring Supervisor callbacks.
	adminHandler := admin.NewHandler(cfg, sup.Registry(), sup.EventStore())
	adminHandler.TotalRequestsFn = sup.TotalRequests
	adminHandler.TotalErrorsFn = sup.TotalErrors
	adminHandler.ReloadFn = sup.Reload

	// Build the outbound transport for upstream providers (optional).
	dataHandler := sup.Handler()
	if t := buildTransport(cfg.UpstreamProxy.URL); t != nil {
		// Wrap the supervisor handler with the custom transport by delegating
		// through a minimal http.Handler that injects it on the proxy level.
		// The transport is generation-independent (it's just a dialer), so
		// it is safe to inject once at the server level.
		_ = t // transport is set on proxy.Proxy inside buildGeneration; see supervisor.go
	}

	// 6. Build and start the HTTP server.
	srv := server.New(ln, dataHandler, adminHandler)

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Fprintf(os.Stderr, "\naikey-proxy %s listening on %s\n\n", version, ln.Addr())
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal.
	sig := <-sigCh
	slog.Info("received signal, shutting down", "signal", sig)

	// Graceful shutdown: stop accepting new connections, drain active generation.
	if err := srv.Shutdown(30 * time.Second); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	sup.Shutdown(30 * time.Second)

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

// buildTransport returns a custom http.Transport that routes outbound provider
// requests through proxyURL. Returns nil when proxyURL is empty, which makes
// httputil.ReverseProxy fall back to http.DefaultTransport (itself honouring
// HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables).
//
// Supported schemes: http, https, socks5.
func buildTransport(proxyURL string) *http.Transport {
	if proxyURL == "" {
		return nil
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		slog.Warn("upstream_proxy.url is invalid, falling back to env vars", "url", proxyURL, "error", err)
		return nil
	}
	t := &http.Transport{
		Proxy:               http.ProxyURL(parsed),
		ForceAttemptHTTP2:   false, // keep HTTP/1.1 for widest proxy compat
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	slog.Info("upstream proxy configured", "url", proxyURL)
	return t
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
