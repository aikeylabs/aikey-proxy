package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	proxyruntime "github.com/AiKeyLabs/aikey-proxy/internal/runtime"
	"github.com/AiKeyLabs/aikey-proxy/internal/server"
	"github.com/AiKeyLabs/aikey-proxy/internal/supervisor"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
	"github.com/AiKeyLabs/pkg/aikeycompat"
	"github.com/AiKeyLabs/pkg/buildinfo"
)

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
	// Handle "version" subcommand before flag parsing (flags expect --config etc.)
	if len(os.Args) > 1 && os.Args[1] == "version" {
		bi := buildinfo.Get()
		if len(os.Args) > 2 && (os.Args[2] == "--json" || os.Args[2] == "-j") {
			fmt.Println(string(bi.JSON()))
		} else {
			fmt.Println("aikey-proxy", bi.String())
		}
		os.Exit(0)
	}

	configPath := flag.String("config", "", "path to config file (default: search cwd then ~/.aikey/)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("aikey-proxy", buildinfo.Get().String())
		os.Exit(0)
	}

	// Minimal stderr-only logger until config is loaded and log dir is known.
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

	// 2. Initialise structured logging: stderr text + async JSONL file.
	logLevel := parseLogLevel(cfg.Log.Level)
	logWriter, err := observability.SetupLogger(cfg.Log.Dir, "aikey-proxy", buildinfo.Get().String(), logLevel)
	if err != nil {
		// Non-fatal: fall back to text-only stderr logging.
		slog.Warn("failed to initialise JSONL log writer, falling back to stderr only", "error", err)
		setupTextLogging(logLevel)
	}

	// Wire GoSafe / HTTP recover to the same log directory so panic dumps
	// live alongside current.jsonl, and register a flush hook so Fatal-mode
	// goroutine panics drain the async writer before exit(2).
	observability.SetCrashDumpDir(cfg.Log.Dir)
	if logWriter != nil {
		observability.SetFatalFlushHook(func() {
			logWriter.Flush(2 * time.Second)
		})
	}

	// Stable, debug-only sentinel used by E2E cond18 (config-split
	// system+user §6 Phase 1 S2) to prove AIKEY_PROXY_LOG_LEVEL=debug
	// actually reached the handler. slog drops Debug-level events when
	// the handler is at Info, so the sentinel only appears under debug.
	// Operators can also tail it as a "is my debug actually on" check.
	slog.Debug("debug logging enabled")
	slog.Info("config loaded",
		"event.name", observability.EventProxyConfigLoaded,
		"listen", cfg.Listen.Addr(),
		"vault", cfg.Vault.Path,
	)

	// 3. Get master password.
	password, err := getVaultPassword()
	if err != nil {
		slog.Error("failed to get master password", "error", err)
		os.Exit(1)
	}

	// 4. Bind the TCP listener once — it is never closed during graceful reloads.
	// supervisor.Listen drifts to port+1..port+drift_max when the configured
	// port is occupied (per 20260430-端口偏移能力修复.md).
	ln, configuredAddr, actualAddr, driftOffset, err := supervisor.Listen(cfg)
	if err != nil {
		slog.Error("failed to bind listener", "error", err)
		os.Exit(1)
	}
	if driftOffset > 0 {
		slog.Warn("port drift: configured port occupied, fell back",
			"configured", configuredAddr,
			"actual", actualAddr,
			"drift_offset", driftOffset,
		)
	}
	slog.Info("listener bound",
		"event.name", observability.EventProxyListenerBound,
		"addr", actualAddr,
	)

	// 4b. Write the runtime snapshot so CLI / web can discover the actual
	// bound port. Per 20260428 ownership: the proxy process is the sole
	// writer of its runtime state; install-state.json is desired/configured
	// state and is owned by the installer. Snapshot is removed on graceful
	// exit (deferred below) — crashed-process residue is overwritten by the
	// next start.
	snapshot := proxyruntime.Snapshot{
		IncarnationID: proxyruntime.NewIncarnationID(),
		PID:           os.Getpid(),
		Listen: proxyruntime.Listen{
			ConfiguredAddr: configuredAddr,
			ActualAddr:     actualAddr,
			DriftOffset:    driftOffset,
		},
		StartedAt: time.Now().UTC(),
	}
	if err := proxyruntime.Write(snapshot); err != nil {
		slog.Warn("failed to write proxy-runtime.json (non-fatal)", "error", err)
	}
	defer func() {
		if err := proxyruntime.Remove(); err != nil {
			slog.Warn("failed to remove proxy-runtime.json on shutdown", "error", err)
		}
	}()

	// 5. Create the Supervisor (starts the initial generation).
	sup, err := supervisor.New(cfg, resolvedPath, password, buildinfo.Get().Version)
	if err != nil {
		slog.Error("failed to start supervisor", "error", err)
		os.Exit(1)
	}

	slog.Info("aikey-proxy started",
		"event.name", observability.EventProxyProcessStarted,
		"version", buildinfo.Get().String(),
		"listen", ln.Addr(),
	)

	// 5b. Build OAuth broker (embedded, uses vault stores).
	//     Reuse the supervisor's vault connection to avoid double-open conflicts.
	brokerVault := sup.VaultReader()
	var oauthHandler server.RouteRegistrar
	if brokerVault != nil {
		tokenStore := vault.NewTokenStore(brokerVault.DB(), brokerVault.DerivedKey())
		accountStore := vault.NewAccountStore(brokerVault.DB())

		// Inject ImpersonateChrome HTTP client for Claude token endpoint (Cloudflare bypass).
		broker.SetHTTPClient(vault.NewImpersonateChromeHTTPClient())

		brk := broker.NewEmbedded(tokenStore, accountStore)
		oauthHandler = broker.NewHandler(brk)
		// Wire broker into supervisor so all proxy generations can resolve OAuth credentials
		sup.SetBroker(&brokerAdapter{inner: brk, accounts: accountStore})
		slog.Info("OAuth broker initialized")
	} else {
		slog.Warn("OAuth broker disabled: vault not available")
	}

	// 6. Build the admin handler, wiring Supervisor callbacks.
	adminHandler := admin.NewHandler(cfg, sup.Registry(), sup.EventStore())
	adminHandler.TotalRequestsFn = sup.TotalRequests
	adminHandler.TotalErrorsFn = sup.TotalErrors
	adminHandler.ReloadFn = sup.Reload
	adminHandler.KeyChecksFn = sup.GetKeyCheckTargets
	adminHandler.ReporterMetricsFn = sup.ReporterMetrics
	adminHandler.CanaryResultFn = sup.CanaryResult

	// Build the outbound transport for upstream providers (optional).
	dataHandler := sup.Handler()
	if t := buildTransport(cfg.UpstreamProxy.URL); t != nil {
		sup.SetTransport(t)
	}

	// 7. Build and start the HTTP server.
	srv := server.New(ln, dataHandler, adminHandler, oauthHandler)

	// Handle graceful shutdown — see pkg/aikeycompat for the per-OS
	// signal set (Windows: SIGINT only; Unix: SIGINT + SIGTERM).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, aikeycompat.ShutdownSignals()...)

	// Fatal: server.Serve is the process's reason for being. If it dies the
	// proxy cannot serve requests, so exit(2) and let the OS supervisor
	// restart us rather than lingering as a zombie that accepts nothing.
	observability.GoSafe("main.server.serve", observability.Fatal, func() {
		fmt.Fprintf(os.Stderr, "\naikey-proxy %s listening on %s\n\n", buildinfo.Get().String(), ln.Addr())
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	})

	// Wait for shutdown signal.
	sig := <-sigCh
	slog.Info("received signal, shutting down", "signal", sig)

	// Graceful shutdown: stop accepting new connections, drain active generation.
	if err := srv.Shutdown(30 * time.Second); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	sup.Shutdown(30 * time.Second)

	slog.Info("aikey-proxy stopped",
		"event.name", observability.EventProxyProcessStopped,
	)

	// Flush the async log writer before exiting so no records are lost.
	if logWriter != nil {
		logWriter.Flush(3 * time.Second)
		_ = logWriter.Close()
	}
}

// getVaultPassword reads the master password from AIKEY_MASTER_PASSWORD env var
// or prompts on stdin.
func getVaultPassword() (string, error) {
	if pw := os.Getenv("AIKEY_MASTER_PASSWORD"); pw != "" {
		return pw, nil
	}

	fmt.Fprint(os.Stderr, "Enter Master Password: ")
	// Stage 1.7 windows-compat: `int(syscall.Stdin)` is fragile on
	// Windows (Stdin is a HANDLE, not an fd) — `os.Stdin.Fd()` returns
	// the right uintptr on every platform that golang.org/x/term knows
	// about and avoids a panic on the Windows MSVC runtime.
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
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

// parseLogLevel converts a config string to a slog.Level.
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// setupTextLogging configures the global logger to write text to stderr only
// (fallback when the JSONL writer cannot be initialised).
func setupTextLogging(level slog.Level) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))
}

// brokerAdapter adapts broker.EmbeddedBroker to proxy.OAuthBroker interface.
// Needed because broker uses typed AccountStatus while proxy uses plain string.
type brokerAdapter struct {
	inner    *broker.EmbeddedBroker
	accounts *vault.VaultAccountStore // for ExternalID lookup
}

func (a *brokerAdapter) EnsureFresh(ctx context.Context, accountID string) error {
	return a.inner.EnsureFresh(ctx, accountID)
}

func (a *brokerAdapter) ResolveCredential(ctx context.Context, accountID string) (*proxy.OAuthCredential, error) {
	cred, err := a.inner.ResolveCredential(ctx, accountID)
	if err != nil {
		return nil, err
	}
	// Look up ExternalID (account UUID from OAuth provider) for persona injection.
	// Why: Claude OAuth requires metadata.user_id with the real account UUID.
	// Without it, Anthropic returns 429 business rejection.
	var externalID string
	if a.accounts != nil {
		if acct, err := a.accounts.GetByID(ctx, accountID); err == nil && acct != nil {
			externalID = acct.ExternalID
		}
	}
	return &proxy.OAuthCredential{
		AccessToken: cred.AccessToken,
		Provider:    cred.Provider,
		AccountID:   cred.AccountID,
		ExternalID:  externalID,
		ExpiresAt:   cred.ExpiresAt,
		Identity:    cred.Identity,
	}, nil
}

func (a *brokerAdapter) GetAccountStatus(ctx context.Context, accountID string) (string, error) {
	status, err := a.inner.GetAccountStatus(ctx, accountID)
	return string(status), err
}
