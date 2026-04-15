# aikey-proxy

AiKey local proxy — the core execution point for Stage 2 MVP.

Runs on the developer's local machine, receives requests with **virtual keys**, replaces them with **real provider keys**, and forwards to AI providers.

## Responsibilities

- Virtual key (`aikey_vk_*`) → real key substitution
- OpenAI / Anthropic dual-protocol compatible proxy
- SSE streaming response passthrough
- Reads existing Rust vault (Argon2id + AES-256-GCM)
- Asynchronous usage event recording (SQLite WAL)
- Model allowlist policy enforcement
- Local admin API (health / status / metrics)

## Architecture

```
┌──────────────────────────────┐
│  Developer CLI / IDE / SDK   │
│  (Cursor, Claude, Python…)   │
└──────────┬───────────────────┘
           │  Authorization: Bearer aikey_vk_xxx
           │  or x-api-key: aikey_vk_xxx
           ▼
┌──────────────────────────────────────────────┐
│           aikey-proxy  (127.0.0.1:27200)     │
│                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
│  │ vkeys   │→ │ provider │→ │ httputil.  │  │
│  │ registry│  │ adapter  │  │ Reverse    │  │
│  └────┬────┘  └──────────┘  │ Proxy      │  │
│       │                     └─────┬──────┘  │
│  ┌────▼────┐                      │         │
│  │  vault  │  real key            │         │
│  │ reader  │──────────────────────┘         │
│  └─────────┘                                │
│       │           ┌──────────────┐          │
│       │           │ events       │          │
│       │           │ collector    │──→ SQLite │
│       │           └──────────────┘   WAL    │
└───────┼──────────────────────────────────────┘
        │  Reads ~/.aikey/data/vault.db (read-only)
        ▼
┌──────────────────┐        ┌──────────────────┐
│  AiKey Vault     │        │  AI Provider     │
│  (Rust CLI)      │        │  OpenAI / Claude │
└──────────────────┘        └──────────────────┘
```

## Call Sequence

```
Client                    aikey-proxy                Vault          Provider
  │                           │                        │               │
  │  POST /v1/chat/completions│                        │               │
  │  Bearer aikey_vk_xxx      │                        │               │
  │──────────────────────────▶│                        │               │
  │                           │ 1. extractVirtualKey   │               │
  │                           │ 2. registry.Resolve    │               │
  │                           │ 3. checkModelAllowlist │               │
  │                           │───GetSecret(alias)────▶│               │
  │                           │◀──real API key─────────│               │
  │                           │ 4. provider.Rewrite    │               │
  │                           │    (swap key + host)   │               │
  │                           │────real key request───────────────────▶│
  │                           │◀───response (or SSE stream)───────────│
  │◀──response────────────────│                        │               │
  │                           │ 5. async: record event │               │
  │                           │    → events.db (WAL)   │               │
```

## Data Flow

| Phase | Direction | Data |
|-------|-----------|------|
| Inbound | Client → Proxy | Virtual key + request body |
| Resolution | Proxy internal | token → registry → route (provider / base_url / key_alias) |
| Secret | Proxy → Vault | alias → decrypted real key (in-memory cache) |
| Outbound | Proxy → Provider | Real key + original request body |
| Response | Provider → Proxy → Client | Passthrough (SSE streaming: FlushInterval=-1) |
| Audit | Proxy → events.db | Async batch write to SQLite WAL |

## Tech Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Go 1.26 | Cross-platform, single binary |
| Proxy core | `net/http` + `httputil.ReverseProxy` | Lightweight and controllable, no heavy framework |
| SQLite | `modernc.org/sqlite` | Pure Go, no CGO, easy cross-compilation |
| KDF | `golang.org/x/crypto/argon2` | Compatible with Rust vault |
| AEAD | `crypto/aes` + GCM | Compatible with Rust vault |
| Config | YAML (`gopkg.in/yaml.v3`) | Good readability |

## Runtime Environment

| Item | Requirement |
|------|-------------|
| Go | >= 1.26.1 (build only) |
| OS | macOS (arm64), Linux (amd64), Windows (amd64) |
| Disk | ~50 MB (binary + vault + events DB) |
| Memory | ~20 MB RSS (idle), scales with concurrent requests |
| Network | Localhost only (127.0.0.1:27200 by default) |
| Dependencies | None at runtime (single static binary) |
| Prerequisite | AiKey vault (`~/.aikey/data/vault.db`) created by `aikey-cli` |

## Quick Start

```bash
# Build
make build

# Prepare config (see aikey-proxy.yaml.example)
cp aikey-proxy.yaml.example aikey-proxy.yaml
# Edit virtual_keys mappings

# Start (requires master password)
export AIKEY_MASTER_PASSWORD="your-password"
./bin/aikey-proxy --config aikey-proxy.yaml

# Or enter password interactively
./bin/aikey-proxy --config aikey-proxy.yaml

# Verify
curl http://127.0.0.1:27200/health
```

## Usage Examples

```bash
# OpenAI compatible
curl -X POST http://127.0.0.1:27200/v1/chat/completions \
  -H "Authorization: Bearer aikey_vk_openai_dev_001" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'

# Anthropic compatible
curl -X POST http://127.0.0.1:27200/v1/messages \
  -H "x-api-key: aikey_vk_anthropic_dev_001" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-sonnet-4-5-20250929","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}'
```

## Outbound Proxy (VPN / Clash / proxychains)

aikey-proxy supports routing outbound AI provider requests through a local proxy.

### Option 1 — Config file (recommended)

```yaml
upstream_proxy:
  url: "http://127.0.0.1:7890"    # Clash HTTP mode
  # url: "socks5://127.0.0.1:7891"  # Clash SOCKS5 mode
```

Supported schemes: `http`, `https`, `socks5`.

### Option 2 — Environment variables

Go's standard library reads these automatically; no config change needed:

```bash
export HTTPS_PROXY=http://127.0.0.1:7890   # Clash HTTP
export HTTPS_PROXY=socks5://127.0.0.1:7891 # Clash SOCKS5
export NO_PROXY=127.0.0.1,localhost         # don't proxy local admin API
./bin/aikey-proxy --config aikey-proxy.yaml
```

### Option 3 — proxychains (Linux)

proxychains intercepts at the OS syscall level; no configuration in aikey-proxy is required:

```bash
proxychains4 ./bin/aikey-proxy --config aikey-proxy.yaml
```

### Priority

`upstream_proxy.url` (config) > `HTTPS_PROXY` env var > direct connection.

| Scenario | Recommended method |
|----------|--------------------|
| Clash for Windows (HTTP) | `upstream_proxy.url: http://127.0.0.1:7890` |
| Clash SOCKS5 | `upstream_proxy.url: socks5://127.0.0.1:7891` |
| System VPN (all traffic tunnelled) | No config needed — works transparently |
| proxychains on Linux | Run with `proxychains4`, no config needed |

## Admin API

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /status` | Uptime, virtual key count, vault status |
| `GET /metrics` | Per virtual-key / provider request statistics |

## OAuth API (via [aikey-auth-broker](../aikey-auth-broker/README.md))

Provider OAuth account management — login, token lifecycle, credential resolution.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/login` | POST | Start login (returns auth_url) or submit code (returns account) |
| `/oauth/status` | GET | Poll login session status |
| `/oauth/poll` | POST | Poll Device Code completion (Kimi) |
| `/oauth/logout` | POST | Remove account and tokens |
| `/oauth/accounts` | GET | List all OAuth accounts |
| `/oauth/accounts/{id}/health` | GET | Token health (valid/expiring/expired) |
| `/oauth/accounts/{id}/display-identity` | POST | Set display name (Kimi: no email) |

OAuth credentials inject provider-specific persona headers during proxy forwarding:
- **Claude**: `anthropic-beta` + `X-Stainless-*` + `X-Claude-Code-Session-Id` + `metadata.user_id`
- **Codex**: `originator: opencode` + `ChatGPT-Account-Id`
- **Kimi**: `X-Msh-Platform: kimi_cli` + `User-Agent: KimiCLI/1.24.0`

## Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `TOKEN_MISSING` | 401 | Missing `aikey_vk_*` token in request |
| `TOKEN_INVALID` | 401 | Token not found in registry |
| `POLICY_MODEL_FORBIDDEN` | 403 | Model not in allowlist |
| `VAULT_ERROR` | 502 | Cannot find matching real key in vault |
| `UPSTREAM_ERROR` | 502 | Cannot connect to upstream provider |
| `OAUTH_NOT_AVAILABLE` | 503 | OAuth broker not initialized |
| `OAUTH_TOKEN_EXPIRED` | 401 | OAuth token expired, re-login required |
| `OAUTH_RESOLVE_FAILED` | 503 | Cannot resolve OAuth credential |

## Project Structure

```
cmd/aikey-proxy/main.go      Entry point, component wiring, graceful shutdown
internal/
  config/                    YAML config parsing and validation
  vault/                     Rust vault compatible reader + OAuth token/account stores
  vkeys/                     Virtual key registry (RWMutex)
  provider/                  OpenAI / Anthropic / Generic adapters
  proxy/                     Core reverse proxy
  events/                    Async event collection + SQLite WAL
  admin/                     Admin API handlers
  server/                    HTTP server lifecycle
scripts/
  dev-setup.sh               Local dev environment setup (macOS / Windows WSL)
  deploy-integration.sh      Integration environment deployment (systemd)
  deploy-production.sh       Production — Ubuntu / CentOS / macOS (auto-detects remote OS)
  deploy-production.ps1      Production — Windows (PowerShell / WinRM)
```

## Deployment

Three environment deployment scripts are provided in the `scripts/` directory:

| Script | Environment | Target Platform | Description |
|--------|-------------|-----------------|-------------|
| `dev-setup.sh` | Local dev | macOS / Linux / Windows WSL | Go check, build, config init, dev tools install |
| `deploy-integration.sh` | Integration / Staging | Ubuntu / CentOS (systemd) | Cross-compile + systemd service, local or remote SSH |
| `deploy-production.sh` | Production (Shell) | **Ubuntu / CentOS / macOS** | Auto-detects remote OS, systemd / launchd, backup + health check |
| `deploy-production.ps1` | Production (PowerShell) | **Windows** | WinRM local/remote, NSSM service, backup + health check |

```bash
# Local development
./scripts/dev-setup.sh

# Integration (remote Linux)
./scripts/deploy-integration.sh --host user@staging-host --config staging.yaml

# Production — Ubuntu / CentOS (remote OS auto-detected)
./scripts/deploy-production.sh --host user@prod-host --config prod.yaml --vault /path/to/vault.db

# Production — macOS
./scripts/deploy-production.sh --host user@mac-host --config prod.yaml --vault /path/to/vault.db
```

```powershell
# Production — Windows local
.\scripts\deploy-production.ps1 -Config C:\prod.yaml -Vault C:\vault.db

# Production — Windows remote (requires WinRM)
.\scripts\deploy-production.ps1 -ComputerName server01 -Config C:\prod.yaml -Credential (Get-Credential)
```

## License

See [LICENSE](LICENSE) for details.
