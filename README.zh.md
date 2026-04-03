# aikey-proxy

AiKey 本地代理 — 阶段 2 MVP 的核心执行点。

运行在开发者本机，接收带有**虚拟 key** 的请求，替换为**真实 provider key**，转发到 AI 提供商。

## 职责

- 虚拟 key（`aikey_vk_*`）→ 真实 key 替换
- OpenAI / Anthropic 双协议兼容代理
- SSE 流式响应透传
- 读取现有 Rust vault（Argon2id + AES-256-GCM）
- 使用事件异步记录（SQLite WAL）
- 模型白名单策略
- 本地管理 API（health / status / metrics）

## 架构

```
┌──────────────────────────────┐
│  Developer CLI / IDE / SDK   │
│  (Cursor, Claude, Python…)   │
└──────────┬───────────────────┘
           │  Authorization: Bearer aikey_vk_xxx
           │  或 x-api-key: aikey_vk_xxx
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
        │  读取 ~/.aikey/data/vault.db (只读)
        ▼
┌──────────────────┐        ┌──────────────────┐
│  AiKey Vault     │        │  AI Provider     │
│  (Rust CLI 创建) │        │  OpenAI / Claude │
└──────────────────┘        └──────────────────┘
```

## 调用时序

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

## 数据流

| 阶段 | 方向 | 数据 |
|------|------|------|
| 入站 | Client → Proxy | 虚拟 key + 请求体 |
| 解析 | Proxy 内部 | token → registry → route（provider / base_url / key_alias） |
| 密钥 | Proxy → Vault | alias → 解密真实 key（内存缓存） |
| 出站 | Proxy → Provider | 真实 key + 原始请求体 |
| 响应 | Provider → Proxy → Client | 透传（流式 SSE: FlushInterval=-1） |
| 审计 | Proxy → events.db | 异步批量写入 SQLite WAL |

## 技术栈

| 组件 | 选型 | 理由 |
|------|------|------|
| 语言 | Go 1.26 | 跨平台、单二进制 |
| 代理核心 | `net/http` + `httputil.ReverseProxy` | 轻量可控，不引入重框架 |
| SQLite | `modernc.org/sqlite` | 纯 Go，无 CGO，交叉编译简单 |
| KDF | `golang.org/x/crypto/argon2` | 兼容 Rust vault |
| AEAD | `crypto/aes` + GCM | 兼容 Rust vault |
| 配置 | YAML (`gopkg.in/yaml.v3`) | 可读性好 |

## 运行环境

| 项目 | 要求 |
|------|------|
| Go | >= 1.26.1（仅构建时需要） |
| 操作系统 | macOS、Linux (amd64)、Windows (amd64) |
| 磁盘 | ~50 MB（二进制 + vault + events DB） |
| 内存 | ~20 MB RSS（空闲），随并发请求数线性增长 |
| 网络 | 仅本地监听（默认 127.0.0.1:27200） |
| 运行时依赖 | 无（单一静态二进制） |
| 前置条件 | 由 `aikey-cli` 创建的 AiKey vault（`~/.aikey/data/vault.db`） |

## 快速开始

```bash
# 构建
make build

# 准备配置（参考 aikey-proxy.yaml.example）
cp aikey-proxy.yaml.example aikey-proxy.yaml
# 编辑 virtual_keys 映射

# 启动（需要 vault 密码）
export AIKEY_MASTER_PASSWORD="your-password"
./bin/aikey-proxy --config aikey-proxy.yaml

# 或交互式输入密码
./bin/aikey-proxy --config aikey-proxy.yaml

# 验证
curl http://127.0.0.1:27200/health
```

## 使用示例

```bash
# OpenAI 兼容
curl -X POST http://127.0.0.1:27200/v1/chat/completions \
  -H "Authorization: Bearer aikey_vk_openai_dev_001" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'

# Anthropic 兼容
curl -X POST http://127.0.0.1:27200/v1/messages \
  -H "x-api-key: aikey_vk_anthropic_dev_001" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-sonnet-4-5-20250929","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}'
```

## 管理 API

| 端点 | 说明 |
|------|------|
| `GET /health` | 健康检查 |
| `GET /status` | uptime、虚拟 key 数量、vault 状态 |
| `GET /metrics` | 按虚拟 key / provider 的请求统计 |

## 错误码

| Code | HTTP | 含义 |
|------|------|------|
| `TOKEN_MISSING` | 401 | 请求中缺少 `aikey_vk_*` token |
| `TOKEN_INVALID` | 401 | token 不在注册表中 |
| `POLICY_MODEL_FORBIDDEN` | 403 | 模型不在白名单内 |
| `VAULT_ERROR` | 502 | vault 中找不到对应的真实 key |
| `UPSTREAM_ERROR` | 502 | 无法连接上游 provider |

## 项目结构

```
cmd/aikey-proxy/main.go      入口、组件装配、优雅关闭
internal/
  config/                    YAML 配置解析与校验
  vault/                     Rust vault 兼容读取（只读）
  vkeys/                     虚拟 key 注册表（RWMutex）
  provider/                  OpenAI / Anthropic / Generic 适配器
  proxy/                     核心反向代理
  events/                    异步事件收集 + SQLite WAL
  admin/                     管理 API handlers
  server/                    HTTP 服务器生命周期
scripts/
  dev-setup.sh               本地开发环境初始化（macOS / Windows WSL）
  deploy-integration.sh      集成环境部署（systemd）
  deploy-production.sh       生产部署 — Ubuntu / CentOS / macOS（自动检测远端 OS）
  deploy-production.ps1      生产部署 — Windows（PowerShell / WinRM）
```

## 部署

提供三套环境的部署脚本，位于 `scripts/` 目录：

| 脚本 | 环境 | 目标平台 | 说明 |
|------|------|---------|------|
| `dev-setup.sh` | 本地开发 | macOS / Linux / Windows WSL | Go 检查、构建、配置初始化、dev 工具安装 |
| `deploy-integration.sh` | 集成/预发布 | Ubuntu / CentOS (systemd) | 交叉编译 + systemd 服务，支持本地或远程 SSH |
| `deploy-production.sh` | 生产（Shell） | **Ubuntu / CentOS / macOS** | 远端 OS 自动检测，systemd / launchd，备份+健康检查 |
| `deploy-production.ps1` | 生产（PowerShell） | **Windows** | WinRM 本地/远程，NSSM 服务，备份+健康检查 |

```bash
# 本地开发
./scripts/dev-setup.sh

# 集成环境（远程 Linux）
./scripts/deploy-integration.sh --host user@staging-host --config staging.yaml

# 生产 — Ubuntu / CentOS（远程 OS 自动检测）
./scripts/deploy-production.sh --host user@prod-host --config prod.yaml --vault /path/to/vault.db

# 生产 — macOS
./scripts/deploy-production.sh --host user@mac-host --config prod.yaml --vault /path/to/vault.db

# 生产 — Windows（PowerShell）
.\scripts\deploy-production.ps1 -Config C:\prod.yaml -Vault C:\vault.db                      # 本地
.\scripts\deploy-production.ps1 -ComputerName server01 -Config C:\prod.yaml -Credential (Get-Credential)  # 远程
```

## 许可证

详见 [LICENSE](LICENSE)。
