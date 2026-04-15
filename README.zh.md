# AiKey Proxy

本地安全反向代理。将虚拟 Key 解析为真实 API Key 或 OAuth Token，注入认证头后转发到上游 Provider。

详细英文文档见 [README.md](README.md)。

## 核心职责

- 接收 Claude Code / Cursor / 其他工具的 API 请求
- 解析虚拟 Key（`aikey_vk_*` / `aikey_personal_*` / `aikey_oauth_*`）
- 从 vault 解密真实凭证
- 注入 Provider 特定的认证头
- 转发到上游 API 端点

## OAuth 支持

通过内嵌的 [aikey-auth-broker](../aikey-auth-broker/README.zh.md) 管理 Provider OAuth 账号。

### OAuth API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/oauth/login` | POST | 开始登录（返回授权 URL）或提交授权码 |
| `/oauth/status` | GET | 查询登录会话状态 |
| `/oauth/poll` | POST | Device Code 轮询（Kimi） |
| `/oauth/logout` | POST | 删除账号和 Token |
| `/oauth/accounts` | GET | 列出所有 OAuth 账号 |
| `/oauth/accounts/{id}/health` | GET | Token 健康检查 |

### Provider Persona 注入

OAuth 请求在转发时自动注入 Provider 特定的认证头：

- **Claude**：完整 Claude Code 指纹（`anthropic-beta` + `X-Stainless-*` + `X-Claude-Code-Session-Id` + `metadata.user_id`）
- **Codex**：`originator: opencode` + `ChatGPT-Account-Id`
- **Kimi**：`X-Msh-Platform: kimi_cli` + `User-Agent: KimiCLI/1.24.0`

## 快速开始

```bash
# 设置主密码并启动
export AIKEY_MASTER_PASSWORD="your_password"
aikey-proxy

# 健康检查
curl http://127.0.0.1:27200/health
```

## 许可证

Apache-2.0
