# aikey-proxy（Go Local Proxy）

- 需要较高的稳定性和高可用：主链路（代理转发）优先，旁路功能可插拔、异常隔离，不影响主数据流
- aikey→上游(LLM/含 Mock)的请求绝不加任何 `X-Aikey-*`/非标准头（`stripAikeyRequestHeaders` 无差别剥离、不开例外） → [no-aikey-headers-to-llm-upstream.md](../workflow/CI/IDE/claude/principles/no-aikey-headers-to-llm-upstream.md)
- vault 变更靠幂等对账读收敛，不允许依赖重启 proxy 生效 → [event-write-reconcile-read.md](../workflow/CI/IDE/claude/principles/event-write-reconcile-read.md)
- 负责费用数据采集、上报：解析回落默认值必须 WARN，事件名 / 错误码走中央枚举 → [logging-conventions.md](../workflow/CI/IDE/claude/principles/logging-conventions.md)
- 对于错误数据、错误的进程状态、临时异常，不阻塞核心业务流，需要可恢复、可幂等覆盖、可最终一致
