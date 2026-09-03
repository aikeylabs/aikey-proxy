// Package mcp is the AiKey MCP gateway plane.
//
// # What it is for
//
// One sentence: Agent tool credentials — GitHub PATs, database passwords, Jira
// tokens — sit in plaintext in every developer's ~/.claude.json today, with
// WRITE scope. That is the same problem AiKey already solved for LLM keys,
// happening again one layer up. Everything in this package exists to move
// those credentials behind the same vault, the same grants, and the same audit
// trail that LLM keys already have.
//
// Requirement spec (single source of truth):
// workflow/CI/requirements/2026-08-20-mcp-gateway.md
//
// # 🔴 The isolation bargain (D-1) — read this before changing anything here
//
// The MCP plane is mounted on the SAME PORT and in the SAME PROCESS as the LLM
// forwarding plane. That was chosen over a separate port or process because
// this plane shares four things with the LLM plane — virtual-key resolution,
// the local vault, the 60s policy poll, and compliance scanning — and splitting
// the process would turn all four into cross-process interfaces, doubling the
// security surface to save some implementation effort. That is the wrong trade
// under the project's cost ladder (safety > stability > UX > ops > … >
// implementation).
//
// 🔴 But the price of same-process is paid HERE, in isolation.go. This is new
// code; new code panics and leaks goroutines. So the plane runs behind:
//
//	its own concurrency semaphore   — MCP saturation cannot starve LLM requests
//	its own timeout                 — read from pkg/fallbackpolicy's three-state
//	                                  resolution, not a second config ladder
//	its own circuit breaker
//	a top-level panic recovery      — a panic in an MCP handler must not reach
//	                                  the shared server
//
// The fences that prove this (1.F2 / 1.F3) are not optional extras: if they do
// not hold, the same-port decision itself is void and the deployment shape has
// to be reopened. Requirement R12.
//
// # What is deliberately NOT here
//
//	a second credential system   — VK bearer resolution is reused verbatim
//	                               (internal/vkeys). R-D-2.
//	session persistence          — sessions are in-memory and die with the
//	                               process. A session is a transport-level
//	                               correlation handle, not a durable grant;
//	                               persisting it would create a second place
//	                               where authorisation appears to live, and
//	                               R8 requires authorisation to be re-checked
//	                               on EVERY tools/call anyway.
//	authorisation caching        — see above. 🚫 Never cache a grant decision
//	                               onto a session; that is exactly the shape of
//	                               "revocation does not take effect".
package mcp
