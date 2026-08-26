package observability

import (
	"context"
	"log/slog"
	"os"
)

// ---- Event name constants ----

// Proxy process lifecycle events.
const (
	EventProxyProcessStarted = "proxy.process.started"
	EventProxyProcessStopped = "proxy.process.stopped"
	// EventProxyShutdownWatchdogTimeout: the post-drain teardown (generation
	// close chain) overran its watchdog and was abandoned; goroutine stacks
	// were dumped to stderr. Exit still completes — this is forensic evidence,
	// not a hang (bugfix 2026-08-19-proxy-shutdown-unbounded-close).
	EventProxyShutdownWatchdogTimeout = "proxy.shutdown.watchdog_timeout"
	EventProxyConfigLoaded   = "proxy.config.loaded"
	EventProxyListenerBound  = "proxy.listener.bound"
)

// Browserless pool-login events. These never carry a session key or token;
// only stable operation metadata is logged.
const (
	EventProxyPoolSessionKeyExchangeFailed     = "proxy.pool.session_key_exchange_failed"
	EventProxyPoolSessionKeyIdentityMismatch   = "proxy.pool.session_key_identity_mismatch"
	EventProxyPoolSessionKeyWritebackFailed    = "proxy.pool.session_key_writeback_failed"
	EventProxyPoolSessionKeyRuntimeSyncPending = "proxy.pool.session_key_runtime_sync_pending"

	ErrCodeProxyPoolSessionKeyWritebackFailed    = "SESSION_KEY_WRITEBACK_FAILED"
	ErrCodeProxyPoolSessionKeyRuntimeSyncPending = "SESSION_KEY_RUNTIME_SYNC_PENDING"
)

// Signal uplink events. The data plane remains non-blocking; these names make
// durable auth-failure outbox and best-effort trend upload failures queryable.
const (
	EventProxySignalAuthFailureStateInvalid     = "proxy.signal.auth_failure_state_invalid"
	EventProxySignalAuthFailureStateWriteFailed = "proxy.signal.auth_failure_state_write_failed"
	EventProxySignalBearerFailed                = "proxy.signal.bearer_failed"
	EventProxySignalUploadFailed                = "proxy.signal.upload_failed"
	EventProxySignalUploadRejected              = "proxy.signal.upload_rejected"
)

// Reload and generation lifecycle events.
const (
	EventProxyReloadStarted          = "proxy.reload.started"
	EventProxyReloadCompleted        = "proxy.reload.completed"
	EventProxyReloadFailed           = "proxy.reload.failed"
	EventProxyGenerationDraining     = "proxy.generation.draining"
	EventProxyGenerationDrained      = "proxy.generation.drained"
	EventProxyGenerationDrainTimeout = "proxy.generation.drain_timeout"
)

// Control-plane self-heal events (2026-07-01): recovery from a host network
// change that leaves the long-lived control-plane client stalled with no-route
// errors to master. See supervisor/selfheal.go + netmon.go.
const (
	EventProxyControlPlaneClientRebuilt    = "proxy.control_plane.client_rebuilt"
	EventProxyControlPlaneNetChange        = "proxy.control_plane.net_change_detected"
	EventProxyControlPlaneSelfRestart      = "proxy.control_plane.self_restart"
	EventProxyControlPlaneRestartExhausted = "proxy.control_plane.restart_budget_exhausted"
)

// Egress (upstream proxy) events (2026-07-08): OS system-proxy auto-detection
// for the direct egress path. A long-lived proxy daemon must FOLLOW the host's
// system proxy (Clash port change / toggle) instead of freezing the value seen
// at process start — see internal/sysproxy.
const (
	EventProxyEgressSysProxyChanged       = "proxy.egress.sysproxy_changed"
	EventProxyEgressSysProxyReadFailed    = "proxy.egress.sysproxy_read_failed"
	EventProxyEgressSysProxyReadRecovered = "proxy.egress.sysproxy_read_recovered"
	// EventProxyEgressPingEngineDialFailed: /admin/probe/ping could not reach
	// the target through the configured engine-spec egress (socks5 chain /
	// mihomo fragment). The raw engine error is logged at Debug only — it can
	// quote the spec verbatim, credentials included (bugfix 2026-07-19).
	EventProxyEgressPingEngineDialFailed = "proxy.egress.ping_engine_dial_failed"
	// EventProxyProbeUpstreamUnresolved: /admin/probe/ping was asked to test a
	// named credential (source_ref) but could not resolve which upstream that
	// credential talks to, so it REFUSED to probe rather than substitute a
	// guess (2026-08-03).
	//
	// Why this is WARN and not a silent default: the predecessor behavior fell
	// back to the provider's public host, which made the probe's verdict
	// uncorrelated with the credential under test — green when the real gateway
	// was down, red when it was fine. requirements/2026-07-18 §上游地址单一解析
	// 「回落路径必须配告警，🚫 不静默」.
	EventProxyProbeUpstreamUnresolved = "proxy.probe.upstream_unresolved"
	// EventProxyEgressRequestAttribution: per-request egress traceability
	// (2026-07-19). One Info line per forwarded request carrying trace_id +
	// account_id + oauth_identity + egress_applied/engine/fingerprint, so a real
	// request can be traced from logs to the egress it exited through (grep the
	// trace_id). fingerprint→exit_ip comes from /admin/egress/selfcheck, off the
	// hot path. The same attribution rides the usage event's ext_json (durable
	// audit). See internal/proxy/egress_attribution.go.
	EventProxyEgressRequestAttribution = "proxy.egress.request_attribution"
)

// SyncRail events (2026-07-03): control-plane sync rail state transitions.
// A rail keeps serving last-known data and retrying forever in every state —
// these events are the VISIBILITY the old silent keep-last-known loops lacked
// (bugfix 2026-07-03-routing-override-rail-silent-stall.md). See
// supervisor/railset.go.
const (
	EventProxySyncRailStale     = "proxy.sync.rail_stale"
	EventProxySyncRailOffline   = "proxy.sync.rail_offline"
	EventProxySyncRailRecovered = "proxy.sync.rail_recovered"
	// #nosec G101 -- an event NAME, not a credential. The literal contains the
	// word "credential" because that is what the event describes.
	EventProxySyncCredentialRebuilt          = "proxy.sync.credential_rebuilt"
	EventProxyGroupRuntimeChanged            = "proxy.group_runtime.changed"
	EventProxyGroupRuntimeWriteFailed        = "proxy.group_runtime.write_failed"
	EventProxyGroupRuntimeReloadFailed       = "proxy.group_runtime.reload_failed"
	EventProxyClusterVaultAssignmentsCorrupt = "proxy.routing_override.cluster_vault_corrupt"
	EventProxyClusterVaultAssignmentsChanged = "proxy.routing_override.cluster_vault_changed"
	// EventProxySyncHealthFileFailed: the statusline sync-health bypass file
	// (~/.aikey/run/sync-health.json) could not be written/removed — the claude
	// status bar may show a stale (or miss a fresh) sync warning.
	// Key-revocation rail (2026-08-26): bounds how long a running proxy keeps
	// honouring a virtual key the control plane has stopped honouring. See
	// supervisor/key_revocation_rail.go and
	// workflow/CI/bugfix/20260826-proxy-revocation-window-unbounded.md.
	EventProxyKeyRevocationDropped   = "proxy.key_revocation.route_dropped"
	EventProxyKeyRevocationChanged   = "proxy.key_revocation.set_changed"
	EventProxyKeyRevocationMalformed = "proxy.key_revocation.snapshot_malformed"
	EventProxyKeyRevocationRefused   = "proxy.key_revocation.request_refused"
	EventProxySyncHealthFileFailed   = "proxy.sync.health_file_failed"
	// EventReporterDeadLetterReplayed: the automatic dead-letter replay ran
	// after the upload pipe recovered (2026-07-04 self-heal) — carries
	// scanned/replayed/still-failing counts, or the error when the pass failed.
	EventReporterDeadLetterReplayed = "proxy.events.dead_letter_replayed"
	// EventComplianceUploadDeadLettered: a team→master compliance upload failed
	// and the batch was conserved in dead_letter.jsonl instead of being dropped
	// (2026-08-10). Carries route_source / status / reason / count. The single
	// most useful line when an audit trail looks short: it says the events
	// exist, where they are, and why they have not landed yet.
	EventComplianceUploadDeadLettered = "proxy.compliance.upload_dead_lettered"
	// EventComplianceDeadLetterReplayed: one conserved compliance batch was
	// re-attempted by a replay pass (automatic on recovery, or admin-triggered).
	EventComplianceDeadLetterReplayed = "proxy.compliance.dead_letter_replayed"
	// EventComplianceDeadLetterOverflow: the dead-letter file hit its size cap
	// and a compliance batch was DROPPED. This is real audit loss, unlike every
	// other event in this group — it is logged at ERROR for that reason.
	EventComplianceDeadLetterOverflow = "proxy.compliance.dead_letter_overflow"
)

// Health events.
const (
	EventProxyHealthOk        = "proxy.health.ok"
	EventProxyHealthDegraded  = "proxy.health.degraded"
	EventProxyHealthRecovered = "proxy.health.recovered"
	EventProxyVaultStale      = "proxy.vault.stale_detected"
)

// Request events.
const (
	EventProxyRequestAuthFailed    = "proxy.request.auth_failed"
	EventProxyRequestPolicyDenied  = "proxy.request.policy_denied"
	EventProxyRequestVaultFailed   = "proxy.request.vault_lookup_failed"
	EventProxyRequestUpstreamError = "proxy.request.upstream_error"
	EventProxyRequestSlow          = "proxy.request.slow"
	EventProxyRequestCompleted     = "proxy.request.completed"
	EventProxyRequestQuotaExceeded = "proxy.request.quota_exceeded"
	// EventProxyRequestDialectUnsupported (2026-07-13): the request's endpoint is
	// not served by the credential's OAuth upstream (codex OAuth = Responses API
	// only). Rejected locally with ErrCodeOAuthResponsesOnly instead of letting
	// ChatGPT's edge answer with a misleading "invalid x-api-key".
	EventProxyRequestDialectUnsupported = "proxy.request.dialect_unsupported"
	// Fence I13 runtime guard (2026-07-21). EventProxyRequestIdentityScrubbed:
	// an outbound header carried one of the control-plane member-identity shapes
	// enumerated in proxy/member_identity_guard.go (that file is the only place
	// in the data plane allowed to spell them out, so the vocabulary fence
	// TestProxySource_DoesNotReferenceMemberIdentityFields keeps meaning
	// something) and was dropped before the upstream saw it.
	// EventProxyRequestIdentityBlocked: the
	// proxy was about to write such a value into the request body's
	// metadata.user_id and refused. Both are WARN, never INFO: they mean code
	// upstream of the guard learned a member's provider identity, which is the
	// thing to go fix — the guard only stops it reaching Anthropic/OpenAI.
	// Neither ever logs the offending value; only the shape name.
	EventProxyRequestIdentityScrubbed = "proxy.request.identity_scrubbed"
	EventProxyRequestIdentityBlocked  = "proxy.request.identity_inject_blocked"
	// EventProxyQuotaModelUnpriced: a completed request's model has no entry in
	// the edge price summary (D-U8/P7), so its usd was NOT counted locally — the
	// token quota floor backstops it and the server baseline catches up on
	// re-sync. Recurring hits signal a stale summary needing a price re-sync.
	EventProxyQuotaModelUnpriced = "proxy.quota.model_unpriced"
	// Compliance restorable-mask chain (方案 20260808 占位符还原与全类型脱敏).
	// EventProxyFilterRestoreAlignMismatch: the masked text and the detector's
	// span metadata disagree for one placeholder family (user typed the literal
	// token, spans drifted, occurrences overlap) — the mask is KEPT, only the
	// response-side restore is dropped for that family.
	// EventProxyFilterRestoreDuplicateToken: the detector sent more than one
	// Restorable for the SAME placeholder token, breaking the "one token ⇒ one
	// restorable" wire contract P1 established (alias entities must be merged
	// child-side). Acting on it would renumber one family's occurrences with the
	// other family's spans — a silent WRONG restore — so every family sharing
	// the token is dropped. WARN, never a request failure: fail-open governs the
	// whole filter chain, and the sensitive text stays masked either way.
	// Both carry counts only; placeholder↔original content is never logged.
	EventProxyFilterRestoreAlignMismatch  = "proxy.filter.restore_align_mismatch"
	EventProxyFilterRestoreDuplicateToken = "proxy.filter.restore_duplicate_token"
	// EventProxyFilterActionCapped: the detector returned mask/block for a piece
	// whose block type is scanned for AUDIT ONLY (agent tool_result / tool_use;
	// 方案② 2026-08-10), so the proxy recorded the finding and forwarded the
	// content BYTE-UNCHANGED. This is the deliberate, decided behavior — not a
	// degrade — but it is logged per occurrence because "we saw sensitive content
	// and let it through on purpose" must never be inferable only from silence.
	// Counts + the verdict name only; never any content.
	// EventProxyFilterMaskUnwritablePiece: a Mask verdict landed on a piece with
	// no write-back target (the joined tool_use.input blob). Unreachable while its
	// action ceiling forbids masking — it fires only if someone raised the ceiling
	// without splitting the join, so it names a code defect, not a content event.
	EventProxyFilterActionCapped        = "proxy.filter.action_capped"
	EventProxyFilterMaskUnwritablePiece = "proxy.filter.mask_unwritable_piece"
	// EventProxyFilterMaxActionReadFailed means the operational enforcement
	// ceiling could not be read from the Vault. The supervisor preserves the
	// safer full ceiling and emits this stable event for external alerting.
	EventProxyFilterMaxActionReadFailed = "proxy.filter.max_action_read_failed"
	// EventProxyFilterProbeExcluded: a Probe-pipeline request (mode C,
	// /probe/<alias>/v1/..., RouteSource "probe") reached the compliance entry
	// point and was skipped WITHOUT entering the chain. Its payload is aikey's
	// own fixed degrade-detection probe, not employee content: masking it would
	// change the prompt the response fingerprint is measured against, and the
	// resulting event would attribute aikey's text to the employee. DEBUG, one
	// line per probe — it is the expected path, logged only so an operator
	// debugging "why is there no compliance event for this request" can see the
	// reason instead of inferring it from silence. Carries no content.
	EventProxyFilterProbeExcluded = "proxy.filter.probe_excluded"
	// EventProxyFilterInputTruncated: one or more content pieces in THIS request
	// were longer than the detector's input cap (proxy pipeInputCap, 16 KiB), so
	// only their leading bytes were scanned and the remaining tail was forwarded
	// to the upstream LLM WITHOUT ever being inspected.
	//
	// WHY it exists (2026-08-13, bugfix 20260813-pipe-input-cap-truncates-silently):
	// the cap itself is a deliberate, correct trade-off (the detector's own NLP
	// input cap is the same 16 KiB, and a huge piece stalls/desyncs the IPC), but
	// it used to happen with ZERO signal — no log, no counter, no event. Nothing
	// in the system could answer "how much content did this deployment never
	// scan?", while the far rarer "rule skipped because RE2 rejected it" already
	// had a startup banner plus a per-rule WARN. That asymmetry is what makes it
	// a 失败要显眼 violation rather than a design bug.
	//
	// The cap is a BYTE budget, not a character budget: CJK text is 3 bytes per
	// character, so ~5,460 Chinese characters already reach it. The event's
	// *_bytes fields are named for that unit on purpose — reading the cap as
	// "16,000 characters" understates the exposure by ~3x.
	//
	// WARN, and RATE-LIMITED to exactly ONE aggregated line per request: a large
	// agent context routinely truncates many pieces at once, and one line per
	// piece would turn a real signal into log spam. The aggregate carries the
	// counts (pieces_truncated / total_bytes / scanned_bytes / skipped_bytes) and
	// the first affected piece index. Counts only — never any content.
	// The externally readable counterpart is /v1/diagnostics/pipeline
	// (mask_restore.scan_truncated_pieces / scan_skipped_bytes), because a signal
	// that only exists in a log file is not externally readable (health-signal-surface).
	EventProxyFilterInputTruncated = "proxy.filter.input_truncated"
	// App-hook effective-content tracking (2026-08-13, bugfix
	// 20260813-pack-swap-does-not-invalidate-proxy-cache). A child app can
	// hot-swap the content it detects against without restarting, so the proxy
	// polls each child for a fingerprint of its effective content set and folds
	// it into the verdict cache key (internal/apphook/contentversion.go).
	//
	// EventAppHookContentVersionChanged: INFO, on transition only. The child's
	// content set moved (an admin added or deleted a rule and the pack reached
	// this box), so every verdict memoized under the previous one is now
	// unreachable and will be re-scanned. This is the line that answers "did my
	// console edit actually reach this node, and when?".
	//
	// EventAppHookContentVersionUnknown: WARN, on transition only. The child can
	// no longer say which content set is live, so verdict memoization is disabled
	// and every piece is really scanned — safe, but the latency cost is real and
	// otherwise unattributable. The externally readable counterpart is
	// GET /admin/compliance/packs returning {available:false}, which is driven by
	// the same child-side condition.
	EventAppHookContentVersionChanged = "proxy.apphook.content_version_changed"
	EventAppHookContentVersionUnknown = "proxy.apphook.content_version_unknown"
	// Verdict-cache suspension, observed FROM THE DATA PLANE (2026-08-13, review
	// finding B6). The pair above is raised by the background poll inside the
	// hook; these two are the dispatcher's own 二层兜底 (日志规范), raised at the
	// point where a real user request actually loses the cache.
	//
	// WHY BOTH LAYERS. The poll's WARN says "the child can no longer state its
	// content set". These say "…and therefore THIS request, and every request
	// after it, is paying the full cold-scan cost", carry the enumerated cause
	// (child_degraded vs unsupported_op_list_packs — restart vs upgrade), and
	// come from the request logger so they carry request_id / trace_id / span_id.
	// The poll's line has no request context and cannot; correlating a latency
	// complaint to a trace is exactly what an operator needs here.
	//
	// 🔴 RATE LIMITING IS PART OF THE CONTRACT, not an optimisation. This state
	// PERSISTS (an un-upgraded detector never self-heals), so one line per
	// request would emit at request rate forever and bury the signal it exists to
	// raise. Both are emitted ONLY on the transition, latched on the Proxy
	// generation — the same 「只记状态转变」 posture as the pair above and as the
	// 16 KiB truncation aggregate.
	//
	// Suspended = WARN (a real, unattributable latency regression is now in
	// effect). Resumed = INFO (recovery is not a fault, but the operator needs
	// the bracket to know the window closed).
	EventProxyFilterVerdictCacheSuspended = "proxy.filter.verdict_cache_suspended"
	EventProxyFilterVerdictCacheResumed   = "proxy.filter.verdict_cache_resumed"
	// Oauth-group routing (N8). EventProxyGroupRouteResolved: a group VK request
	// picked + injected a candidate account. EventProxyGroupRouteDegraded: no
	// usable candidate (no material / all expired-exhausted / key unavailable) →
	// the request is failed rather than silently routed wrong.
	EventProxyGroupRouteResolved = "proxy.group.route_resolved"
	EventProxyGroupRouteDegraded = "proxy.group.route_degraded"
	// EventProxyGroupAccountCooldown (N8c): a pool account's upstream returned a
	// fallback-worthy failure (401 broken / exhaustion-429), so it was cooled down
	// and subsequent requests route around it.
	EventProxyGroupAccountCooldown = "proxy.group.account_cooldown"
	// EventProxyGroupRoutingConfigInvalid means the delivered pool policy could
	// not be parsed. The data path falls back to the product default, but a WARN
	// keeps control-plane drift visible and traceable.
	EventProxyGroupRoutingConfigInvalid = "proxy.group.routing_config_invalid"
	// EventProxyGroupAccountSwitched (N9 #8): the seat's rank-0 (primary) account
	// was unusable (cooled / exhausted / expired / no material) so the request
	// fell back to a different candidate — an auditable account switch.
	EventProxyGroupAccountSwitched = "proxy.group.account_switched"
	// EventProxyGroupLoginRequired (RW2; semantics = 2026-08-15 方案 b, which
	// supersedes the old D2 "strict HRW, never skip" rule): NO pool candidate is
	// serviceable for this member and at least one is waiting on a login. The
	// proxy returns a structured login prompt naming the actionable account (the
	// engine's target first). A needs_login account alone does NOT emit this —
	// healthy siblings serve first (vkeys.PickRoutedAccount, spec R27).
	EventProxyGroupLoginRequired = "proxy.group.login_required"
	// EventProxyGroupWindowPrecut (N10): an account's upstream utilization crossed
	// its randomized window cap (window_max_util_pct), so it was pre-cut for that
	// window (cooled until reset) — staying under 100% which looks like abuse.
	EventProxyGroupWindowPrecut = "proxy.group.window_precut"
	// EventProxyGroupRequestFailover (N9): a pool account's upstream failure was
	// retried IN-REQUEST on another candidate account (first-byte gate held — the
	// client saw nothing of the failed attempt). One event per switch, carrying
	// from/to account + the failed status.
	EventProxyGroupRequestFailover = "proxy.group.request_failover"
	// EventProxyGroupProviderPathState records path-scoped transport breaker
	// changes. It never carries raw base URLs or egress specifications.
	EventProxyGroupProviderPathState = "proxy.group.provider_path_state"
	// EventProxyGroupModelTierCooldown (P1-C): a premium-model window (e.g. the
	// Fable 7d_oi weekly window) exhausted — the account is cooled for THAT model
	// tier only and keeps serving every other model. Also used for the
	// unmapped-exhausted-window observability WARN (tier-table gap detection).
	EventProxyGroupModelTierCooldown = "proxy.group.model_tier_cooldown"
	// EventProxyGroupTokenRevoked (update/20260817 覆盖度审计 2026-08-18): the
	// upstream HARD-revoked a member token (401/403 with a documented revocation
	// marker). The revocation MOMENT gets its own scheduling-log row — the
	// login_required rows that follow are the consequence, not the cause.
	EventProxyGroupTokenRevoked = "proxy.group.token_revoked"
	// EventProxyGroupWafExcluded: a 429 carried NO exhaustion/rate-limit evidence
	// headers and was classified as WAF/风控 — deliberately NOT cooled (cooling on
	// a fake 429 is how a WAF starves a healthy pool) and passed through. Logged
	// because "keeps hitting an evidence-less wall" is exactly the signal a 撞墙
	// investigation needs.
	EventProxyGroupWafExcluded = "proxy.group.waf_429_excluded" //nolint:gosec // G101 false positive: gosec's hardcoded-credential heuristic matches this identifier/value pair. It is an event name in the central enum, never a secret.
	// EventProxyGroupUpstreamErrorPassthrough: a non-failover-eligible upstream
	// 4xx (400/402/403/404/422… — NOT 401, NOT an evidence 429) was passed through
	// verbatim. No routing state changes; the row exists so a support bundle can
	// correlate "user saw provider errors" with the surrounding scheduling
	// timeline (拍板 2026-08-18 #3). Per-window suppression bounds a burst.
	EventProxyGroupUpstreamErrorPassthrough = "proxy.group.upstream_error_passthrough" //nolint:gosec // G101 false positive: gosec's hardcoded-credential heuristic matches this identifier/value pair. It is an event name in the central enum, never a secret.
	// EventProxyGroupSeatBlocked (§5.5): the engine left this seat UNBOUND because
	// every account in its pool/segment is at the ≤3-人/号 cap, so the proxy 429s it
	// (never WRH-falls-back, which would route a 4th user onto a full account).
	EventProxyGroupSeatBlocked             = "proxy.group.seat_blocked"
	EventProxyGroupRequestBodyRejected     = "proxy.group.request_body_rejected"
	EventProxyGroupReplayCapacityExhausted = "proxy.group.replay_capacity_exhausted"
	// EventProxyGroupLoginStateWriteFailed / ClearFailed: the bypass
	// ~/.aikey/run/group-login-required.json state file (statusline login hint,
	// 20260703 update) could not be written / removed. Best-effort by design —
	// the 401 response itself is unaffected — but WARN because the statusline
	// hint silently disappearing (or nagging stale) is a debugging trap.
	EventProxyGroupLoginStateWriteFailed = "proxy.group.login_state_write_failed"
	EventProxyGroupLoginStateClearFailed = "proxy.group.login_state_clear_failed"
)

// Usage extraction events.
//
// EventProxyExtractionMismatch fires when an extractor falls back to defaults
// because the response body doesn't match expected wire format (json error,
// missing usage field, unknown field names like Responses API's
// input_tokens/output_tokens vs Chat Completions' prompt_tokens/completion_tokens).
//
// EventProxyExtractionEmpty is the caller-side double-defense: HTTP 200 with
// non-empty body but extractor returned (0, 0). Catches the case where a new
// wire format ships and the extractor wasn't updated to log Mismatch for it.
const (
	EventProxyExtractionMismatch = "proxy.extraction.shape_mismatch"
	EventProxyExtractionEmpty    = "proxy.extraction.empty"
)

// ---- Error code constants ----

const (
	ErrCodeTokenMissing                   = "TOKEN_MISSING"
	ErrCodeTokenInvalid                   = "TOKEN_INVALID"
	ErrCodePolicyModelForbidden           = "POLICY_MODEL_FORBIDDEN"
	ErrCodeSecretNotConfigured            = "SECRET_NOT_CONFIGURED"
	// ErrCodeUpstreamBaseURLMissing (2026-08-25, bugfix
	// 2026-08-25-empty-upstream-base-url-unhelpful-error): the resolved route
	// carries no upstream base URL — a configuration gap (custom provider with
	// neither a credential Base URL nor a provider default), NOT a network
	// failure. Kept distinct from UPSTREAM_ERROR so the error names the fix
	// instead of sending the operator to debug connectivity.
	ErrCodeUpstreamBaseURLMissing         = "UPSTREAM_BASE_URL_MISSING"
	ErrCodeUpstreamError                  = "UPSTREAM_ERROR"
	ErrCodeProviderError                  = "PROVIDER_ERROR"
	ErrCodeUsageExtractionFailed          = "USAGE_EXTRACTION_FAILED"
	ErrCodeClusterVaultAssignmentsCorrupt = "CLUSTER_VAULT_ASSIGNMENTS_CORRUPT"
	// Enterprise quota (Phase 2, design §5.5). Stage 3 wires the token code;
	// USD + degraded-block are reserved for later stages ($ enforcement / §8).
	ErrCodeQuotaExceededToken = "QUOTA_EXCEEDED_TOKEN"
	ErrCodeQuotaExceededUSD   = "QUOTA_EXCEEDED_USD"
	ErrCodeQuotaDegradedBlock = "QUOTA_DEGRADED_BLOCK"
	// Oauth-group routing degrade codes (N8). The resolver's typed reasons
	// (GROUP_NO_CANDIDATES / GROUP_NO_MATERIAL / GROUP_ALL_UNUSABLE) are surfaced
	// verbatim; GROUP_KEY_UNAVAILABLE is the proxy-local "can't decrypt" case.
	ErrCodeGroupKeyUnavailable = "GROUP_KEY_UNAVAILABLE"
	// ErrCodeGroupUpstreamUnavailable preserves a non-quota pool outage after
	// every candidate has entered a 5xx/transport cooldown. It must remain 503;
	// collapsing it into GROUP_ALL_UNUSABLE would falsely tell clients that the
	// provider quota or rate limit was exhausted.
	ErrCodeGroupUpstreamUnavailable = "GROUP_UPSTREAM_UNAVAILABLE"
	// ErrCodeGroupPoolFull (§5.5): 429 when the seat is blocked — every pool account
	// is at the per-account user cap, or no usable account remains. Neutral wording
	// (does not guess the cause); the user waits or contacts the admin.
	ErrCodeGroupPoolFull               = "GROUP_POOL_FULL"
	ErrCodeGroupRequestBodyTooLarge    = "GROUP_REQUEST_BODY_TOO_LARGE"
	ErrCodeGroupRequestBodyReadFailed  = "GROUP_REQUEST_BODY_READ_FAILED"
	ErrCodeGroupReplayCapacityExceeded = "GROUP_REPLAY_CAPACITY_EXCEEDED"
	// ErrCodeModelTierExhausted (P1-C Phase 2, 用户拍板 2026-07-19): 429 when the
	// REQUESTED MODEL's premium weekly window (e.g. Fable 7d_oi) is exhausted on
	// every usable pool account, while other models still serve — the message
	// tells the user to switch model instead of implying the whole pool is down.
	ErrCodeModelTierExhausted = "MODEL_TIER_EXHAUSTED"
	// ErrCodeOAuthResponsesOnly (2026-07-13): the request targets an endpoint the
	// credential's OAuth upstream doesn't serve. Codex OAuth (ChatGPT accounts)
	// speaks ONLY the Responses API at chatgpt.com/backend-api/codex — a
	// /chat/completions client (opencode, ai-sdk, LangChain, …) pointed at an
	// OAuth-backed openai key used to have its path appended to that base,
	// producing a 4xx from ChatGPT's edge whose body ("invalid x-api-key") sent
	// users hunting a key problem that did not exist. Fail fast with the real
	// reason + the way out (use an API-key credential for this client). 400.
	ErrCodeOAuthResponsesOnly = "OAUTH_RESPONSES_ONLY"
	// ErrCodeAccountEgressProxy (§11.7, P7): the resolved oauth-group account pins
	// a per-account egress proxy whose already-constructed dial path is currently
	// unreachable. 503; the request is REFUSED rather than sent out the node's IP
	// (which would defeat the per-account isolation).
	ErrCodeAccountEgressProxy = "ACCOUNT_EGRESS_PROXY_UNAVAILABLE"
	// ErrCodeAccountEgressEngine means the configured per-account egress could
	// not even be constructed by this proxy build (for example a Hysteria2
	// fragment when no compatible engine is installed). This is a deterministic
	// local configuration/capability failure, not an account-health signal, so
	// oauth-group in-request failover must not route around it.
	ErrCodeAccountEgressEngine = "ACCOUNT_EGRESS_ENGINE_UNAVAILABLE"
	// ErrCodeNodeEgressEngine is ErrCodeAccountEgressEngine one layer out: the
	// NODE-level `upstream_proxy` spec could not be constructed by this build, so
	// this node has no usable egress at all. 503, and the request is REFUSED.
	//
	// 🔴 Why refusing beats degrading (decided 2026-07-31). The node egress exists
	// to make the upstream see a PARTICULAR exit. Dialing direct when the spec
	// fails is not a reduced service, it is a different one — the request leaves
	// from the node's own datacenter IP, which is the outcome the egress was
	// configured to prevent. Worse, it is invisible: the client gets 200, the
	// console stays green, and the only trace is a WARN nobody reads.
	//
	// The realistic trigger is not a typo. It is an OSS-built `aikey-proxy`
	// reaching a node that has a mihomo FRAGMENT configured — exactly the
	// enterprise-egress build failure that `make-cluster-offline-package.sh`
	// downgrades to a WARN. Under the old behavior that shipping defect had no
	// runtime symptom. Under this one it is the first thing anybody sees.
	//
	// This matches pkg/egress's own stated contract ("fails LOUDLY … never
	// silently, never out the wrong IP") and the per-account path, which has
	// refused since 2026-07-16. The node path was the last one still degrading.
	ErrCodeNodeEgressEngine = "NODE_EGRESS_ENGINE_UNAVAILABLE"
)

// ---- HealthSnapshot ----

// HealthSnapshot captures a point-in-time view of proxy health for log records.
type HealthSnapshot struct {
	Status           string  `json:"status"`
	GenerationID     int     `json:"generation_id,omitempty"`
	InflightRequests int64   `json:"inflight_requests"`
	TotalRequests    int64   `json:"total_requests"`
	TotalErrors      int64   `json:"total_errors"`
	LatencyP95Ms     float64 `json:"latency_p95_ms,omitempty"`
	VaultChangeSeq   uint64  `json:"vault_change_seq,omitempty"`
	ProxyLoadedSeq   uint64  `json:"proxy_loaded_seq,omitempty"`
	UptimeSeconds    float64 `json:"uptime_seconds,omitempty"`
}

// ---- MultiHandler ----

// MultiHandler is a slog.Handler that forwards every record to all registered
// child handlers. It enables writing structured JSON to a log file while
// simultaneously printing human-readable text to stderr.
type MultiHandler struct {
	handlers []slog.Handler
}

// NewMultiHandler returns a MultiHandler that forwards to all given handlers.
func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

// Enabled reports whether any child handler is enabled for level.
func (h *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, hh := range h.handlers {
		if hh.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle forwards rec to all child handlers that are enabled for its level.
func (h *MultiHandler) Handle(ctx context.Context, rec slog.Record) error { //nolint:gocritic // rec type is fixed by the slog.Handler interface; cannot be a pointer
	for _, hh := range h.handlers {
		if hh.Enabled(ctx, rec.Level) {
			// Clone the record so each handler gets an independent copy.
			_ = hh.Handle(ctx, rec.Clone())
		}
	}
	return nil
}

// WithAttrs returns a new MultiHandler with attrs pre-applied to all children.
func (h *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		handlers[i] = hh.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: handlers}
}

// WithGroup returns a new MultiHandler with the group applied to all children.
func (h *MultiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		handlers[i] = hh.WithGroup(name)
	}
	return &MultiHandler{handlers: handlers}
}

// ---- Logger setup ----

// SetupLogger initializes the global slog logger to write:
//   - human-readable text to stderr (for local development visibility)
//   - structured JSON Lines to logDir/current.jsonl (for machine parsing)
//
// It returns the AsyncWriter so the caller can Flush/Close it on shutdown.
// serviceName and serviceVersion are embedded in every log record.
func SetupLogger(logDir, serviceName, serviceVersion string, level slog.Level) (*AsyncWriter, error) {
	hostname, _ := os.Hostname()

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Rename built-in slog keys to match the spec field names.
			switch a.Key {
			case slog.TimeKey:
				return slog.Attr{Key: "ts", Value: a.Value}
			case slog.MessageKey:
				return slog.Attr{Key: "message", Value: a.Value}
			}
			return a
		},
	}

	// Text handler for stderr (developer-facing).
	textHandler := slog.NewTextHandler(os.Stderr, opts)

	// Async JSONL handler for the log file.
	asyncW, err := NewAsyncWriter(logDir)
	if err != nil {
		return nil, err
	}
	jsonHandler := slog.NewJSONHandler(asyncW, opts)

	// Attach common fields to both handlers.
	commonAttrs := []slog.Attr{
		slog.String("service.name", serviceName),
		slog.String("service.version", serviceVersion),
		slog.String("host.name", hostname),
		slog.Int("process.pid", os.Getpid()),
	}
	text := textHandler.WithAttrs(commonAttrs)
	json := jsonHandler.WithAttrs(commonAttrs)

	slog.SetDefault(slog.New(NewMultiHandler(text, json)))
	return asyncW, nil
}
