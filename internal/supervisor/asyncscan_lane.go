// asyncscan_lane.go — the COMPOSITION ROOT of the asynchronous deep-scan lane.
//
// 🔴 WHY THIS FILE EXISTS AT ALL.
// Every part of this lane was built and unit-tested before anything constructed
// it. asyncscan's enqueuer, local executor, placement, merge, coverage and event
// builder; deepscanfwd's forwarder, frame builder and v2 sink — all green, all
// unreachable. Measured then: NewEnqueuer 0, NewLocalExecutor 0,
// NewRemoteForwarder 0, BuildEvents 0 non-test references from outside their own
// packages. The proxy polled GET /v1/compliance/scan-nodes every 60 seconds,
// published a trusted node set, computed deepScanMode()==remote — and enqueued
// nothing, because p.asyncEnqueuer was permanently nil.
//
// Unit tests cannot see that: they construct the component and inject its
// dependencies themselves. Neither can the runtime: "no enqueuer" is
// indistinguishable from "this deployment does not scan asynchronously", which
// is a supported state on Personal and on any org without nodes.
// Fence: asyncscan_lane_wiring_test.go.
//
// WHY HERE AND NOT IN internal/proxy. The lane needs three things that only the
// supervisor has: the generation's proxy, the control-plane state the rails
// publish (node set, `sct1` token, team_async_scan), and the reporter that
// uploads events. Putting the composition in internal/proxy would mean pushing
// all three down into the data plane.
package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/cluster"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/asyncscan"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/deepscanfwd"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/pkg/deepscan"
	"github.com/AiKeyLabs/pkg/scannode"
	"github.com/AiKeyLabs/pkg/scantoken"
)

// asyncScanLane is one generation's lane. Everything in it is torn down on
// reload-drain, in the order the comments below explain.
type asyncScanLane struct {
	enqueuer *asyncscan.Enqueuer
	local    *asyncscan.LocalExecutor
	remote   *deepscanfwd.RemoteForwarder
	lru      *asyncscan.ScannedLRU
	jobs     sync.Map // job id -> deepscanfwd.PieceJob, for Merge when the result returns
	stop     chan struct{}
	done     sync.WaitGroup
	log      *slog.Logger
	// localSubmit is the door to the local executor. An indirection rather than
	// a direct lane.local.Submit call so a test can drive the ROUTING decision
	// without spawning a real detector child — the same seam LocalExecutor and
	// RemoteForwarder already expose (OnChildStopped, RejectFor). Production
	// always points it at lane.local.
	localSubmit func(deepscanfwd.PieceJob) bool
	// remoteNodes is how many nodes this generation's forwarder was built with.
	// Recorded rather than re-read: the published set can change under a rail
	// refresh, and this number describes THIS lane, which is what the log line
	// and the health section are about.
	remoteNodes int
	// remoteNodeIDs names the nodes this generation trusts, for the health
	// surface. Ids only — never addresses or fingerprints: /health is read by
	// more people than the config file is.
	remoteNodeIDs []string
}

// installAsyncScanLane builds the lane for this generation and wires it into p.
//
// Returns nil when the lane is not running, in which case p's enqueuer is
// cleared — a reload that turns the lane off must not leave the previous
// generation's hook installed.
func (s *Supervisor) installAsyncScanLane(p *proxy.Proxy, reporter *events.Reporter, spawn func() (apphook.Hook, error)) *asyncScanLane {
	// The operator kill-switch turns off compliance entirely, and the async lane
	// is part of compliance. Checked first so "off" cannot be partially honoured.
	if complianceDisabledByOperator() {
		p.SetAsyncEnqueuer(nil)
		return nil
	}
	// ── CLUSTER: the node list comes from the installer, not the control plane ──
	//
	// 🔴 A Cluster worker has no member JWT — nobody logs in on a node — so the
	// scan_nodes rail skips it by design. What it does have is a file written
	// onto the box as root by cluster-install.sh, and that is a STRONGER
	// statement than any response: the operator who deployed this fleet listed
	// these nodes and these fingerprints (design §4b.8).
	//
	// Published HERE, before deepScanMode() is asked anything, because that
	// function's answer depends on it. Without this, everything the installer
	// renders into every worker's cluster-node.env — which is precisely what
	// `--role scan` and deploy-cluster-production.sh exist to produce — lands in
	// a file nothing reads, and the whole fleet quietly scans locally.
	s.publishClusterScanNodesIfAny()

	mode := s.deepScanMode()
	if mode == DeepScanModeOff {
		p.SetAsyncEnqueuer(nil)
		return nil
	}
	// No detector to spawn ⇒ no local executor ⇒ nothing can scan a personal
	// piece, and on Personal/Trial nothing can scan anything. Rather than a lane
	// that silently drops everything, run none and say so once.
	if spawn == nil {
		p.SetAsyncEnqueuer(nil)
		slog.Info("async scan lane not installed: no detector binary for the background executor",
			"event.name", observability.EventAsyncScanExecutorSaturated)
		return nil
	}

	lane := &asyncScanLane{
		lru:  asyncscan.NewScannedLRU(envInt("AIKEY_PROXY_ASYNC_SCANNED_LRU", 4096)),
		stop: make(chan struct{}),
		log:  slog.Default(),
	}

	// ── the LOCAL executor is built unconditionally ──────────────────────────
	// 🔴 Not "only when mode==local". A personal-routed piece is scanned on this
	// machine or not at all (asyncscan.Place, rule one), and personal pieces
	// exist on every edition including a Production fleet with nodes deployed.
	// A remote-only lane would silently drop every one of them.
	lane.local = asyncscan.NewLocalExecutor(asyncscan.LocalExecutorConfig{
		QueueMax:      envInt("AIKEY_PROXY_ASYNC_QUEUE_MAX", 256),
		QueueBytes:    int64(envInt("AIKEY_PROXY_ASYNC_QUEUE_BYTES", 16<<20)),
		IdleStop:      time.Duration(envInt("AIKEY_PROXY_ASYNC_RULES_IDLE_STOP_S", 300)) * time.Second,
		DetectTimeout: time.Duration(envInt("AIKEY_PROXY_ASYNC_RULES_DETECT_TIMEOUT_MS", 2000)) * time.Millisecond,
		Logger:        lane.log,
	}, spawn)
	lane.localSubmit = lane.local.Submit

	// ── the REMOTE forwarder only when a trusted node set exists ─────────────
	nodes := s.scanNodes.Load()
	nodesReason := scannode.ReasonNoNodes
	if nodes != nil {
		nodesReason = nodes.Reason
	}
	if mode == DeepScanModeRemote && nodes != nil && len(nodes.Nodes) > 0 {
		trusted := nodes.Trusted
		lane.remote = deepscanfwd.NewRemoteForwarder(deepscanfwd.Config{
			Nodes:      nodes.Nodes,
			QueueMax:   envInt("AIKEY_PROXY_ASYNC_QUEUE_MAX", 256),
			QueueBytes: int64(envInt("AIKEY_PROXY_ASYNC_QUEUE_BYTES", 16<<20)),
			// 🔴 scannode.NewTLSSink IS the trust decision, and nothing else here
			// re-implements any part of it: https-only, the resolved IP must be in
			// a private range, and the peer certificate's SHA-256 must be in the
			// closed set this very response published. Dialing any other way would
			// send raw employee prompts to whatever answers on that address.
			DialSink: func(n scannode.Node) deepscan.Sink {
				return scannode.NewTLSSink(n, trusted,
					time.Duration(envInt("AIKEY_PROXY_DEEPSCAN_CONNECT_TIMEOUT_MS", 2000))*time.Millisecond,
					// The ACK timeout bounds how long a node may hold ONE frame.
					// Generous relative to the dial timeout on purpose: a scan of a
					// 256 KiB piece is real work (windowed bge + rule chunks), and a
					// node that is merely slow must not be counted as failed — that
					// would trip the breaker and take a working node out of rotation.
					time.Duration(envInt("AIKEY_PROXY_DEEPSCAN_ACK_TIMEOUT_MS", 30000))*time.Millisecond)
			},
			Logger: lane.log,
		})
		lane.remote.Start()
		lane.remoteNodes = len(nodes.Nodes)
		for _, n := range nodes.Nodes {
			lane.remoteNodeIDs = append(lane.remoteNodeIDs, n.ID)
		}
	}

	lane.enqueuer = asyncscan.NewEnqueuer(s.asyncSubmitFunc(lane), lane.lru)
	p.SetAsyncEnqueuer(lane.enqueuer)

	// The lane's only externally readable signal. Without it, "the lane is
	// installed and delivering", "installed and dropping everything" and "never
	// installed" are the same observation from outside the process — and the
	// first live run of the failover case spent its whole budget unable to tell
	// them apart.
	reason := string(nodesReason)
	p.SetDeepScanHealthFunc(func() *proxy.DeepScanHealth {
		return lane.health(string(mode), reason)
	})

	// The results pump is what turns a scan into a row in the org's ledger. A
	// lane without it would spend the CPU and the network and then drop the
	// finding — worse than no lane, because the coverage hole would be invisible.
	lane.done.Add(1)
	go func() {
		defer lane.done.Done()
		s.pumpAsyncResults(lane, reporter)
	}()

	slog.Info("async scan lane installed",
		"event.name", "proxy.async_scan.lane_installed",
		"mode", string(mode), "remote_nodes", remoteNodeCount(lane))
	return lane
}

// health projects the lane's live state. Cheap: read a few counters, build a
// struct. Called on every health request, so it must not take a lock the data
// plane holds.
func (l *asyncScanLane) health(mode, reason string) *proxy.DeepScanHealth {
	h := &proxy.DeepScanHealth{Mode: mode, Reason: reason, Status: "ok"}
	if l.remote != nil {
		st := l.remote.Stats()
		h.Status = st.Status
		h.EnqueuedTotal = st.Enqueued
		h.DroppedTotal = st.Dropped
		h.DroppedBytesTotal = st.DroppedBytes
		h.ForwardedTotal = st.Forwarded
		h.FailedTotal = st.Failed
		h.QueueLen = st.QueueLen
		for _, n := range l.remoteNodeIDs {
			h.Nodes = append(h.Nodes, proxy.DeepScanNodeHealth{ID: n})
		}
	}
	if l.local != nil {
		st := l.local.Stats()
		h.Rules = &proxy.AsyncRulesHealth{
			Executor:       st.Executor,
			CompletedTotal: st.Completed,
			DroppedTotal:   st.Dropped,
		}
	}
	return h
}

func remoteNodeCount(l *asyncScanLane) int {
	if l == nil || l.remote == nil {
		return 0
	}
	return l.remoteNodes
}

// asyncSubmitFunc is the whole routing decision for one committed piece.
//
// 🔴 IT MUST NOT BLOCK. It runs at the request-forwarding commit point, on the
// request goroutine. Every path below is a bounded non-blocking offer; when a
// queue is full the piece is DROPPED and counted, because a coverage hole the
// health surface can show is strictly better than latency added to a live
// request by a best-effort lane.
func (s *Supervisor) asyncSubmitFunc(lane *asyncScanLane) asyncscan.SubmitFunc {
	return func(p asyncscan.CommittedPiece, id asyncscan.RequestIdentity) bool {
		// Placement is asyncscan.Place and nothing else: that is where "a personal
		// piece never leaves this machine" and "an unrecognised team_async_scan
		// value fails closed" live. Re-deciding here would duplicate two security
		// rules in a second place, which is how one of them eventually drifts.
		placement := asyncscan.Place(p, s.teamAsyncScanMode(), s.isClusterNode())
		if placement == asyncscan.PlacementSkip {
			return false
		}

		// The already-scanned record is keyed on the WHOLE content, not on the
		// head the fast layer inspected — two requests with identical bodies are
		// one piece of work for this lane even though the fast layer saw both.
		sum := sha256.Sum256([]byte(p.Text))
		contentSHA := hex.EncodeToString(sum[:])
		if !lane.lru.Claim(contentSHA) {
			return false
		}

		job := deepscanfwd.PieceJob{
			JobID:         id.TraceID + ":" + contentSHA[:16],
			TenantID:      id.TenantID,
			AuditUnitID:   id.ScopeKey,
			ContentSHA256: contentSHA,
			Source:        p.Source,
			Text:          p.Text,
			HeadBytes:     p.HeadBytes,
			Engines:       []string{"rules", "bge"},
		}
		lane.jobs.Store(job.JobID, jobRecord{job: job, id: id, personal: p.Personal})

		switch placement {
		case asyncscan.PlacementRemote:
			if lane.remote == nil {
				// The node set went away between Place and here (a rail refresh
				// during a request). Fall back to the local executor rather than
				// dropping: the piece is already claimed and the content is on
				// this machine anyway.
				return lane.submitLocal(job)
			}
			tok := ""
			if t := s.scanToken.Load(); t != nil {
				tok = *t
			}
			if tok == "" {
				// Nodes but no token: the frame would be refused `unauthorized` by
				// every node. Scanning locally is the honest degradation.
				return lane.submitLocal(job)
			}
			frame, _ := deepscanfwd.BuildFrame(job, tok, envInt("AIKEY_PROXY_DEEPSCAN_MAX_PIECE_BYTES", 0))
			return lane.remote.Enqueue(frame)
		default:
			return lane.submitLocal(job)
		}
	}
}

// submitLocal offers a job to the on-machine executor. Nil-safe: a lane built
// without one (no detector binary) drops rather than panics, and the drop is the
// honest outcome — there is nothing on this machine that could scan it.
func (l *asyncScanLane) submitLocal(job deepscanfwd.PieceJob) bool {
	if l.localSubmit == nil {
		return false
	}
	return l.localSubmit(job)
}

type jobRecord struct {
	job deepscanfwd.PieceJob
	id  asyncscan.RequestIdentity
	// personal decides which ledger the result is filed in. It is remembered
	// here because it exists only at the commit point (CommittedPiece.Personal)
	// and never travels in the frame — a node must not learn it either.
	personal bool
}

// pumpAsyncResults drains both executors and files what they found.
func (s *Supervisor) pumpAsyncResults(lane *asyncScanLane, reporter *events.Reporter) {
	var remoteCh <-chan deepscan.ResultFrame
	if lane.remote != nil {
		remoteCh = lane.remote.Results()
	}
	localCh := lane.local.Results()
	for {
		var r deepscan.ResultFrame
		select {
		case <-lane.stop:
			return
		case r = <-localCh:
		case r = <-remoteCh:
		}
		s.fileAsyncResult(lane, reporter, r)
	}
}

// fileAsyncResult merges one result with the job that produced it and uploads
// the events.
//
// 🔴 The identity (seat, session, trace, tenant) is joined HERE, from the job
// this proxy remembered — it never travelled to the node (design §3.3). That is
// the whole reason the node uploads nothing: it does not know, and must not
// know, whose request this was.
func (s *Supervisor) fileAsyncResult(lane *asyncScanLane, reporter *events.Reporter, r deepscan.ResultFrame) {
	v, ok := lane.jobs.LoadAndDelete(r.JobID)
	if !ok {
		// A result for a job this generation does not remember: a reload happened
		// between send and answer. Counted, not filed — stamping it with a guessed
		// identity would put a finding on the wrong seat.
		slog.Warn("async scan: result for an unknown job (reload in flight?)",
			"event.name", observability.EventAsyncScanVersionSkew, "job_id", r.JobID)
		return
	}
	rec := v.(jobRecord)
	merged := asyncscan.Merge(rec.job, r, apphook.ActionBlock, apphook.ActionBlock)
	lane.lru.Finalize(rec.job.ContentSHA256)

	evs := asyncscan.BuildEvents(merged, rec.id)
	if len(evs) == 0 || reporter == nil {
		return
	}
	// The local self-view store has no scan_coverage column, so local copies use
	// the conservative encoding (no advertised features ⇒ coverage stripped).
	localPayloads := asyncscan.EncodeForMaster(evs, nil)

	// 🔴 A PERSONAL piece is filed in the employee's OWN ledger and nowhere else
	// (design §4b.6; checklist A-8.1: master 0 rows, local ledger 1 row). Until
	// 2026-09-13 every result was filed as "team": findings on content sent with a
	// personal key — tenant, seat, key id, session, trace, categories — reached
	// the organisation's master, and the local ledger got nothing. The synchronous
	// fast layer never did this; the async lane lost the flag at the commit point.
	// Same transport and dead letter as every other compliance upload.
	// bugfix: workflow/CI/bugfix/20260913-async-scan-filed-personal-findings-as-team.md
	if rec.personal {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := reporter.UploadAsyncComplianceBatch(ctx, "personal", localPayloads); err != nil {
			slog.Warn("async scan: personal findings did not reach the local ledger (dead-lettered for retry)",
				"event.name", observability.EventAsyncScanPersonalFileFailed, "error", err)
		}
		return
	}

	// EncodeForMaster strips fields the master has not advertised in
	// intake_features — a new proxy against an old master must not take the
	// batch down over an optional observability field.
	payloads := asyncscan.EncodeForMaster(evs, s.masterIntakeFeatures())
	if len(payloads) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := reporter.UploadAsyncComplianceBatch(ctx, "team", payloads); err != nil {
		// Best-effort by design: the transport dead-letters and retries. Logged
		// so a permanently failing lane is visible rather than merely quiet.
		slog.Warn("async scan: event upload failed (dead-lettered for retry)",
			"event.name", observability.EventDeepScanForwardFailed, "error", err)
	}
	// LOCAL MIRROR of team results — the same decision the synchronous fast layer
	// already implements (user 2026-09-03: team and personal detections are both
	// recorded on this machine's page), extended to this lane by user decision
	// 2026-09-13. Best-effort and after the master upload: never dead-lettered,
	// and its failure never touches the record of truth. No-op on a host without
	// a local store. See Reporter.MirrorComplianceEventsLocally.
	mctx, mcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer mcancel()
	if err := reporter.MirrorComplianceEventsLocally(mctx, "team", localPayloads); err != nil {
		slog.Warn("async scan: local mirror of team findings failed (master upload unaffected)",
			"event.name", observability.EventAsyncScanLocalMirrorFailed, "error", err)
	}
}

// Close tears the lane down on reload-drain: stop accepting, stop the pump, then
// the executors. The forwarder goes last because the pump may still be draining
// its results channel.
func (l *asyncScanLane) Close(ctx context.Context) {
	if l == nil {
		return
	}
	close(l.stop)
	l.done.Wait()
	if l.local != nil {
		_ = l.local.Close(ctx)
	}
	if l.remote != nil {
		_ = l.remote.Close(ctx)
	}
}

// teamAsyncScanMode is what the control plane last said about team content.
// Unset ⇒ off: a proxy that has never reached a master must not decide on its
// own that the organisation permits asynchronous scanning of team content.
func (s *Supervisor) teamAsyncScanMode() asyncscan.TeamAsyncScan {
	if v := s.teamAsyncScan.Load(); v != nil {
		return asyncscan.TeamAsyncScan(*v)
	}
	return asyncscan.TeamAsyncScanOff
}

// masterIntakeFeatures is what this deployment's master advertised it can store.
func (s *Supervisor) masterIntakeFeatures() []string {
	if v := s.intakeFeatures.Load(); v != nil {
		return *v
	}
	return nil
}

func envInt(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// asyncExecutorSpawn builds the background executor's OWN detector child.
//
// 🔴 ITS OWN CHILD, NEVER THE REQUEST POOL (design §3.8,
// DEC-scan-node-deepscan-15). A 256 KiB piece is ~16 chunks at ~11 ms each —
// about 180 ms of detector time (measured, baseline-forensics §F8 ②). The
// request path's per-Detect budget is around 1 ms. Sharing the pool would make
// every request that arrived during one background piece time out, flip the
// filter hook to degraded, and forward traffic UNFILTERED. The background lane
// would have switched synchronous compliance off in bursts — a compliance
// outage caused by an observability feature.
//
// Returns nil when there is no detector binary to run, which
// installAsyncScanLane treats as "no lane" rather than as a lane that silently
// drops everything.
func (s *Supervisor) asyncExecutorSpawn(vaultReader *vault.Reader) func() (apphook.Hook, error) {
	binPath, binArgs, _, _, _ := s.resolveFilterBinary(vaultReader)
	if binPath == "" {
		return nil
	}
	return func() (apphook.Hook, error) {
		cfg := s.asyncExecutorChildConfig(binPath, binArgs)
		h := apphook.NewChildHook(&cfg)
		if err := h.Start(s.ctx); err != nil {
			return nil, err
		}
		return h, nil
	}
}

// asyncReturnEventsEnv makes the background detector hand every finding back to
// the proxy and upload nothing itself (ai-compliance-detector returnEventsMode;
// exact "1" only).
const asyncReturnEventsEnv = "AIKEY_COMPLIANCE_RETURN_EVENTS=1"

// asyncExecutorChildConfig is the background detector's process configuration.
// Split out of asyncExecutorSpawn so its environment can be asserted without
// starting a process.
func (s *Supervisor) asyncExecutorChildConfig(binPath string, binArgs []string) apphook.ChildHookConfig {
	return apphook.ChildHookConfig{
		Name:       "ai-compliance-detector-async",
		BinaryPath: binPath,
		BinaryArgs: binArgs,
		// A whole piece, not a request turn: seconds, not milliseconds.
		Timeout:      time.Duration(envInt("AIKEY_PROXY_ASYNC_RULES_DETECT_TIMEOUT_MS", 2000)) * time.Millisecond,
		ReadyTimeout: filterReadyTimeout(),
		// 🔴 The SAME env scrubbing the request-path child gets, so this child
		// cannot inherit AIKEY_DEEPSCAN_SOCKET and forward every prompt to the
		// on-machine daemon a second time — the same content scanned twice and
		// uploaded twice, by two senders whose event ids cannot collide.
		//
		// 🔴 PLUS return-events mode: this private pool must never upload on its
		// own. The proxy is the only party that knows the seat, session and trace
		// of a piece, so it is the only filer; a child that also uploaded would put
		// a second, unattributed copy of every finding in a ledger. The detector's
		// own doc names the proxy as the party that sets it; until 2026-09-13 only
		// the scan node's pool (workers) did.
		ExtraEnv: append(s.filterChildEnv("", ""), asyncReturnEventsEnv),
	}
}

// publishClusterScanNodesIfAny loads the installer-rendered node list on a
// Cluster worker and publishes it as this proxy's trusted set.
//
// No-op everywhere else: on Personal there is no control plane and no rendered
// file, and on Production the rail owns the set. Calling it unconditionally
// keeps the decision in ONE place (isClusterNode) rather than at each caller.
func (s *Supervisor) publishClusterScanNodesIfAny() {
	if !s.isClusterNode() {
		return
	}
	env := map[string]string{
		cluster.EnvScanNodeAddrs:        os.Getenv(cluster.EnvScanNodeAddrs),
		cluster.EnvScanNodeFingerprints: os.Getenv(cluster.EnvScanNodeFingerprints),
		cluster.EnvScanTokenKeyFile:     os.Getenv(cluster.EnvScanTokenKeyFile),
	}
	set, err := cluster.LoadRenderedScanNodes(env)
	if err != nil {
		// LoadRenderedScanNodes already logged the specific inconsistency (and
		// returns an empty, untrusting set). Publishing it anyway is deliberate:
		// the alternative is leaving a PREVIOUS generation's set live after the
		// operator edited the file into a state we refuse.
		slog.Warn("cluster scan nodes refused; this worker will deep-scan locally",
			"event.name", observability.EventScanNodeUntrustedFingerprint, "error", err)
	}
	s.publishScanNodes(set)

	// On a Cluster worker the rendered list IS the instruction: a non-empty list
	// means team content may go to those nodes. There is no control-plane value
	// to consult, and defaulting to `off` here would make the rendered list
	// inert — which is the bug this function exists to fix, one layer up.
	mode := string(asyncscan.TeamAsyncScanOff)
	if len(set.Nodes) > 0 {
		mode = string(asyncscan.TeamAsyncScanNodes)
	}
	s.teamAsyncScan.Store(&mode)

	// The token is MINTED LOCALLY on a cluster node (single tenant; the worker
	// and the scan nodes share one trust domain and one key file), rather than
	// fetched from a control plane the worker cannot authenticate to.
	if tok := s.mintClusterScanToken(); tok != "" {
		s.scanToken.Store(&tok)
	}
}

// mintClusterScanToken signs a short-lived token with the key the installer
// placed on this box. Empty when there is no key file — in which case the
// forwarder has nodes but no credential, and asyncSubmitFunc falls back to the
// local executor rather than sending frames every node will refuse.
func (s *Supervisor) mintClusterScanToken() string {
	path := strings.TrimSpace(os.Getenv(cluster.EnvScanTokenKeyFile))
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-installed path
	if err != nil {
		slog.Warn("cluster scan token key unreadable; remote deep scan disabled on this worker",
			"event.name", observability.EventScanNodeUntrustedFingerprint, "path", path, "error", err)
		return ""
	}
	ks, err := scantoken.ParseKeySet(raw)
	if err != nil {
		slog.Warn("cluster scan token key file is malformed; remote deep scan disabled on this worker",
			"event.name", observability.EventScanNodeUntrustedFingerprint, "path", path, "error", err)
		return ""
	}
	org := strings.TrimSpace(s.cfg.Cluster.OrgID)
	if org == "" {
		return ""
	}
	return scantoken.Mint(ks.Current, org, time.Now())
}
