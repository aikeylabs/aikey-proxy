package mcp

// localpublish.go — P14 task 14.0/14.4. Where Personal edition's tool list
// comes from.
//
// # The gap this closes
//
// Until this file, `BuildLocalPolicy` emitted a toolset with `Tools: []` and
// nothing ever filled it. The manifest syncer DID reach each hosted backend and
// DID read its tools — and then, on a node with no control plane, threw the
// answer away: `syncBackend` returns early when `reporter == nil`.
//
// So `/mcp/local` served `{"tools": []}` on every Personal install. The chain
// was never noticed because P5's end-to-end case runs
// `config → policy → transport.ListTools` and BYPASSES the catalog, and because
// no real MCP client had ever connected — the two halves of one blind spot.
//
// bugfix: workflow/CI/bugfix/20260902-personal-mcp-local-served-an-empty-tool-list.md
// regression fence: `make -C workflow/CI verify-mcp-local-review` drills L1/L2
//
// 🔴 It matters most for adoption (P14): after `aikey mcp adopt` rewrites the
// developer's client config to point at the gateway, an empty toolset means
// every tool they had disappears. That is exactly the outcome R21 argues
// against ("最小权限 → 收纳当场失败"), reached by a different road.
//
// # The shape, and why this one
//
// 🔴 A PUBLISHER symmetric to `ManifestReporter`, not a second read path.
//
//	Production   proxy observes → REPORTS upward → control plane decides → policy
//	Personal     proxy observes → PUBLISHES into the local policy → same policy
//
// Either way the tools arrive as rows in the SAME `Policy` snapshot, read by the
// SAME `PolicyCatalog`, subject to the SAME grant evaluation and the SAME
// freeze rule. The rejected alternative — letting Personal's catalog read the
// syncer's observations directly — is shorter and gives Personal a read path
// that only it has, so every rule living in `PolicyCatalog` would have to be
// re-derived there. The first one anybody forgot would be a security rule that
// silently does not apply on the edition where the tools run on the user's own
// machine.
//
// # Who plays the reviewer
//
// On Production a human adopts or rejects a manifest. Personal has no console,
// so the rules are fixed here and are deliberately the ones R21 sets for
// adoption:
//
//	first sight of a tool   → auto_admitted, write_op = TRUE
//	upstream hash changed   → the APPROVED definition keeps being served, and the
//	                          tool goes needs_review (write tools freeze, R3)
//	tool stops arriving     → not served; its approval row is kept, so an
//	                          upstream that comes back unchanged is not re-admitted
//	                          as if it were new
//
// 🔴 `write_op = true` by default, never from the upstream's `readOnlyHint`
// (I4c): the upstream is the party this defends against. The asymmetry argument
// for that default — "a write marked read-only is dangerous, a read-only marked
// write is merely inconvenient" — only holds while the inconvenience is
// RECOVERABLE. On Personal it is recoverable through `aikey mcp review`, which
// is why that command is part of this change rather than a later one.
//
// # Why the approvals are on disk
//
// The approved fingerprint is not a cache: it is the answer to "what did this
// server look like when the user accepted it". Keeping it in memory would mean
// every proxy restart re-baselines against whatever the upstream serves at that
// moment — so a poisoned update that landed while the proxy was stopped would
// be adopted silently, and the detector would record the attack as the new
// normal. It therefore lives beside `mcp.json` and the vault in ~/.aikey,
// 🚫 NOT under the run directory, which is allowed to be deleted (fence 2.F5
// deletes the policy cache on purpose).
//
// 🔴 A read failure yields an EMPTY baseline and a loud WARN, never a silent
// one: an empty baseline re-admits everything, which is the pre-P14 behaviour
// and therefore not a regression — but it is also exactly the state an attacker
// would want, so it must never happen quietly.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// LocalManifestFilename is the approval record's name. It sits in the same
// directory as `mcp.json`.
const LocalManifestFilename = "mcp-manifest.json"

// localManifestVersion is the on-disk schema version. Present so a future
// change can migrate rather than guess; an unknown version is refused rather
// than reinterpreted.
//
// v2 (P14 task 14.3) added the first-review gate. A v1 record is MIGRATED, not
// refused: its backends were already serving their tools, so they are marked
// reviewed. 🔴 Refusing it would hide every tool on an existing install behind a
// review the user never knew they owed — an upgrade that silently disconnects
// somebody's Agent is the worst way to introduce a gate.
const localManifestVersion = 2

// LocalManifestPath resolves the approval record beside the local config.
//
// 🔴 Derived from LocalConfigPath rather than resolved independently, so
// relocating the config with AIKEY_MCP_CONFIG carries the approvals with it. A
// config that moved and approvals that did not would re-admit every tool on the
// next probe, with nothing in the logs to say why.
func LocalManifestPath() (string, error) {
	cfg, err := LocalConfigPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), LocalManifestFilename), nil
}

// ApprovedTool is one tool as the user has accepted it.
type ApprovedTool struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description"`
	InputSchema string `json:"input_schema"`
	// Hash is the PUBLISHED fingerprint — the thing drift is measured against.
	Hash string `json:"hash"`
	// WriteOp is what a freeze does to this tool. 🔴 Never taken from the
	// upstream's own annotations.
	WriteOp bool `json:"write_op"`
	// FirstSeenMs is when this tool first appeared, for display.
	FirstSeenMs int64 `json:"first_seen_ms"`
	// Rejected marks a tool a human looked at and did NOT publish.
	//
	// 🔴 Recorded rather than deleted. A deleted row is re-admitted as brand new
	// on the very next probe, so "I decided not to expose this one" would last
	// five minutes — and the second time it appeared, nothing would say a human
	// had already turned it down.
	Rejected bool `json:"rejected,omitempty"`
	// AddedAfterSetup answers "did this show up AFTER I set this server up" —
	// the question `aikey mcp review` puts in front of the user.
	//
	// 🔴 Recorded as a FACT at admission, 🚫 not derived by comparing
	// FirstSeenMs with the backend's baseline time. The first version did
	// derive it, and two probes inside the same millisecond made a genuine
	// later arrival read as part of the baseline — a capability expansion
	// rendered as "always been there", decided by clock resolution.
	AddedAfterSetup bool `json:"added_after_setup,omitempty"`
}

// ApprovedBackend is every tool approved for one backend.
type ApprovedBackend struct {
	// BaselinedAtMs is when this backend was first successfully probed. Tools
	// with FirstSeenMs greater than this appeared later.
	BaselinedAtMs int64 `json:"baselined_at_ms"`
	// ReviewedAtMs is when a human first looked at this backend's tools.
	// 🔴 Zero means NOBODY HAS, and until somebody does, none of its tools are
	// served (task 14.3a/14.3b).
	//
	// Why a gate exists at all when drift detection already runs: drift can only
	// notice that a manifest CHANGED. It cannot notice that a server was
	// malicious on the first day — the poisoned description simply becomes the
	// pinned baseline, and the detector never sees it again (D-20). The first
	// look is the only chance.
	ReviewedAtMs int64                    `json:"reviewed_at_ms,omitempty"`
	Tools        map[string]*ApprovedTool `json:"tools"`
}

type approvalRecord struct {
	Version  int                         `json:"version"`
	Backends map[string]*ApprovedBackend `json:"backends"`
}

// PendingChange is a drift waiting for the user, held in memory only.
//
// 🔴 Not persisted: it is re-derived from the upstream on every probe, and
// persisting it would create a second thing that can be stale. What IS
// persisted is the approval — the thing that must survive.
type PendingChange struct {
	BackendID string
	Name      string
	// Approved is what is being served right now.
	Approved ApprovedTool
	// Observed is what the upstream says today. 🔴 Both are handed to the user
	// in full, because a poisoned description is the attack and showing only the
	// tool name is the same as showing nothing (14.3d).
	Observed ObservedTool
}

// LocalPublisher turns observations into the local policy.
type LocalPublisher struct {
	mu       sync.Mutex
	path     string
	store    *PolicyStore
	logger   *slog.Logger
	now      func() time.Time
	rec      approvalRecord
	pending  map[string]map[string]PendingChange // backend → tool → change
	observed map[string]map[string]ObservedTool  // backend → tool → what upstream says now
	// loadErr records a failed read so the health surface can say so rather
	// than presenting an empty baseline as a clean one.
	loadErr string
}

// NewLocalPublisher loads the approval record and returns a publisher.
//
// 🔴 Never returns an error. A publisher that refused to start would leave the
// toolset empty, which is the very failure this file exists to remove; the read
// problem is surfaced instead (WARN + LoadError) so it is visible without being
// fatal.
func NewLocalPublisher(path string, store *PolicyStore, logger *slog.Logger) *LocalPublisher {
	if logger == nil {
		logger = slog.Default()
	}
	p := &LocalPublisher{
		path: path, store: store, logger: logger, now: time.Now,
		rec:      approvalRecord{Version: localManifestVersion, Backends: map[string]*ApprovedBackend{}},
		pending:  map[string]map[string]PendingChange{},
		observed: map[string]map[string]ObservedTool{},
	}
	p.load()
	return p
}

func (p *LocalPublisher) load() {
	raw, err := os.ReadFile(p.path) //nolint:gosec // path derived from the config path, never from request input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return // first run; an empty baseline is correct here.
		}
		p.loadErr = err.Error()
		// 🔴 ERROR, not Warn: continuing means re-admitting every tool at
		// whatever the upstream serves next, and that must never be quiet.
		p.logger.Error("MCP local manifest approvals could not be read; every tool will be re-admitted at its CURRENT upstream definition",
			"event.name", observability.EventProxyMCPLocalManifestUnreadable,
			"path", p.path, "error", err)
		return
	}
	var rec approvalRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		p.loadErr = err.Error()
		p.logger.Error("MCP local manifest approvals are not valid JSON; every tool will be re-admitted at its CURRENT upstream definition",
			"event.name", observability.EventProxyMCPLocalManifestUnreadable,
			"path", p.path, "error", err)
		return
	}
	switch rec.Version {
	case localManifestVersion:
		// current
	case 1:
		// 🔴 v1 predates the first-review gate. Its backends were already
		// serving, so they are marked reviewed at their baseline time. Treating
		// them as unreviewed would make an upgrade hide every tool on the
		// machine behind a review the user never knew they owed.
		for _, ab := range rec.Backends {
			if ab != nil && ab.ReviewedAtMs == 0 {
				ab.ReviewedAtMs = ab.BaselinedAtMs
			}
		}
		p.logger.Info("MCP local manifest approvals migrated to the current schema; backends that were already serving are treated as reviewed",
			"event.name", observability.EventProxyMCPLocalManifestMigrated,
			"path", p.path, "from", rec.Version, "to", localManifestVersion,
			"backends", len(rec.Backends))
	default:
		p.loadErr = fmt.Sprintf("unknown schema version %d", rec.Version)
		p.logger.Error("MCP local manifest approvals carry a schema version this build does not know; they are being ignored",
			"event.name", observability.EventProxyMCPLocalManifestUnreadable,
			"path", p.path, "version", rec.Version, "supported", localManifestVersion)
		return
	}
	if rec.Backends == nil {
		rec.Backends = map[string]*ApprovedBackend{}
	}
	p.rec = rec
}

// LoadError is non-empty when the approval record could not be read.
//
// 🔴 Exposed so the health surface can distinguish "nothing has been approved
// yet" from "we could not read what was approved". Collapsing them would let a
// corrupt file look like a fresh install.
func (p *LocalPublisher) LoadError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.loadErr
}

// Publish implements ManifestPublisher.
func (p *LocalPublisher) Publish(_ context.Context, m ObservedManifest) {
	p.mu.Lock()
	changed := p.absorb(m)
	if changed {
		p.writeApprovalsLocked()
	}
	policy := p.rebuildLocked()
	p.mu.Unlock()

	if policy != nil {
		p.store.Store(policy)
	}
}

// absorb folds one observation into the approval record. Returns whether the
// record changed and therefore needs writing.
func (p *LocalPublisher) absorb(m ObservedManifest) bool {
	now := p.now().UnixMilli()
	ab := p.rec.Backends[m.BackendID]
	changed := false
	// 🔴 "Is this the batch that established the baseline?" — captured before
	// anything is admitted, because that is the only moment it is knowable.
	baselineBatch := ab == nil
	if ab == nil {
		ab = &ApprovedBackend{BaselinedAtMs: now, Tools: map[string]*ApprovedTool{}}
		p.rec.Backends[m.BackendID] = ab
		changed = true
	}
	if ab.Tools == nil {
		ab.Tools = map[string]*ApprovedTool{}
	}

	pend := map[string]PendingChange{}
	obs := map[string]ObservedTool{}
	for _, t := range m.Tools {
		obs[t.Name] = t
		at := ab.Tools[t.Name]
		if at == nil {
			// 🔴 Admitted, not queued. The user installed this server
			// themselves; on an edition with no console, holding its tools back
			// would leave them no way to release them (R21's equivalence
			// migration, applied to the edition where the user IS the
			// administrator).
			ab.Tools[t.Name] = &ApprovedTool{
				Name: t.Name, Title: t.Title, Description: t.Description,
				InputSchema: t.InputSchema, Hash: t.Hash,
				// 🔴 write_op TRUE. Not from t.Annotations — see the file header.
				WriteOp:         true,
				FirstSeenMs:     now,
				AddedAfterSetup: !baselineBatch,
			}
			changed = true
			continue
		}
		if at.Hash != t.Hash {
			// 🔴 The approved definition is NOT overwritten. Overwriting is how
			// a detector records an attack as the new normal and never sees it
			// again.
			pend[t.Name] = PendingChange{BackendID: m.BackendID, Name: t.Name, Approved: *at, Observed: t}
		}
	}
	p.pending[m.BackendID] = pend
	p.observed[m.BackendID] = obs
	return changed
}

// rebuildLocked recomputes the local toolset from the approval record.
func (p *LocalPublisher) rebuildLocked() *Policy {
	base := p.store.Snapshot()
	if base == nil {
		return nil
	}
	policy := *base
	// Copy the toolsets so the snapshot the catalog is currently serving is not
	// mutated underneath it.
	policy.Toolsets = make([]PolicyToolset, len(base.Toolsets))
	copy(policy.Toolsets, base.Toolsets)

	var tools []PolicyTool
	// 🔴 Backend order comes from the POLICY, which comes from the order the
	// user wrote them in mcp.json. That makes the name-collision rule below
	// deterministic and explainable ("the first server in your file keeps the
	// name") instead of depending on Go's map iteration.
	for _, b := range base.Backends {
		ab := p.rec.Backends[b.ID]
		if ab == nil {
			continue
		}
		if ab.ReviewedAtMs == 0 {
			// 🔴 Task 14.3b: nothing from a backend nobody has looked at reaches
			// any toolset. Not hidden from the CONSOLE — there isn't one — but
			// absent from the policy, so the catalog, the grant evaluation and
			// tools/list all agree without any of them learning about drafts.
			continue
		}
		obs := p.observed[b.ID]
		pend := p.pending[b.ID]
		names := make([]string, 0, len(ab.Tools))
		for n := range ab.Tools {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if ab.Tools[n].Rejected {
				// A human looked at this one and said no. It stays out, and it
				// stays out on every future probe.
				continue
			}
			if _, stillThere := obs[n]; !stillThere {
				// 🔴 A tool that stopped arriving is a FACT, not a verdict: it
				// is simply not served. Its approval row is kept, so if the same
				// definition comes back it is not re-admitted as though it were
				// new.
				continue
			}
			at := ab.Tools[n]
			state := ToolStateAutoAdmitted
			if _, drifted := pend[n]; drifted {
				state = ToolStateNeedsReview
			}
			tools = append(tools, PolicyTool{
				ID:           b.ID + "/" + n,
				BackendID:    b.ID,
				Name:         n,
				Title:        at.Title,
				Description:  at.Description,
				InputSchema:  at.InputSchema,
				ManifestHash: at.Hash,
				State:        state,
				WriteOp:      at.WriteOp,
			})
		}
	}
	p.disambiguateLocked(tools)

	for i := range policy.Toolsets {
		if policy.Toolsets[i].Slug == LocalToolsetSlug {
			policy.Toolsets[i].Tools = tools
		}
	}
	// Any monotonic value; nothing polls this on Personal, but the catalog's
	// index is rebuilt from it and a stale version would be confusing in logs.
	policy.Version = p.now().UnixMilli()
	policy.GeneratedAtMs = policy.Version
	return &policy
}

// disambiguateLocked gives a colliding tool name a backend-qualified alias.
//
// 🔴 Two backends may legitimately both expose `search`. Left alone, the
// catalog's call resolution takes the FIRST match, so calling `search` would
// silently reach the wrong server — with the user's credential for that server.
// That is a wrong-target execution, not a naming annoyance.
//
// The first backend in the user's own config keeps the plain name so adoption
// stays an equivalence migration for it; later ones are exposed as
// `<backend>__<tool>`. Both are named in a WARN, because a tool that quietly
// changed name is a tool their Agent can no longer call.
func (p *LocalPublisher) disambiguateLocked(tools []PolicyTool) {
	seen := map[string]string{} // effective name → backend that holds it
	for i := range tools {
		t := &tools[i]
		if owner, taken := seen[t.Name]; taken {
			t.Alias = t.BackendID + "__" + t.Name
			p.logger.Warn("two MCP backends expose a tool with the same name; the second one is exposed under a qualified name",
				"event.name", observability.EventProxyMCPLocalToolNameCollision,
				"tool", t.Name, "kept_by", owner, "renamed_backend", t.BackendID,
				"exposed_as", t.Alias)
			seen[t.Alias] = t.BackendID
			continue
		}
		seen[t.Name] = t.BackendID
	}
}

// writeApprovalsLocked saves the approval record.
//
// 🔴 The name is deliberate and 🚫 must not be shortened back to `persistLocked`.
// The hot-path call-graph fence resolves callees by NAME, so a method called
// `persistLocked` here joins the graph of internal/proxy's own
// `poolCooldownStore.persistLocked` — which IS on the forwarding path — and this
// file's writes get reported as new file I/O in the request path. The same
// remedy was applied once before, when `persist` collided with
// `lastErrorsRing.persist`; baselining the false positive instead would make the
// fence's inventory describe something that is not there.
func (p *LocalPublisher) writeApprovalsLocked() {
	p.rec.Version = localManifestVersion
	body, err := json.MarshalIndent(p.rec, "", "  ")
	if err != nil {
		p.logger.Warn("MCP local manifest approvals could not be encoded; they will be re-derived on the next probe",
			"event.name", observability.EventProxyMCPLocalManifestUnwritable, "error", err)
		return
	}
	if dir := filepath.Dir(p.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			p.logger.Warn("MCP local manifest approvals could not be written",
				"event.name", observability.EventProxyMCPLocalManifestUnwritable, "path", p.path, "error", err)
			return
		}
	}
	tmp := p.path + ".tmp"
	// 0600: it names the tools an Agent may run on this machine.
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		p.logger.Warn("MCP local manifest approvals could not be written",
			"event.name", observability.EventProxyMCPLocalManifestUnwritable, "path", tmp, "error", err)
		return
	}
	if err := os.Rename(tmp, p.path); err != nil {
		_ = os.Remove(tmp)
		p.logger.Warn("MCP local manifest approvals could not be replaced",
			"event.name", observability.EventProxyMCPLocalManifestUnwritable, "path", p.path, "error", err)
	}
}

// ---------------------------------------------------------------------------
// what `aikey mcp review` reads and writes
// ---------------------------------------------------------------------------

// ReviewTool is one row of the review surface.
type ReviewTool struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	WriteOp bool   `json:"write_op"`
	// State is auto_admitted or needs_review.
	State string `json:"state"`
	// NewSinceSetup is true when the tool appeared AFTER the backend was first
	// probed. 🔴 Surfaced rather than gated: on this edition hiding it would
	// leave the user no way to release it, so it is admitted and made visible.
	NewSinceSetup bool `json:"new_since_setup"`
	// ServedDescription is what an Agent sees today (the approved text).
	ServedDescription string `json:"served_description"`
	// UpstreamDescription is what the backend says now. Only set when they
	// differ — that difference IS the attack surface (14.3d).
	UpstreamDescription string `json:"upstream_description,omitempty"`
	// NotServed marks a tool the upstream has stopped offering.
	NotServed bool `json:"not_served"`
	// Rejected marks a tool a human turned down at review.
	Rejected bool `json:"rejected,omitempty"`
}

// ReviewBackend groups the rows.
type ReviewBackend struct {
	BackendID     string `json:"backend_id"`
	BaselinedAtMs int64  `json:"baselined_at_ms"`
	// AwaitingFirstReview is true while nobody has looked at this backend yet.
	// 🔴 None of its tools are being served while this is true (14.3b), and the
	// review screen leads with it — a user whose Agent has no tools needs the
	// reason on the first line, not buried in a list.
	AwaitingFirstReview bool         `json:"awaiting_first_review"`
	Tools               []ReviewTool `json:"tools"`
}

// Review renders the whole approval state for the CLI.
func (p *LocalPublisher) Review() []ReviewBackend {
	p.mu.Lock()
	defer p.mu.Unlock()

	ids := make([]string, 0, len(p.rec.Backends))
	for id := range p.rec.Backends {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]ReviewBackend, 0, len(ids))
	for _, id := range ids {
		ab := p.rec.Backends[id]
		rb := ReviewBackend{
			BackendID:           id,
			BaselinedAtMs:       ab.BaselinedAtMs,
			AwaitingFirstReview: ab.ReviewedAtMs == 0,
		}
		names := make([]string, 0, len(ab.Tools))
		for n := range ab.Tools {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			at := ab.Tools[n]
			row := ReviewTool{
				Name: n, Title: at.Title, WriteOp: at.WriteOp,
				State:             ToolStateAutoAdmitted,
				NewSinceSetup:     at.AddedAfterSetup,
				ServedDescription: at.Description,
				Rejected:          at.Rejected,
			}
			if ab.ReviewedAtMs == 0 {
				// 🔴 `draft` is the control plane's word for exactly this state,
				// reused rather than invented: "recorded, never reviewed, not
				// exposed". Two names for one state is how the console and the
				// CLI come to disagree about what a user is looking at.
				row.State = ToolStateDraft
			}
			if _, ok := p.observed[id][n]; !ok {
				row.NotServed = true
			}
			if ch, drifted := p.pending[id][n]; drifted {
				row.State = ToolStateNeedsReview
				row.UpstreamDescription = ch.Observed.Description
			}
			rb.Tools = append(rb.Tools, row)
		}
		out = append(out, rb)
	}
	return out
}

// ErrNothingToAccept means the named backend has nothing waiting for a human.
var ErrNothingToAccept = errors.New("mcp: nothing is waiting for review on that backend")

// ErrUnknownBackend means the approval record has never heard of it.
var ErrUnknownBackend = errors.New("mcp: no such backend")

// AcceptResult says what one human decision changed.
type AcceptResult struct {
	// FirstReview is true when this was the backend's first look, so its tools
	// went from "not served at all" to serving.
	FirstReview bool
	Published   int
	Rejected    int
	Repinned    int
}

// Accept records that a human looked at a backend and said go ahead.
//
// 🔴 ONE verb for the two things a human is ever asked here, because they are
// one decision — "I have read this and I accept it":
//
//	first review  → the backend's tools start being served (task 14.3a-c)
//	drift         → the changed definitions are re-pinned
//
// 🚫 Two endpoints would mean the caller has to know which state it is in
// before it can act, and get it wrong the moment a backend drifts before its
// first review.
//
// `exclude` is the deselection. 🔴 Task 14.3c: adoption presents everything
// SELECTED and the human looks for anything obviously wrong — ticking forty
// boxes is a review heavy enough to make people abandon adoption entirely,
// which trades a first-order security property for a third-order one and gets
// neither. Excluded tools are recorded as rejected, not deleted, so they do not
// come back as new on the next probe.
func (p *LocalPublisher) Accept(backendID string, exclude []string) (AcceptResult, error) {
	p.mu.Lock()
	ab := p.rec.Backends[backendID]
	if ab == nil {
		p.mu.Unlock()
		return AcceptResult{}, ErrUnknownBackend
	}
	pend := p.pending[backendID]
	first := ab.ReviewedAtMs == 0
	if !first && len(pend) == 0 {
		p.mu.Unlock()
		return AcceptResult{}, ErrNothingToAccept
	}

	res := AcceptResult{FirstReview: first}
	excluded := map[string]bool{}
	for _, n := range exclude {
		excluded[n] = true
	}

	if first {
		ab.ReviewedAtMs = p.now().UnixMilli()
		for name, at := range ab.Tools {
			if excluded[name] {
				at.Rejected = true
				res.Rejected++
				continue
			}
			// 🔴 Re-accepting later must not silently un-reject something a
			// human turned down; only an explicit publish of that name does.
			if at.Rejected {
				continue
			}
			res.Published++
		}
	}

	for name, ch := range pend {
		at := ab.Tools[name]
		if at == nil || excluded[name] {
			continue
		}
		at.Title = ch.Observed.Title
		at.Description = ch.Observed.Description
		at.InputSchema = ch.Observed.InputSchema
		at.Hash = ch.Observed.Hash
		// 🔴 write_op is NOT reset by accepting a new version. It is the user's
		// classification of what the tool DOES, and an upstream edit is not a
		// reason to forget it — least of all when the upstream is the party we
		// are guarding against.
		res.Repinned++
	}
	p.pending[backendID] = map[string]PendingChange{}
	p.writeApprovalsLocked()
	policy := p.rebuildLocked()
	p.mu.Unlock()

	if policy != nil {
		p.store.Store(policy)
	}
	if res.FirstReview {
		p.logger.Info("MCP local backend passed its first review",
			"event.name", observability.EventProxyMCPLocalManifestPublished,
			"backend_id", backendID, "published", res.Published, "rejected", res.Rejected)
	}
	if res.Repinned > 0 {
		p.logger.Info("MCP local manifest change accepted",
			"event.name", observability.EventProxyMCPLocalManifestAccepted,
			"backend_id", backendID, "tools", res.Repinned)
	}
	return res, nil
}

// ErrNoSuchTool means the backend or tool is not in the approval record.
var ErrNoSuchTool = errors.New("mcp: no such tool")

// SetWriteOp records the user's classification of one tool (14.3e/14.3f).
func (p *LocalPublisher) SetWriteOp(backendID, tool string, writeOp bool) error {
	p.mu.Lock()
	ab := p.rec.Backends[backendID]
	if ab == nil || ab.Tools[tool] == nil {
		p.mu.Unlock()
		return ErrNoSuchTool
	}
	ab.Tools[tool].WriteOp = writeOp
	p.writeApprovalsLocked()
	policy := p.rebuildLocked()
	p.mu.Unlock()

	if policy != nil {
		p.store.Store(policy)
	}
	return nil
}
