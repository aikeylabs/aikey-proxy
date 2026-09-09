package mcp

// localconfig.go — P5. Where Personal edition's MCP policy comes from.
//
// # The problem this solves
//
// Personal has no control plane: no org, no seats, no grants, and therefore
// nothing on the policy rail. Until now that meant the MCP plane did not mount
// at all — which is correct for a gateway that cannot authorise anyone, and
// wrong for the edition the design calls stdio hosting's PRIMARY form (§5.3).
//
// # The design decision, stated plainly
//
// 🔴 A local config file is a second PRODUCER of the same Policy snapshot, not
// a second policy MODEL. It is translated into exactly the structure the
// control plane produces, stored in the same PolicyStore, and read by the same
// PolicyCatalog.
//
// That choice is the whole point. The alternative — a `LocalCatalog`
// implementing the Catalog interface directly — looks simpler and is the
// dangerous one: the freeze rule (R3), the per-call grant re-evaluation (R8),
// the disabled-backend filter and the drift bookkeeping all live in
// PolicyCatalog, and a second implementation would have to re-derive every one
// of them. The first one anybody forgot would be a security rule that silently
// does not apply on the edition where the tools run on the user's own machine.
//
// ⇒ ONE catalog, one authorisation path, two producers. Personal gets less
// CONFIGURATION, never fewer CHECKS.
//
// # What Personal genuinely does not have
//
// Grants. There is one user, and asking them to grant themselves access would
// be ceremony with no decision in it (交互简洁性优先). So the translation emits
// a grant covering the local identity — 🔴 an EXPLICIT row in the policy, not a
// special case in the evaluator. The evaluator stays identical across editions;
// what differs is the data it is given. A `if personal { allow }` branch in the
// authorisation path is exactly the thing that eventually gets reached from
// somewhere else.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LocalConfigFilename is the file Personal edition reads.
//
// It lives beside the vault in ~/.aikey rather than in the run directory,
// because it is CONFIGURATION the user authored (via `aikey mcp add`) and must
// survive everything the run directory is allowed to lose.
const LocalConfigFilename = "mcp.json"

// LocalToolsetSlug is the single toolset Personal exposes.
//
// 🔴 A frozen public contract: it is the path a developer types into their
// client config (`http://127.0.0.1:27200/mcp/local`), so renaming it silently
// breaks every machine that already has it — the same rule the design states
// for toolset slugs generally.
const LocalToolsetSlug = "local"

// LocalBackend is one locally-hosted MCP server, as the user configured it.
type LocalBackend struct {
	// Name is the display name and the id. One namespace, because a local file
	// a human edits should not make them invent two.
	Name string `json:"name"`

	// Command / Args are what gets executed.
	//
	// 🔴 There is no `env` map here, and its absence is the feature: a config
	// file with an env map is where the credential ends up, which is the exact
	// thing this product exists to stop. Secrets are referenced BY ALIAS below
	// and live in the vault.
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`

	// CredentialAlias names a secret in the local vault. Empty = no credential.
	CredentialAlias string `json:"credential_alias,omitempty"`
	// CredentialEnv is the environment variable the secret is injected as
	// (for example PGPASSWORD). Required when CredentialAlias is set.
	CredentialEnv string `json:"credential_env,omitempty"`

	// Disabled keeps a backend in the file while switching it off, so a user
	// can stop one without losing how it was configured.
	Disabled bool `json:"disabled,omitempty"`
}

// LocalConfig is the whole file.
type LocalConfig struct {
	Backends []LocalBackend `json:"backends"`
}

// LocalConfigPath resolves the config location.
//
// 🔴 It MUST land beside vault.db, because this file references credentials by
// vault alias: a config the CLI writes in one place and the proxy reads from
// another produces a gateway that silently hosts nothing, with both sides
// reporting success. So the resolution is deliberately identical to how this
// proxy finds every other ~/.aikey artifact — os.UserHomeDir() — and to the
// CLI's own resolve_aikey_dir(). 🚫 No third convention: an earlier draft of
// this function honoured an $AIKEY_HOME variable that nothing else in either
// codebase reads, which would have relocated the config away from the vault on
// exactly the installs that set it.
//
// AIKEY_MCP_CONFIG overrides the whole path. It exists for tests and for a
// relocated install, is spelled the same in the Rust CLI, and is the ONLY
// override either side honours. Fence: the CLI's
// mcp_config_path_matches_the_proxy test.
func LocalConfigPath() (string, error) {
	if p := os.Getenv("AIKEY_MCP_CONFIG"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aikey", LocalConfigFilename), nil
}

// ErrNoLocalConfig means the file is absent — the normal state for a user who
// has never run `aikey mcp add`.
//
// 🔴 A distinct sentinel rather than an empty config, because the two must
// produce different behaviour: absent means "do not mount the plane at all"
// (a plain 404 is the truthful answer), while present-and-empty means "the user
// removed their last backend" and should still serve an empty toolset, so their
// client reports zero tools instead of a broken endpoint.
var ErrNoLocalConfig = errors.New("mcp: no local MCP config")

// LoadLocalConfig reads and validates the file.
func LoadLocalConfig(path string) (*LocalConfig, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path derived from AIKEY_HOME/$HOME, never from request input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoLocalConfig
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg LocalConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		// 🔴 Named file + parse error, because this is a file the USER edited by
		// hand or via the CLI, and "invalid character '}' looking for beginning
		// of object key" is only actionable if you know which file it is in.
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	seen := map[string]bool{}
	for i := range cfg.Backends {
		b := &cfg.Backends[i]
		b.Name = strings.TrimSpace(b.Name)
		if b.Name == "" {
			return nil, fmt.Errorf("%s: backend #%d has no name", path, i+1)
		}
		if seen[b.Name] {
			// Two backends with one name would make `aikey mcp remove <name>`
			// ambiguous and would collide in the tool namespace.
			return nil, fmt.Errorf("%s: two backends are both named %q", path, b.Name)
		}
		seen[b.Name] = true
		if strings.TrimSpace(b.Command) == "" {
			return nil, fmt.Errorf("%s: backend %q has no command", path, b.Name)
		}
		// 🔴 An alias without a variable name is refused HERE rather than at
		// spawn time. Caught at load, it is one clear message at startup;
		// caught at spawn, it is a tool that fails on first use with an error
		// the user sees days later.
		if b.CredentialAlias != "" && strings.TrimSpace(b.CredentialEnv) == "" {
			return nil, fmt.Errorf("%s: backend %q references credential %q but does not say "+
				"which environment variable to pass it as; set credential_env (for example PGPASSWORD)",
				path, b.Name, b.CredentialAlias)
		}
	}
	return &cfg, nil
}

// SecretLookup resolves a vault alias to its plaintext.
//
// A narrow port so this file does not depend on the vault package — and so the
// fence can drive it without an unlocked vault.
type SecretLookup func(alias string) (string, error)

// BuildLocalPolicy translates the user's config into the SAME Policy structure
// the control plane produces.
//
// The identity arguments are the org and seat the local virtual key resolves
// to. They are passed in rather than invented here because they must MATCH what
// Authenticate() puts on the request — a grant naming a seat that never
// authenticates would make every call 404 with no way to tell why.
//
// 🔴 Tools are deliberately EMPTY. They are discovered by the manifest syncer
// against the running backend, exactly as they are for a remote one: the user's
// config says which servers to host, never which tools those servers have.
// Letting the file declare tools would let it declare a tool the backend does
// not implement — and, worse, declare `write_op: false` for one that does.
func BuildLocalPolicy(cfg *LocalConfig, orgID, seatID string, lookup SecretLookup) (*Policy, []error) {
	p := &Policy{
		OrgID:         orgID,
		Version:       time.Now().UnixMilli(), // any monotonic value; nothing polls it
		GeneratedAtMs: time.Now().UnixMilli(),
		Backends:      []PolicyBackend{},
		Toolsets: []PolicyToolset{{
			ID:     LocalToolsetSlug,
			Slug:   LocalToolsetSlug,
			Title:  "Local tools",
			Status: StatusActive,
			Tools:  []PolicyTool{},
		}},
		// 🔴 An explicit grant row, not a bypass. See the file header: the
		// evaluator must be identical on every edition, and only its INPUT
		// differs.
		Grants: []PolicyGrant{{
			SubjectKind:     SubjectSeat,
			SubjectID:       seatID,
			VirtualServerID: LocalToolsetSlug,
		}},
	}

	var problems []error
	for _, b := range cfg.Backends {
		pb := PolicyBackend{
			ID:              b.Name,
			Name:            b.Name,
			Transport:       TransportStdio,
			Command:         b.Command,
			Args:            b.Args,
			Status:          StatusActive,
			DiscoverySource: DiscoveryStatic,
		}
		if b.Disabled {
			pb.Status = StatusDisabled
		}
		if b.CredentialAlias != "" {
			// The credential id IS the alias on this edition: there is no
			// mcp_backend_credential table locally, and inventing an id would
			// mean maintaining a mapping with exactly one entry per alias.
			pb.CredentialID = b.CredentialAlias
			if lookup == nil {
				// 🔴 Recorded as a problem and the backend is still published,
				// DISABLED. Dropping it silently would make a mis-set-up backend
				// indistinguishable from one the user never configured.
				problems = append(problems, fmt.Errorf("backend %q needs credential %q but this "+
					"proxy has no unlocked vault to read it from", b.Name, b.CredentialAlias))
				pb.Status = StatusDisabled
			} else if _, err := lookup(b.CredentialAlias); err != nil {
				problems = append(problems, fmt.Errorf("backend %q references credential %q, which "+
					"is not in the vault (run `aikey add %s`): %w",
					b.Name, b.CredentialAlias, b.CredentialAlias, err))
				pb.Status = StatusDisabled
			}
		}
		p.Backends = append(p.Backends, pb)
	}
	return p, problems
}

// LocalCredentialMaterial resolves every referenced alias into the material the
// credential store holds.
//
// 🔴 Returns Material, the same type the control-plane rail delivers, so the
// proxy has ONE credential store and one resolver on every edition. A separate
// "local credential" path would be a second place for the redaction, the env-
// injection rule and the "never in argv" property to be implemented — and the
// second implementation is the one that gets it wrong.
func LocalCredentialMaterial(cfg *LocalConfig, lookup SecretLookup) ([]Material, []error) {
	if lookup == nil {
		return nil, nil
	}
	var out []Material
	var problems []error
	for _, b := range cfg.Backends {
		if b.CredentialAlias == "" || b.Disabled {
			continue
		}
		secret, err := lookup(b.CredentialAlias)
		if err != nil {
			// 🚫 The alias is named, the secret is not. Errors get pasted into
			// tickets.
			problems = append(problems, fmt.Errorf("credential %q for backend %q: %w",
				b.CredentialAlias, b.Name, err))
			continue
		}
		out = append(out, Material{
			ID:   b.CredentialAlias,
			Kind: CredentialKindEnv,
			// HeaderName carries the VARIABLE NAME for an env credential — see
			// CredentialKindEnv for why the field is reused rather than doubled.
			HeaderName: strings.TrimSpace(b.CredentialEnv),
			Secret:     secret,
		})
	}
	return out, problems
}
