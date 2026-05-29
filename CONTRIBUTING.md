# Contributing to aikey-proxy

The local HTTP proxy that routes Agent traffic to the correct upstream provider credential. Sits between `aikey-cli` (which owns the vault) and your Agent.

If you are new to AiKey, read the [profile overview](https://github.com/aikeylabs/.github/blob/main/profile/README.md) and start with [aikey-cli](https://github.com/aikeylabs/aikey-cli) — most flows touch the CLI first.

## Before you start

- This repo is the request-path hot loop. Changes here can affect latency, correctness of request routing, and the security boundary between Agents and real provider credentials. Please open an issue or a Discussion before sending a large refactor.
- Cross-protocol changes (OpenAI ↔ Anthropic translator, model-name inference) must come with fixture-based tests. We do not accept "trust me, it works" changes to wire-format handling.

## Local setup

You need:

- Go 1.22 or later.
- A working `aikey-cli` install on the same machine so the proxy can pull credentials from the vault. Either `cargo install --path .` from a clone of `aikey-cli`, or use the published installer.

```bash
git clone https://github.com/aikeylabs/aikey-proxy.git
cd aikey-proxy
go build ./...
go test ./...
```

To run the proxy against your real vault:

```bash
aikey proxy        # starts the proxy via the CLI; equivalent to `go run ./cmd/aikey-proxy`
```

Or run the binary directly with a config file (`-config`).

## Tests

- Unit tests: `go test ./...`
- Translator fixtures live under `pkg/protocol-translator/pairs/<source>_<target>/testdata/`. New translator behavior needs a new fixture pair (request input + expected upstream output + expected client response).
- Integration tests need the `integration` build tag: `go test -tags=integration -p 1 ./...`. They spin up a fake upstream provider via testcontainers; `-p 1` is required because they share a Ryuk reaper.

## Code style

- Run `go vet ./...` and `gofmt -s -l .` before pushing. CI will catch the rest.
- Prefer interfaces in the request-path (`VaultGetter`, `EventInserter`) so each handler can be unit-tested without the full vault.
- Keep allocations on the hot path down — this is the per-request loop, not a one-shot.

## PR flow

1. Open an issue or Discussion if the change touches request handling, the credential boundary, the translator, or any error code.
2. Fork → branch → PR against `main`. One logical change per PR.
3. Fill in the PR template. Call out cross-edition impact (Personal / Trial / Production).
4. CI must be green. We do not merge red CI even for "obvious" changes — past incidents started that way.

## Security

Vulnerabilities go to **aikeyfounder@gmail.com**, not GitHub issues. See [SECURITY.md](https://github.com/aikeylabs/.github/blob/main/SECURITY.md).

## Code of Conduct

Participating in this repo means you accept the [AiKey Labs Code of Conduct](https://github.com/aikeylabs/.github/blob/main/CODE_OF_CONDUCT.md).
