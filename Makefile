MODULE     := github.com/AiKeyLabs/aikey-proxy
VERSION    ?= dev
PKG        := github.com/AiKeyLabs/pkg/buildinfo
GIT_REVISION  = $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY     = $(shell test -z "$$(git status --porcelain --untracked-files=normal 2>/dev/null)" && echo "" || echo "-dirty")
BUILD_ID     ?= $(shell head -c 2 /dev/urandom 2>/dev/null | xxd -p 2>/dev/null \
                  || powershell -NoProfile -C "'{0:x4}' -f (Get-Random -Max 65535)" 2>/dev/null \
                  || echo "0000")
BUILD_TIME    = $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
                  || powershell -NoProfile -C "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')" 2>/dev/null \
                  || echo "unknown")
LDFLAGS    := -ldflags "\
  -X $(PKG).Version=$(VERSION) \
  -X $(PKG).Revision=$(GIT_REVISION)$(GIT_DIRTY) \
  -X $(PKG).BuildID=$(BUILD_ID) \
  -X $(PKG).BuildTime=$(BUILD_TIME)"
CONFIG     := aikey-proxy.yaml
# Installation directory — override with: make install INSTALL_DIR=/your/path
INSTALL_DIR ?= $(HOME)/.aikey/bin
# Prefer the optional repository workspace when it exists.  A normal checkout
# is also self-contained because go.mod carries the sibling-module replace
# directives (including aikey-auth-broker); exporting a nonexistent go.work
# makes every Make target fail before Go can use those replacements.
GOWORK_FILE := $(abspath ../go.work)
GOWORK     ?= $(if $(wildcard $(GOWORK_FILE)),$(GOWORK_FILE),off)
export GOWORK

# The strict lint profile was enabled after this repository had accumulated
# pre-existing findings.  Keep that debt visible via `lint-full`, while the
# release fence fails on every finding introduced after this reviewed, pinned
# baseline.  This SHA must only move together with a debt-audit document; never
# derive it from origin/HEAD or a new commit could silently baseline itself.
LINT_BASE_REV ?= 9695facb96c1fefb8a2f8ba1f4b41823cf1efad6

.PHONY: build test test-bugfix-provider-routing test-pathprefix-matrix run install uninstall restart clean lint lint-full cross-compile sync-fingerprint sync-provider-registry sync-provider-data chaos-gap7 chaos-gap8 chaos filter-integration

# v4.3 (2026-05-01): aikey-cli/data/provider_fingerprint.yaml is the single
# source of truth for provider routing. The pkg/providerroutes Go package
# embeds it via go:embed; we sync into pkg/providerroutes/data/ before any
# go build so all consumers (this proxy + control service + future Go
# consumers) compile against the same yaml content.
#
# The pkg/providerroutes/data/ copy is CHECKED IN (design D-7) so every Go
# consumer wired via a go.mod replace compiles without a per-service sync step.
# Canonical still lives in aikey-cli; editing the copy directly is wrong — the
# sync target regenerates it and the package's SHA gate fails the build when the
# two diverge.
FINGERPRINT_SRC := ../aikey-cli/data/provider_fingerprint.yaml
FINGERPRINT_DST := ../pkg/providerroutes/data/provider_fingerprint.yaml

# provider_registry.yaml is the SECOND provider source of truth and answers a
# different question: fingerprint owns (provider × protocol → base_url), registry
# owns provider identity — canonical code, brand aliases, family, proxy_path
# (requirement spec 2026-07-18-provider-protocol-compatibility-and-baseurl §3).
# Go had no path to it until pkg/providerregistry, which is why alias tables were
# hand-copied into Go; §10 of that spec forbids exactly that. Synced the same way
# and for the same reason as the fingerprint copy.
REGISTRY_SRC := ../aikey-cli/data/provider_registry.yaml
REGISTRY_DST := ../pkg/providerregistry/data/provider_registry.yaml

sync-fingerprint:
	@mkdir -p ../pkg/providerroutes/data
	@cp $(FINGERPRINT_SRC) $(FINGERPRINT_DST)

sync-provider-registry:
	@mkdir -p ../pkg/providerregistry/data
	@cp $(REGISTRY_SRC) $(REGISTRY_DST)

# Both provider sources must be fresh before any compile — a build that embeds
# one stale copy misroutes exactly as badly as embedding two.
sync-provider-data: sync-fingerprint sync-provider-registry

build: sync-provider-data
	@go build $(LDFLAGS) -o bin/aikey-proxy ./cmd/aikey-proxy
	@cp $(CONFIG) bin/$(CONFIG)

# ./cmd/aikey-proxy added 2026-07-08: the egress system-proxy-switch
# integration tests (egress_integration_test.go) live in package main because
# they drive the REAL buildTransport — internal/... alone would skip them.
test:
	go test -race -v ./internal/... ./cmd/aikey-proxy/

# Regression fence for the 2026-07-24 OAuth URL composer and the adjacent
# Provider/Protocol consumer regressions. This target is the canonical entry
# referenced by both bugfix records; keep new routing lanes in this matrix so
# a release does not depend on remembering a list of ad-hoc go test commands.
test-bugfix-provider-routing: ## regression: OAuth Stitch + App/Probe axes + health URL + vault projection
	go test -v -count=1 ./internal/provider/ -run 'TestProtocolFamily'
	go test -v -count=1 ./internal/vault/ -run 'TestGetAliasCredential_(OAuthByDisplayIdentity|PreProtocolColumnOAuthRemainsReadable)'
	go test -v -count=1 ./internal/supervisor/ -run 'Test(OAuthTokenToRoute_SetsOAuthSource|BuildManagedRoutes_PreservesBothMockProtocolBindings)'
	go test -v -count=1 ./internal/admin/ -run 'TestProbeKey_UsesProviderRouteStitchForEveryVersionShape'
	go test -v -count=1 ./internal/proxy/ -run 'Test(StitchOAuthRequestURL_OneProviderTableRule|Fence_OAuthBinding|Fence_Tier1OAuthRouteStitchesVersionExactlyOnce|Fence_CodexOAuth|GroupServe_(OAuthAccountInjectsBearer|MockCodexOAuthUsesRuntimeRailAndFingerprintVersion|MockOAuthMissingBaseURLFailsClosed|EmptyRouteProviderUsesAccountProvider)|AppPipeline_PreservesProviderAndUsesProtocolAdapter|ProbePipeline_PreservesProviderAndUsesProtocolAdapter|NormalizeBindingForClientRouteKeepsIndependentAxes)'

# Registry-derived path-prefix routing matrix (2026-08-08). Every picker:true
# provider in provider_registry.yaml is driven through the REAL proxy handler and
# the upstream path it produces is compared against the vendor's real endpoint —
# i.e. it checks that `http://127.0.0.1:<port>/<proxy_path>` really is the drop-in
# replacement for the vendor base_url that `aikey use` claims it is.
#
# BUILD-TAGGED ON PURPOSE: it is RED today (20 of 28 providers fail — D-1 prefix
# not recognized × 15, D-2 upstream path doubled × 5), so it stays out of default
# CI to avoid blocking unrelated work. The GREEN half of the same matrix —
# TestPathPrefixMatrix_MatchesKnownDefectLedger — DOES run in default CI and holds
# the anti-regression line. Evidence + fix options:
# ../workflow/CI/bugfix/20260808-provider-path-prefix-routing-registry-drift.md
test-pathprefix-matrix: ## matrix: every picker:true provider routes + stitches (RED — known defects D-1/D-2)
	go test -count=1 -tags pathprefix_matrix -run TestPathPrefixMatrix_Strict -v ./internal/proxy/

# Chaos experiments (缺口7/8) — build-tagged so they stay OUT of the normal
# `test` suite. They drive the real newStreamDrainer / http.Server code paths
# and print quantified memory/connection data for the decision matrix. Plan +
# evidence: ../workflow/CI/e2e/chaos/2026-06-09-proxy-gap7-gap8-chaos-plan.md
chaos-gap7: ## chaos: SSE buffer memory vs body-size/concurrency (缺口7)
	go test -tags chaos -run TestChaosGap7_BufferMemory -v -timeout 120s ./internal/proxy/

chaos-gap8: ## chaos: idle keep-alive connection flood (缺口8)
	go test -tags chaos -run TestChaosGap8_ConnFlood -v -timeout 180s ./internal/proxy/

chaos: chaos-gap7 chaos-gap8 ## chaos: run all proxy chaos experiments

# gap7 streaming token-extraction regression: the three fences (golden /
# accumulator-equivalence / chunk-split-invariance) + the full-proxy live-event
# E2E (real streaming request → incremental drainer → collector → store → assert
# recorded tokens). Run after any change to stream_drainer / provider extractors.
e2e-gap7: ## e2e: gap7 streaming token-extraction fences + full-proxy live E2E
	go test -race -run 'TokenStreamFence|StreamSplitInvariance' ./internal/provider/ ./internal/proxy/
	go test -race -run 'TestProxy_Streaming_RecordsTokens|TestProxy_Streaming_RecordsModelAndCache|TestProxy_Streaming_LargeBody|TestStreamDrainer' ./internal/proxy/

# Compliance filter end-to-end through the REAL ai-compliance-detector child (embedded
# baseline pack). Reproduces + locks the 2026-06-16 history-leak bug: a sensitive token
# in HISTORY is masked, assistant reply untouched, identical re-send served from cache
# (0 extra detector calls). Builds the detector first; the Go test skips if it's missing.
filter-integration: ## e2e: history-leak fix + cache via real detector (builds detector first)
	$(MAKE) -C ../ai-compliance-detector build
	go test -tags integration -count=1 -run 'TestFilterIntegration' -v ./internal/proxy/

run: build
	./bin/aikey-proxy --config bin/$(CONFIG)

## Install aikey-proxy binary to INSTALL_DIR (idempotent, safe to run repeatedly)
install: build
	@echo "Installing aikey-proxy to $(INSTALL_DIR)..."
	@install -Dm755 bin/aikey-proxy $(INSTALL_DIR)/aikey-proxy
	@echo "Installed: $(INSTALL_DIR)/aikey-proxy"

## Build, install, and restart the running proxy process.
## Why pkill + aikey proxy start: proxy requires vault master password via session
## cache, so it must be started through the CLI (not nohup directly).
restart: install
	@echo "Restarting aikey-proxy..."
	@pkill -f "aikey-proxy --config" 2>/dev/null || true
	@sleep 1
	@echo "Binary updated. Run: aikey proxy start"

## Remove aikey-proxy from INSTALL_DIR
uninstall:
	@rm -f $(INSTALL_DIR)/aikey-proxy
	@echo "Removed: $(INSTALL_DIR)/aikey-proxy"

clean:
	rm -rf bin/

lint:
	@git cat-file -e "$(LINT_BASE_REV)^{commit}" 2>/dev/null || { \
		echo "ERROR: lint baseline commit $(LINT_BASE_REV) is unavailable; fetch repository history" >&2; \
		exit 1; \
	}
	golangci-lint run --new-from-rev=$(LINT_BASE_REV) ./...

# Explicit debt audit.  This is intentionally not the release fence until the
# pinned baseline findings are paid down; unlike `lint`, it reports the entire
# repository and is expected to remain red meanwhile.
lint-full:
	golangci-lint run ./...

cross-compile: sync-provider-data
	@mkdir -p bin
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/aikey-proxy-darwin-arm64  ./cmd/aikey-proxy
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-darwin-amd64  ./cmd/aikey-proxy
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-linux-amd64   ./cmd/aikey-proxy
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/aikey-proxy-linux-arm64   ./cmd/aikey-proxy
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-windows-amd64.exe ./cmd/aikey-proxy
	@cp $(CONFIG) bin/$(CONFIG)
