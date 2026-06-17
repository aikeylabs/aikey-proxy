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
# Go workspace — needed for local aikey-auth-broker dependency
GOWORK     ?= $(shell cd .. && pwd)/go.work
export GOWORK

.PHONY: build test run install uninstall restart clean lint cross-compile sync-fingerprint chaos-gap7 chaos-gap8 chaos filter-integration

# v4.3 (2026-05-01): aikey-cli/data/provider_fingerprint.yaml is the single
# source of truth for provider routing. The pkg/providerroutes Go package
# embeds it via go:embed; we sync into pkg/providerroutes/data/ before any
# go build so all consumers (this proxy + control service + future Go
# consumers) compile against the same yaml content.
#
# The pkg/providerroutes/data/ copy is gitignored — canonical lives in
# aikey-cli; editing the copy is a build-step concern, not a code change.
FINGERPRINT_SRC := ../aikey-cli/data/provider_fingerprint.yaml
FINGERPRINT_DST := ../pkg/providerroutes/data/provider_fingerprint.yaml

sync-fingerprint:
	@mkdir -p ../pkg/providerroutes/data
	@cp $(FINGERPRINT_SRC) $(FINGERPRINT_DST)

build: sync-fingerprint
	@go build $(LDFLAGS) -o bin/aikey-proxy ./cmd/aikey-proxy
	@cp $(CONFIG) bin/$(CONFIG)

test:
	go test -race -v ./internal/...

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
	golangci-lint run ./...

cross-compile: sync-fingerprint
	@mkdir -p bin
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/aikey-proxy-darwin-arm64  ./cmd/aikey-proxy
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-darwin-amd64  ./cmd/aikey-proxy
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-linux-amd64   ./cmd/aikey-proxy
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/aikey-proxy-linux-arm64   ./cmd/aikey-proxy
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-windows-amd64.exe ./cmd/aikey-proxy
	@cp $(CONFIG) bin/$(CONFIG)
