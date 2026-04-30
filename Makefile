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

.PHONY: build test run install uninstall restart clean lint cross-compile sync-fingerprint

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
