MODULE     := github.com/AiKeyLabs/aikey-proxy
VERSION    := 0.1.0
LDFLAGS    := -ldflags "-X main.version=$(VERSION)"
CONFIG     := aikey-proxy.yaml
# Installation directory — override with: make install INSTALL_DIR=/your/path
INSTALL_DIR ?= $(HOME)/.aikey/bin

.PHONY: build test run install uninstall clean lint cross-compile

build:
	go build $(LDFLAGS) -o bin/aikey-proxy ./cmd/aikey-proxy
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
	@echo "Run 'aikey proxy start' to start the proxy."

## Remove aikey-proxy from INSTALL_DIR
uninstall:
	@rm -f $(INSTALL_DIR)/aikey-proxy
	@echo "Removed: $(INSTALL_DIR)/aikey-proxy"

clean:
	rm -rf bin/

lint:
	golangci-lint run ./...

cross-compile:
	@mkdir -p bin
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/aikey-proxy-darwin-arm64  ./cmd/aikey-proxy
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-darwin-amd64  ./cmd/aikey-proxy
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-linux-amd64   ./cmd/aikey-proxy
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/aikey-proxy-linux-arm64   ./cmd/aikey-proxy
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/aikey-proxy-windows-amd64.exe ./cmd/aikey-proxy
	@cp $(CONFIG) bin/$(CONFIG)
