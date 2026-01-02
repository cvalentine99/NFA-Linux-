# NFA-Linux Makefile
# Next-Generation Network Forensic Analyzer
# Copyright (c) 2026 NFA-Linux Team

# Build Configuration
APP_NAME := nfa-linux
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | cut -d' ' -f3)

# Directories
BUILD_DIR := build
DIST_DIR := dist
FRONTEND_DIR := frontend
CMD_DIR := cmd/$(APP_NAME)

# Go Build Flags
LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.BuildTime=$(BUILD_TIME)' \
	-X 'main.GitCommit=$(GIT_COMMIT)'

# CGO is required for pcap and eBPF
export CGO_ENABLED := 1

# Wails Build Tags for Ubuntu 24.04+
WAILS_TAGS := webkit2_41

# Default target
.PHONY: all
all: build

# ============================================================================
# Development Targets
# ============================================================================

.PHONY: dev
dev: frontend-deps ## Run in development mode with hot reload
	@echo "Starting development server..."
	wails dev -tags $(WAILS_TAGS)

.PHONY: run
run: build ## Build and run the application
	@echo "Running $(APP_NAME)..."
	./$(BUILD_DIR)/$(APP_NAME)

.PHONY: run-headless
run-headless: build ## Run in headless mode
	@echo "Running $(APP_NAME) in headless mode..."
	./$(BUILD_DIR)/$(APP_NAME) -headless -version

# ============================================================================
# Build Targets
# ============================================================================

.PHONY: build
build: frontend-build go-build ## Build the complete application
	@echo "Build complete: $(BUILD_DIR)/$(APP_NAME)"

.PHONY: go-build
go-build: ## Build Go binary only
	@echo "Building Go binary..."
	@mkdir -p $(BUILD_DIR)
	wails build -tags $(WAILS_TAGS) -ldflags "$(LDFLAGS)" -o $(APP_NAME)
	@mv $(BUILD_DIR)/bin/$(APP_NAME) $(BUILD_DIR)/$(APP_NAME) 2>/dev/null || true

.PHONY: go-build-debug
go-build-debug: ## Build Go binary with debug symbols
	@echo "Building Go binary with debug symbols..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -tags $(WAILS_TAGS) -ldflags "-X 'main.Version=$(VERSION)' -X 'main.BuildTime=$(BUILD_TIME)' -X 'main.GitCommit=$(GIT_COMMIT)'" -o $(BUILD_DIR)/$(APP_NAME)-debug ./$(CMD_DIR)

.PHONY: frontend-deps
frontend-deps: ## Install frontend dependencies
	@echo "Installing frontend dependencies..."
	cd $(FRONTEND_DIR) && pnpm install

.PHONY: frontend-build
frontend-build: frontend-deps ## Build frontend
	@echo "Building frontend..."
	cd $(FRONTEND_DIR) && pnpm run build

.PHONY: frontend-lint
frontend-lint: ## Lint frontend code
	@echo "Linting frontend..."
	cd $(FRONTEND_DIR) && pnpm run lint

.PHONY: frontend-typecheck
frontend-typecheck: ## Type check frontend
	@echo "Type checking frontend..."
	cd $(FRONTEND_DIR) && pnpm exec tsc --noEmit

# ============================================================================
# Production Build Targets
# ============================================================================

.PHONY: build-prod
build-prod: clean frontend-build ## Build production binary
	@echo "Building production binary..."
	@mkdir -p $(BUILD_DIR)
	wails build -tags $(WAILS_TAGS) -ldflags "$(LDFLAGS)" -trimpath -o $(APP_NAME)
	@mv $(BUILD_DIR)/bin/$(APP_NAME) $(BUILD_DIR)/$(APP_NAME) 2>/dev/null || true
	@echo "Production build complete: $(BUILD_DIR)/$(APP_NAME)"

.PHONY: build-prod-upx
build-prod-upx: build-prod ## Build production binary with UPX compression
	@echo "Compressing binary with UPX..."
	@which upx > /dev/null || (echo "UPX not found. Install with: sudo apt install upx" && exit 1)
	upx --best --lzma $(BUILD_DIR)/$(APP_NAME)
	@echo "Compressed binary: $(BUILD_DIR)/$(APP_NAME)"

# ============================================================================
# Cross-Compilation Targets
# ============================================================================

.PHONY: build-linux-amd64
build-linux-amd64: frontend-build ## Build for Linux AMD64
	@echo "Building for Linux AMD64..."
	@mkdir -p $(DIST_DIR)/linux-amd64
	GOOS=linux GOARCH=amd64 wails build -tags $(WAILS_TAGS) -ldflags "$(LDFLAGS)" -platform linux/amd64 -o $(APP_NAME)
	@mv $(BUILD_DIR)/bin/$(APP_NAME) $(DIST_DIR)/linux-amd64/$(APP_NAME)

.PHONY: build-linux-arm64
build-linux-arm64: frontend-build ## Build for Linux ARM64
	@echo "Building for Linux ARM64..."
	@mkdir -p $(DIST_DIR)/linux-arm64
	GOOS=linux GOARCH=arm64 wails build -tags $(WAILS_TAGS) -ldflags "$(LDFLAGS)" -platform linux/arm64 -o $(APP_NAME)
	@mv $(BUILD_DIR)/bin/$(APP_NAME) $(DIST_DIR)/linux-arm64/$(APP_NAME)

.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 ## Build for all platforms
	@echo "All platform builds complete"

# ============================================================================
# Package Targets
# ============================================================================

.PHONY: package
package: package-deb package-rpm package-appimage ## Create all packages
	@echo "All packages created in $(DIST_DIR)/"

.PHONY: package-deb
package-deb: build-prod ## Create DEB package
	@echo "Creating DEB package..."
	@mkdir -p $(DIST_DIR)/deb
	./scripts/build-deb.sh $(VERSION)
	@echo "DEB package created: $(DIST_DIR)/$(APP_NAME)_$(VERSION)_amd64.deb"

.PHONY: package-rpm
package-rpm: build-prod ## Create RPM package
	@echo "Creating RPM package..."
	@mkdir -p $(DIST_DIR)/rpm
	./scripts/build-rpm.sh $(VERSION)
	@echo "RPM package created: $(DIST_DIR)/$(APP_NAME)-$(VERSION).x86_64.rpm"

.PHONY: package-appimage
package-appimage: build-prod ## Create AppImage
	@echo "Creating AppImage..."
	@mkdir -p $(DIST_DIR)/appimage
	./scripts/build-appimage.sh $(VERSION)
	@echo "AppImage created: $(DIST_DIR)/$(APP_NAME)-$(VERSION)-x86_64.AppImage"

.PHONY: package-tarball
package-tarball: build-prod ## Create tarball
	@echo "Creating tarball..."
	@mkdir -p $(DIST_DIR)
	tar -czvf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-linux-amd64.tar.gz \
		-C $(BUILD_DIR) $(APP_NAME) \
		-C .. README.md LICENSE docs/
	@echo "Tarball created: $(DIST_DIR)/$(APP_NAME)-$(VERSION)-linux-amd64.tar.gz"

# ============================================================================
# Docker Targets
# ============================================================================

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

.PHONY: docker-build-ml
docker-build-ml: ## Build ML sidecar Docker image
	@echo "Building ML sidecar Docker image..."
	docker build -t $(APP_NAME)-ml:$(VERSION) -t $(APP_NAME)-ml:latest -f ml_sidecar/Dockerfile ml_sidecar/

.PHONY: docker-run
docker-run: docker-build ## Run Docker container
	@echo "Running Docker container..."
	docker run --rm -it \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network=host \
		-v /tmp/nfa-output:/output \
		$(APP_NAME):$(VERSION) -headless -interface eth0

.PHONY: docker-compose-up
docker-compose-up: ## Start all services with docker-compose
	@echo "Starting services..."
	docker-compose up -d

.PHONY: docker-compose-down
docker-compose-down: ## Stop all services
	@echo "Stopping services..."
	docker-compose down

.PHONY: docker-push
docker-push: docker-build ## Push Docker image to registry
	@echo "Pushing Docker image..."
	docker push $(APP_NAME):$(VERSION)
	docker push $(APP_NAME):latest

# ============================================================================
# Test Targets
# ============================================================================

.PHONY: test
test: ## Run all tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./internal/...

.PHONY: test-short
test-short: ## Run short tests only
	@echo "Running short tests..."
	go test -v -short ./internal/...

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "Running integration tests..."
	go test -v -tags=integration ./test/integration/...

.PHONY: test-benchmark
test-benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	go test -v -bench=. -benchmem ./test/benchmark/...

.PHONY: test-coverage
test-coverage: test ## Generate coverage report
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

.PHONY: test-frontend
test-frontend: ## Run frontend tests
	@echo "Running frontend tests..."
	cd $(FRONTEND_DIR) && pnpm test

# ============================================================================
# Code Quality Targets
# ============================================================================

.PHONY: lint
lint: lint-go lint-frontend ## Lint all code
	@echo "Linting complete"

.PHONY: lint-go
lint-go: ## Lint Go code
	@echo "Linting Go code..."
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format Go code
	@echo "Formatting Go code..."
	go fmt ./...
	goimports -w .

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

.PHONY: staticcheck
staticcheck: ## Run staticcheck
	@echo "Running staticcheck..."
	@which staticcheck > /dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

.PHONY: security
security: ## Run security checks
	@echo "Running security checks..."
	@which gosec > /dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec -quiet ./...

# ============================================================================
# Documentation Targets
# ============================================================================

.PHONY: docs
docs: ## Generate documentation
	@echo "Generating documentation..."
	@which godoc > /dev/null || go install golang.org/x/tools/cmd/godoc@latest
	@echo "Starting godoc server at http://localhost:6060"
	godoc -http=:6060

.PHONY: docs-api
docs-api: ## Generate API documentation
	@echo "Generating API documentation..."
	@which swag > /dev/null || go install github.com/swaggo/swag/cmd/swag@latest
	swag init -g main.go -o docs/api

# ============================================================================
# Installation Targets
# ============================================================================

.PHONY: install
install: build-prod ## Install to system
	@echo "Installing $(APP_NAME)..."
	sudo ./scripts/install.sh

.PHONY: uninstall
uninstall: ## Uninstall from system
	@echo "Uninstalling $(APP_NAME)..."
	sudo ./scripts/uninstall.sh

.PHONY: install-deps
install-deps: ## Install system dependencies
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y \
		build-essential \
		libpcap-dev \
		libgtk-3-dev \
		libwebkit2gtk-4.1-dev \
		pkg-config

.PHONY: install-wails
install-wails: ## Install Wails CLI
	@echo "Installing Wails CLI..."
	go install github.com/wailsapp/wails/v2/cmd/wails@latest

.PHONY: install-tools
install-tools: ## Install development tools
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/tools/cmd/goimports@latest

# ============================================================================
# Utility Targets
# ============================================================================

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -rf $(FRONTEND_DIR)/dist
	rm -rf $(FRONTEND_DIR)/node_modules
	rm -f coverage.out coverage.html
	go clean -cache -testcache

.PHONY: clean-docker
clean-docker: ## Clean Docker images
	@echo "Cleaning Docker images..."
	docker rmi $(APP_NAME):$(VERSION) $(APP_NAME):latest 2>/dev/null || true
	docker rmi $(APP_NAME)-ml:$(VERSION) $(APP_NAME)-ml:latest 2>/dev/null || true

.PHONY: deps
deps: ## Download Go dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod verify

.PHONY: deps-update
deps-update: ## Update Go dependencies
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

.PHONY: generate
generate: ## Run go generate
	@echo "Running go generate..."
	go generate ./...

.PHONY: version
version: ## Print version information
	@echo "App Name:    $(APP_NAME)"
	@echo "Version:     $(VERSION)"
	@echo "Build Time:  $(BUILD_TIME)"
	@echo "Git Commit:  $(GIT_COMMIT)"
	@echo "Go Version:  $(GO_VERSION)"

.PHONY: check-wails
check-wails: ## Check Wails installation
	@echo "Checking Wails installation..."
	wails doctor

.PHONY: help
help: ## Show this help message
	@echo "NFA-Linux Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Default help
.DEFAULT_GOAL := help
