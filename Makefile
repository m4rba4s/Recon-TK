# RTK Elite - Professional Build System
# Zero-Warning Policy for Production Release

BINARY_NAME=rtk
GO_VERSION=1.23
STATICCHECK_VERSION=2023.1.7

.PHONY: all build test lint staticcheck clean install deps help

## Build commands
all: deps lint build test

build:
	@echo "🔨 Building $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) .

## Quality assurance
lint: staticcheck vet fmt

staticcheck: install-staticcheck
	@echo "🔍 Running staticcheck..."
	@staticcheck -f stylish ./...
	@echo "✅ Staticcheck passed with 0 warnings"

vet:
	@echo "🔍 Running go vet..."
	@go vet ./...
	@echo "✅ Go vet passed"

fmt:
	@echo "🔍 Checking go fmt..."
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "❌ Code is not formatted. Run 'make format'"; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "✅ Code is properly formatted"

format:
	@echo "🎨 Formatting code..."
	@gofmt -w .

## Testing
test:
	@echo "🧪 Running tests..."
	@go test -v ./...

## Dependencies
deps:
	@echo "📦 Downloading dependencies..."
	@go mod download
	@go mod tidy

install-staticcheck:
	@echo "📦 Installing staticcheck..."
	@which staticcheck > /dev/null || go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

## Maintenance
clean:
	@echo "🧹 Cleaning..."
	@rm -f $(BINARY_NAME)
	@go clean -cache -testcache -modcache

help:
	@echo "RTK Elite - Professional Build System"
	@echo "====================================="
	@echo "Available targets:"
	@echo "  all       - Full build pipeline"
	@echo "  build     - Build binary"
	@echo "  lint      - Run all linting"
	@echo "  test      - Run tests"
	@echo "  clean     - Clean artifacts"