## Makefile inspired by https://github.com/gofiber/fiber/blob/main/Makefile

## help: 💡 Display available commands
.PHONY: help
help:
	@echo 'GoCarta Development:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## audit: 🚀 Conduct quality checks
.PHONY: audit
audit:
	go mod verify
	go vet ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## format: 🎨 Format code
.PHONY: format
format:
	gofmt -l -s -w .

## lint: 🚨 Run lint checks
.PHONY: lint
lint:
	@which golangci-lint > /dev/null || $(MAKE) install-lint
	golangci-lint run

## install-lint: 🛠 Install golangci-lint
.PHONY: install-lint
install-lint:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b /usr/local/bin v2.4.0

## modernize: 🛠 Run gopls modernize
.PHONY: modernize
modernize:
	go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test=false ./...

## proto: 📦 Compile protobuf files
.PHONY: proto
proto:
	./scripts/build-proto.sh
	./scripts/build-carta-proto.sh

## services: 📦 Compile services
.PHONY: services
services:
	./scripts/build-services.sh

## tidy: 📌 Clean and tidy dependencies
.PHONY: tidy
tidy:
	go mod tidy -v

## clean: 🗑️ Remove build artifacts and caches
.PHONY: clean
clean:
	go clean -cache -modcache
	rm -f ./build/*
