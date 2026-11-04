.PHONY: all build build-udm test clean

BINARY_NAME=unifi-radius
VERSION ?= $(shell cat VERSION 2>/dev/null || grep -oE '[0-9]+\.[0-9]+\.[0-9]+' pkg/version/version.go 2>/dev/null || echo "dev")
COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE = $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "today")
LDFLAGS = -s -w -X main.Version=$(VERSION) -X main.GitCommit=$(COMMIT) -X main.BuildDate=$(DATE) -X github.com/mwittenburg/unifi-radius-server/pkg/version.GitCommit=$(COMMIT) -X github.com/mwittenburg/unifi-radius-server/pkg/version.BuildDate=$(DATE)

all: test build

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/server

build-udm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/server

test:
	go test -v ./...

clean:
	rm -rf bin/ dist/ data/*.db data/*.db-wal data/*.db-shm

