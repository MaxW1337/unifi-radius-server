.PHONY: all build build-udm test clean

BINARY_NAME=unifi-radius
VERSION ?= 1.0.0
COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE = $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "today")
LDFLAGS = -s -w -X main.Version=$(VERSION) -X main.GitCommit=$(COMMIT) -X main.BuildDate=$(DATE)

all: test build

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/server

build-udm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/server

test:
	go test -v ./...

clean:
	rm -rf bin/ dist/ data/*.db data/*.db-wal data/*.db-shm

