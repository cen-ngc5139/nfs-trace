GO := go
GO_BUILD = CGO_ENABLED=1 $(GO) build
GO_GENERATE = $(GO) generate
GO_TAGS ?=
TARGET_GOARCH ?= amd64
GOARCH ?= amd64
TARGET=pwru
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
VERSION=$(shell git describe --tags --always)
LIBPCAP_ARCH ?= x86_64-unknown-linux-gnu
# For compiling libpcap and CGO
CC ?= gcc

TEST_TIMEOUT ?= 5s
.DEFAULT_GOAL := pwru


test: elf build run



build:
	cd ./cmd;CGO_ENABLED=0 GOOS=linux GOARCH=amd64   go build -gcflags "all=-N -l" -o nfs-trace-linux-amd64
	cd ./cmd;CGO_ENABLED=0 GOOS=linux GOARCH=arm64   go build -gcflags "all=-N -l" -o nfs-trace-linux-arm64

dlv:
	dlv --headless --listen=:2345 --api-version=2 exec ./cmd/nfs-trace-linux-amd64 -- --filter-struct rpc_task --filter-func ^nfs.* --all-kmods true

run:
	./cmd/nfs-trace-linux-amd64 --filter-struct rpc_task --filter-func ^nfs.* --all-kmods true

elf:
	TARGET_GOARCH=$(TARGET_GOARCH) $(GO_GENERATE)
    	CC=$(CC) GOARCH=$(TARGET_GOARCH) $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
    		-ldflags "-w -s \
    		-X 'github.com/cilium/pwru/internal/pwru.Version=${VERSION}'"