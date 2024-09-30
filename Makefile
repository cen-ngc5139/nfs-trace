GO := go
GO_BUILD = CGO_ENABLED=1 $(GO) build
GO_GENERATE = $(GO) generate
GO_TAGS ?=
TARGET_GOARCH ?= amd64,arm64
GOARCH ?= amd64
GOOS ?= linux
VERSION=$(shell git describe --tags --always)
FILTER_STRUCT ?= kiocb
# For compiling libpcap and CGO
CC ?= gcc


build: elf
	cd ./cmd;CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH)   go build -gcflags "all=-N -l" -o nfs-trace

dlv:  build
	# dlv --headless --listen=:2345 --api-version=2 exec ./cmd/nfs-trace -- --filter-struct=$(FILTER_STRUCT) --filter-func="^nfs.*" --all-kmods=true
	dlv --headless --listen=:2345 --api-version=2 exec ./cmd/nfs-trace -- --config-path=./cmd/config.yaml

run:  build
	./cmd/nfs-trace --filter-struct=$(FILTER_STRUCT) --filter-func="^(vfs_|nfs_).*" --all-kmods=true --enable-nfs-metrics=true --enable-dns=true --enable-debug=true

skip:  build
	./cmd/nfs-trace --filter-struct=$(FILTER_STRUCT) --skip-attach=true --all-kmods=true --filter-func="^nfs.*"

funcs:  build
	./cmd/nfs-trace --filter-struct=kiocb --all-kmods=true --filter-func="^(vfs_|nfs_).*" --add-funcs="nfs_file_direct_read:1,nfs_file_direct_write:1,nfs_swap_rw:1,nfs_file_read:1,nfs_file_write:1"

elf:
	TARGET_GOARCH=$(TARGET_GOARCH) FILTER_STRUCT=$(FILTER_STRUCT) $(GO_GENERATE)
    	CC=$(CC) GOARCH=$(TARGET_GOARCH) $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
    		-ldflags "-w -s "

image:
	docker buildx create --use
	docker buildx build --platform linux/amd64 -t ghostbaby/nfs-trace:v0.0.1-amd64 --push .
	docker buildx build --platform linux/arm64 -t ghostbaby/nfs-trace:v0.0.1-arm64 --push .