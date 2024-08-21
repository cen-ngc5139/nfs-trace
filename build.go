//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type rpc_task_fields -target $TARGET_GOARCH -output-dir ./cmd -cc clang -no-strip KProbePWRU ./bpf/kprobe_pwru.c -- -DRPC_TASK_VAR=$FILTER_STRUCT -I./bpf/headers -Wno-address-of-packed-member

package main
