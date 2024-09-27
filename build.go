//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type rpc_task_fields -type raw_metrics -type path_segment -type dns_event -target $TARGET_GOARCH -go-package binary -output-dir ./internal/binary -cc clang -no-strip KProbePWRU ./bpf/kprobe_pwru.c -- -DRPC_TASK_VAR=$FILTER_STRUCT -I./bpf/headers -Wno-address-of-packed-member

package main
