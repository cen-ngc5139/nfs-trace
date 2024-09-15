package bpf

import (
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cilium/ebpf"
)

func AttachTracepoint(coll *ebpf.Collection) (*tracing, bool, error) {
	var hasError bool
	// attach nfs tracepoints
	nfsTracepointProgs := map[string]*ebpf.Program{}
	for name, prog := range coll.Programs {
		key, ok := NFSTracepointProgs[name]
		if !ok {
			continue
		}

		nfsTracepointProgs[key] = prog
	}

	trace := Tracepoint("nfs", nfsTracepointProgs)

	// attach rpc tracepoints
	rpcTracepointProgs := map[string]*ebpf.Program{}
	for name, prog := range coll.Programs {
		key, ok := RPCTracepointProgs[name]
		if !ok {
			continue
		}

		if !IsTracepointExist("sunrpc", key) {
			hasError = true
			log.Warningf("警告：Tracepoint %s/%s 不存在，跳过\n", "sunrpc", key)
			continue
		}

		rpcTracepointProgs[key] = prog
	}

	if !hasError {
		rpcTrace := Tracepoint("sunrpc", rpcTracepointProgs)
		trace.Merge(rpcTrace)
	}

	return trace, hasError, nil
}
