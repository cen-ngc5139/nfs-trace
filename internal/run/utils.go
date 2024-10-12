package run

import (
	"github.com/cen-ngc5139/nfs-trace/internal/config"
	"github.com/cilium/ebpf"
)

func upateBpfSpecWithFlags(bpfSpec *ebpf.CollectionSpec, cfg config.Configuration) {
	if !cfg.Features.NFSMetrics {
		delete(bpfSpec.Programs, "kb_nfs_write_d")
		delete(bpfSpec.Programs, "kb_nfs_read_d")
		delete(bpfSpec.Programs, "rpc_exit_task")
		delete(bpfSpec.Programs, "rpc_execute")
		delete(bpfSpec.Programs, "nfs_init_read")
		delete(bpfSpec.Programs, "nfs_init_write")
		delete(bpfSpec.Programs, "rpc_task_begin")
		delete(bpfSpec.Programs, "rpc_task_done")

		delete(bpfSpec.Maps, "waiting_RPC")
		delete(bpfSpec.Maps, "link_begin")
		delete(bpfSpec.Maps, "link_end")
		delete(bpfSpec.Maps, "io_metrics")
	}

	if !cfg.Features.DNS {
		delete(bpfSpec.Programs, "kprobe_udp_sendmsg")
		delete(bpfSpec.Maps, "dns_events")
		delete(bpfSpec.Programs, "kretprobe_udp_recvmsg")
	}
}

func getKprobeAttachMap(cfg config.Configuration) (kprobeFuncs, kretprobeFuncs map[string]string) {
	kprobeFuncs = make(map[string]string)
	kretprobeFuncs = make(map[string]string)

	if cfg.Features.NFSMetrics {
		kprobeFuncs["kb_nfs_write_d"] = "nfs_writeback_done"
		kprobeFuncs["kb_nfs_read_d"] = "nfs_readpage_done"
		kprobeFuncs["rpc_exit_task"] = "rpc_exit_task"
		kprobeFuncs["rpc_execute"] = "rpc_make_runnable"
	}

	// 如果未启用 DNS 模式，则删除 kprobe_udp_sendmsg 的 kprobe
	if cfg.Features.DNS {
		kprobeFuncs["kprobe_udp_sendmsg"] = "udp_sendmsg"
		kprobeFuncs["kprobe_sys_recvmsg"] = "__sys_recvmsg"
		kretprobeFuncs["kretprobe_sys_recvmsg"] = "__sys_recvmsg"
	}

	return kprobeFuncs, kretprobeFuncs
}
