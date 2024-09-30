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
		delete(bpfSpec.Programs, "kprobe_udp_recvmsg")
		delete(bpfSpec.Maps, "dns_events")
	}
}

func getKprobeAttachMap(cfg config.Configuration) map[string]string {
	attachMap := make(map[string]string)

	if cfg.Features.NFSMetrics {
		attachMap["kb_nfs_write_d"] = "nfs_writeback_done"
		attachMap["kb_nfs_read_d"] = "nfs_readpage_done"
		attachMap["rpc_exit_task"] = "rpc_exit_task"
		attachMap["rpc_execute"] = "rpc_make_runnable"
	}

	// 如果未启用 DNS 模式，则删除 kprobe_udp_recvmsg 的 kprobe
	if cfg.Features.DNS {
		attachMap["kprobe_udp_recvmsg"] = "udp_sendmsg"
	}

	return attachMap
}
