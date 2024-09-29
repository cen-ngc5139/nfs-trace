package run

import (
	"github.com/cen-ngc5139/nfs-trace/internal/bpf"
	"github.com/cilium/ebpf"
)

func upateBpfSpecWithFlags(bpfSpec *ebpf.CollectionSpec, flag *bpf.Flags) {
	if !flag.EnableNFSMetrics {
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

	if !flag.EnableDNS {
		delete(bpfSpec.Programs, "kprobe_udp_recvmsg")
		delete(bpfSpec.Maps, "dns_events")
	}
}

func getKprobeAttachMap(flag *bpf.Flags) map[string]string {
	attachMap := make(map[string]string)

	if flag.EnableNFSMetrics {
		attachMap["kb_nfs_write_d"] = "nfs_writeback_done"
		attachMap["kb_nfs_read_d"] = "nfs_readpage_done"
		attachMap["rpc_exit_task"] = "rpc_exit_task"
		attachMap["rpc_execute"] = "rpc_make_runnable"
	}

	// 如果未启用 DNS 模式，则删除 kprobe_udp_recvmsg 的 kprobe
	if flag.EnableDNS {
		attachMap["kprobe_udp_recvmsg"] = "udp_sendmsg"
	}

	return attachMap
}
