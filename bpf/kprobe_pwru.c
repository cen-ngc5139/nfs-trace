// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

struct rpc_task_fields
{
	int owner_pid;
	char pod[100];
	char container[100];
	u64 caller_addr;
	char file[40];
};

struct rpc_task_fields *unused_event __attribute__((unused));

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} rpc_task_map SEC(".maps");

struct metadata
{
    char pod[100];
    char container[100];
    u64 pid;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct metadata);
    __uint(max_entries, 1024);
} pid_cgroup_map SEC(".maps");

#ifndef RPC_TASK_VAR
#define RPC_TASK_VAR nfs_pgio_header
#endif

static __always_inline int
kprobe_nfs_kiocb(struct kiocb *iocb, struct pt_regs *ctx)
{
    struct rpc_task_fields event = {};
    struct task_struct *task;

    // 获取 PID
    event.owner_pid = bpf_get_current_pid_tgid() >> 32;

    // 从 kiocb 结构体中获取文件路径
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    if (!file)
        return 0;

    struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
    if (!de)
        return 0;

    struct qstr qs = {};

    bpf_probe_read_kernel(&qs, sizeof(qs), (void *)&de->d_name);
    if (qs.len == 0)
        return 0;

    bpf_probe_read_kernel(&event.file, sizeof(event.file), (void *)qs.name);

    if (bpf_probe_read_kernel(&event.caller_addr, sizeof(event.caller_addr), (void *)PT_REGS_SP(ctx)))
    {
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
    {
        return 0;
    }

    // 使用 pid 到 pid_cgroup_map 中搜索
    struct metadata *metadata = bpf_map_lookup_elem(&pid_cgroup_map, &event.owner_pid);
    if (metadata)
    {
        bpf_probe_read_kernel(&event.pod, sizeof(event.pod), metadata->pod);
        bpf_probe_read_kernel(&event.container, sizeof(event.container), metadata->container);
    }


    // 输出事件到 perf 事件数组
    bpf_perf_event_output(ctx, &rpc_task_map, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return BPF_OK;
}

#define CONCAT(a, b) a##b
#define EXPAND_AND_CONCAT(a, b) CONCAT(a, b)

#ifdef HAS_KPROBE_MULTI
#define PWRU_KPROBE_TYPE "kprobe.multi"
#define PWRU_HAS_GET_FUNC_IP true
#else
#define PWRU_KPROBE_TYPE "kprobe"
#define PWRU_HAS_GET_FUNC_IP false
#endif /* HAS_KPROBE_MULTI */

#define PWRU_ADD_KPROBE(X)                                               \
	SEC(PWRU_KPROBE_TYPE "/skb-" #X)                                     \
	int kprobe_skb_##X(struct pt_regs *ctx)                              \
	{                                                                    \
		struct RPC_TASK_VAR *hdr = (struct RPC_TASK_VAR *)PT_REGS_PARM##X(ctx); \
		return EXPAND_AND_CONCAT(kprobe_nfs_, RPC_TASK_VAR)(hdr, ctx);                                    \
	}

PWRU_ADD_KPROBE(1)
PWRU_ADD_KPROBE(2)
PWRU_ADD_KPROBE(3)
PWRU_ADD_KPROBE(4)
PWRU_ADD_KPROBE(5)

char __license[] SEC("license") = "Dual BSD/GPL";
