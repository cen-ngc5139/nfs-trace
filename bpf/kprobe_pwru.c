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
	char cgroup_name[256];
	u64 caller_addr;
	char file[40];
};

struct rpc_task_fields *unused_event __attribute__((unused));

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} rpc_task_map SEC(".maps");

#ifndef RPC_TASK_VAR
#define RPC_TASK_VAR nfs_pgio_header
#endif

static __always_inline struct rpc_task_fields
kprobe_rpc(struct rpc_task *task, struct pt_regs *ctx)
{
	struct rpc_task_fields event = {};
	int owner_pid;

	// 获取 tk_owner
	owner_pid = BPF_CORE_READ(task, tk_owner);
	if (owner_pid == 0)
    {
        return event;
    }

	event.owner_pid = owner_pid;
	struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
	if (!cur_tsk)
    {
        return event;
    }

	const char *name = BPF_CORE_READ(cur_tsk, sched_task_group, css.cgroup, kn, name);
    if (!name)
    {
        return event;
    }

	if (bpf_probe_read_str(&event.cgroup_name, sizeof(event.cgroup_name), name) < 0)
    {
        return event;
    }

	if (bpf_probe_read_kernel(&event.caller_addr, sizeof(event.caller_addr), (void *)PT_REGS_SP(ctx)) < 0)
    {
        return event;
    }

    bpf_printk("owner_pid: %d, cgroup_name: %s, caller_addr: %llx\n", event.owner_pid, event.cgroup_name, event.caller_addr);

	return event;
}

static __always_inline int
kprobe_nfs_header(struct nfs_pgio_header *hdr, struct pt_regs *ctx)
{
    bpf_printk("hdr: %llx\n", hdr);
    struct rpc_task *rpc;
    // 获取 tk_owner
    BPF_CORE_READ_INTO(&rpc,hdr, task);
    if (!rpc)
    {
        return BPF_OK;
    }

    struct rpc_task_fields event = kprobe_rpc(rpc, ctx);
    if (!event.owner_pid)
    {
        return BPF_OK;
    }

    bpf_perf_event_output(ctx, &rpc_task_map, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return BPF_OK;
}

static __always_inline int
kprobe_nfs_kiocb(struct kiocb *iocb, struct pt_regs *ctx)
{
    struct rpc_task_fields event = {};
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

    if (bpf_probe_read_kernel(&event.caller_addr, sizeof(event.caller_addr), (void *)PT_REGS_SP(ctx)) < 0)
    {
        return 0;
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
