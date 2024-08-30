// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

struct raw_metrics
{
    u64 read_count;
    u64 read_size;
    u64 read_lat;
    u64 write_count;
    u64 write_size;
    u64 write_lat;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1024);
} link_begin SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1024);
} waiting_RPC SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1024);
} link_end SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct raw_metrics);
    __uint(max_entries, 1024);
} io_metrics SEC(".maps");
struct rpc_task_fields
{
    int pid;
    int mount_id;
    char pod[100];
    char container[100];
    u64 caller_addr;
    char path[100];
    char file[100];
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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1024);
} read_count SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1024);
} write_count SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} start_ts SEC(".maps");

// 获取当前 dentry 中完整的目录，用于获取文件、挂载目录
static __always_inline int get_full_path(struct dentry *dentry, char *path, int buf_size)
{
    int offset = buf_size - 1;
    path[offset] = '\0';

#pragma unroll
    for (int i = 0; i < 10; i++)
    {
        struct dentry *parent;
        struct qstr dname;

        if (bpf_probe_read_kernel(&dname, sizeof(dname), (void *)&dentry->d_name) < 0)
            break;

        int name_len = 30;
        if (name_len > offset)
            name_len = offset;

        if (offset < name_len)
            break;

        offset -= name_len;
        if (bpf_probe_read_kernel(&path[offset], name_len, (void *)dname.name) < 0)
            break;

        // 检查并添加分隔符 '/'
        if (offset > 0 && path[offset] != '/')
        {
            offset--;
            path[offset] = '/';
        }

        // bpf_printk("dname: %s\n", &path[offset]);

        if (bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent) < 0)
            break;

        if (dentry == parent)
            break;

        dentry = parent;
    }

    return buf_size - offset - 1;
}

static __always_inline int
kprobe_nfs_kiocb(struct kiocb *iocb, struct pt_regs *ctx)
{
    struct rpc_task_fields event = {};

    // 获取 PID
    event.pid = bpf_get_current_pid_tgid() >> 32;

    // 使用 pid 到 pid_cgroup_map 中搜索
    struct metadata *metadata = bpf_map_lookup_elem(&pid_cgroup_map, &event.pid);
    if (metadata)
    {
        bpf_probe_read_kernel(&event.pod, sizeof(event.pod), metadata->pod);
        bpf_probe_read_kernel(&event.container, sizeof(event.container), metadata->container);
    }

    // 从 kiocb 结构体中获取文件路径
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    if (!file)
        return 0;

    struct path fp = BPF_CORE_READ(file, f_path);
    if (!fp.mnt)
        return 0;

    struct dentry *de = BPF_CORE_READ(&fp, dentry);
    if (!de)
        return 0;

    // 获取 stack point
    if (bpf_probe_read_kernel(&event.caller_addr, sizeof(event.caller_addr), (void *)PT_REGS_SP(ctx)))
    {
        return 0;
    }

    // 获取文件的完整路径
    int len = get_full_path(de, event.file, sizeof(event.file));
    if (len <= 0)
    {
        return 0;
    }

    // 获取 mount id
    struct vfsmount *vfsmnt = BPF_CORE_READ(&fp, mnt);
    if (!vfsmnt)
        return 0;

    struct mount *mnt = container_of(vfsmnt, struct mount, mnt);
    if (!mnt)
        return 0;

    event.mount_id = BPF_CORE_READ(mnt, mnt_id);

    // 获取 mount 目录
    // struct dentry *mnt_mountpoint = BPF_CORE_READ(mnt, mnt_mountpoint);
    // if (!mnt_mountpoint)
    //     return 0;

    // get_full_path(mnt_mountpoint, event.path, sizeof(event.path));

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

#define PWRU_ADD_KPROBE(X)                                                      \
    SEC(PWRU_KPROBE_TYPE "/skb-" #X)                                            \
    int kprobe_skb_##X(struct pt_regs *ctx)                                     \
    {                                                                           \
        struct RPC_TASK_VAR *hdr = (struct RPC_TASK_VAR *)PT_REGS_PARM##X(ctx); \
        return EXPAND_AND_CONCAT(kprobe_nfs_, RPC_TASK_VAR)(hdr, ctx);          \
    }

PWRU_ADD_KPROBE(1)
PWRU_ADD_KPROBE(2)
PWRU_ADD_KPROBE(3)
PWRU_ADD_KPROBE(4)
PWRU_ADD_KPROBE(5)

// tracepoint 增加 nfs_readpage_done/nfs_writeback_done 挂载函数用于统计 IOPS

SEC("tracepoint/nfs_readpage_done")
int trace_nfs_readpage_done(struct pt_regs *ctx)
{
    // u64 dev = PT_REGS_PARM1(ctx);
    u64 fileid = PT_REGS_PARM3(ctx);
    // u64 key = ((u64)dev << 32) | fileid;

    bpf_printk("读取操作 - 设备: %d, 文件ID: %d, Key: %d\n", fileid, fileid, fileid);

    // u64 *count = bpf_map_lookup_elem(&read_count, &key);
    // if (count)
    //     (*count)++;
    // else
    //     bpf_map_update_elem(&read_count, &key, &(u64){1}, BPF_ANY);

    return 0;
}

SEC("tracepoint/nfs_writeback_done")
int trace_nfs_writeback_done(struct pt_regs *ctx)
{
    // u64 dev = PT_REGS_PARM1(ctx);
    u64 fileid = PT_REGS_PARM3(ctx);
    // u64 key = ((u64)dev << 32) | fileid;

    bpf_printk("写入操作 - 设备: %d, 文件ID: %d, Key: %d\n", fileid, fileid, fileid);

    // u64 *count = bpf_map_lookup_elem(&write_count, &key);
    // if (count)
    //     (*count)++;
    // else
    //     bpf_map_update_elem(&write_count, &key, &(u64){1}, BPF_ANY);

    return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
