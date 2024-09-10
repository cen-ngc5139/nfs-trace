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

struct rpc_task_info
{
    u64 timestamp;
    u32 pid;
    u32 tid;
};

struct rpc_task_state
{
    /* The first 8 bytes is not allowed to read */
    unsigned long pad;

    u64 task_id;
    u64 client_id;
    const void *action;
    unsigned long runstate;
    int status;
    unsigned short flags;
} __attribute__((packed));

struct nfs_file_fields
{
    /* The first 8 bytes is not allowed to read */
    unsigned long pad;

    dev_t dev;
    u32 fhandle;
    u64 fileid;
    loff_t offset;
    u32 arg_count;
    u32 res_count;
};

struct nfs_init_fields
{
    /* The first 8 bytes is not allowed to read */
    unsigned long pad;

    dev_t dev;
    u32 fhandle;
    u64 fileid;
    loff_t offset;
    u32 count;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1024);
} link_begin SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct rpc_task_info);
    __uint(max_entries, 1024);
} waiting_RPC SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1024);
} link_end SEC(".maps");

struct raw_metrics *unused_raw_metrics __attribute__((unused));
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct raw_metrics);
    __uint(max_entries, 4096);
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
    u32 dev_id;
    u32 file_id;
    u64 key;
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

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    event.dev_id = BPF_CORE_READ(inode, i_sb, s_dev);
    event.file_id = BPF_CORE_READ(inode, i_ino);
    event.key = (((u64)event.dev_id) << 32) | (event.file_id & 0xFFFFFFFF);

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

    // 输出件到 perf 事件数组
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
SEC("tracepoint/nfs/nfs_initiate_read")
int nfs_init_read(struct nfs_init_fields *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();

    bpf_map_update_elem(&link_begin, &pid, &timestamp, BPF_ANY);

    return 0;
}

SEC("tracepoint/nfs/nfs_initiate_write")
int nfs_init_write(struct nfs_init_fields *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();

    bpf_map_update_elem(&link_begin, &pid, &timestamp, BPF_ANY);

    return 0;
}

SEC("tracepoint/sunrpc/rpc_task_begin")
int rpc_task_begin(struct rpc_task_state *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 rpc_task_id = (u64)ctx->task_id;

    u64 *timestamp = bpf_map_lookup_elem(&link_begin, &pid);
    if (timestamp)
    {
        struct rpc_task_info info = {
            .timestamp = *timestamp,
            .tid = tid,
            .pid = pid};
        bpf_map_update_elem(&waiting_RPC, &rpc_task_id, &info, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/sunrpc/rpc_task_end")
int rpc_task_done(struct rpc_task_state *ctx)
{
    u64 rpc_task_id = (u64)ctx->task_id;
    struct rpc_task_info *info = bpf_map_lookup_elem(&waiting_RPC, &rpc_task_id);
    if (info)
    {
        // 更新 link_end map
        int update_result = bpf_map_update_elem(&link_end, &info->pid, &info->timestamp, BPF_ANY);
        if (update_result != 0)
        {
            return 0;
        }

        // 从 waiting_RPC map 中删除元素
        int delete_result = bpf_map_delete_elem(&waiting_RPC, &rpc_task_id);
        if (delete_result != 0)
        {
            return 0;
        }
    }

    return 0;
}

SEC("kprobe/nfs_readpage_done")
int kb_nfs_read_d(struct pt_regs *regs)
{
    struct rpc_task *task;
    struct inode *inode;
    struct nfs_pgio_header *hdr;
    u64 current_time = bpf_ktime_get_ns();

    task = (struct rpc_task *)PT_REGS_PARM1(regs);

    // 获取 rpc owner pid
    u32 pid = BPF_CORE_READ(task, tk_owner);
    inode = (struct inode *)PT_REGS_PARM3(regs);
    hdr = (struct nfs_pgio_header *)PT_REGS_PARM2(regs);

    // 获取 dev 和 fileid
    u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    u64 fileid = BPF_CORE_READ(inode, i_ino);
    u64 key = (((u64)dev) << 32) | (fileid & 0xFFFFFFFF);

    // 获取读取字节数
    u32 res_count = BPF_CORE_READ(hdr, res.count);

    struct raw_metrics *metrics = bpf_map_lookup_elem(&io_metrics, &key);
    if (!metrics)
    {
        struct raw_metrics new_metrics = {0};
        bpf_map_update_elem(&io_metrics, &key, &new_metrics, BPF_ANY);
        metrics = bpf_map_lookup_elem(&io_metrics, &key);
        if (!metrics)
            return 0;
    }

    // 计算读操作延迟
    u64 *start_time = bpf_map_lookup_elem(&link_end, &pid);
    if (start_time)
    {
        metrics->read_lat += current_time - *start_time;
        bpf_map_delete_elem(&link_begin, &pid);
    }

    // 更新读操作计数和字节数
    __sync_fetch_and_add(&metrics->read_count, 1);
    __sync_fetch_and_add(&metrics->read_size, res_count);

    // 更新 io_metrics map
    bpf_map_update_elem(&io_metrics, &key, metrics, BPF_ANY);

    // bpf_printk("Read - dev: %llu, file: %llu, bytes: %u, count: %d, total_bytes: %d, latency: %d\n",
    //            dev, fileid, res_count, metrics->read_count, metrics->read_size, metrics->read_lat);

    return 0;
}

SEC("kprobe/nfs_writeback_done")
int kb_nfs_write_d(struct pt_regs *regs)
{
    int pid;
    struct rpc_task *task;
    struct inode *inode;
    struct nfs_pgio_header *hdr;
    u64 current_time = bpf_ktime_get_ns();

    task = (struct rpc_task *)PT_REGS_PARM1(regs);

    // 获取 rpc owner pid
    pid = BPF_CORE_READ(task, tk_owner);
    inode = (struct inode *)PT_REGS_PARM3(regs);
    hdr = (struct nfs_pgio_header *)PT_REGS_PARM2(regs);

    // 获取 dev 和 fileid
    struct nfs_write_data *wdata = BPF_CORE_READ(task, tk_msg.rpc_argp);
    u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    u64 fileid = BPF_CORE_READ(inode, i_ino);
    u64 key = (((u64)dev) << 32) | (fileid & 0xFFFFFFFF);
    // 获取写入字节数
    u32 res_count = BPF_CORE_READ(hdr, res.count);

    struct raw_metrics *metrics = bpf_map_lookup_elem(&io_metrics, &key);
    if (!metrics)
    {
        struct raw_metrics new_metrics = {0};
        bpf_map_update_elem(&io_metrics, &key, &new_metrics, BPF_ANY);
        metrics = bpf_map_lookup_elem(&io_metrics, &key);
        if (!metrics)
            return 0;
    }

    // 计算写操作延迟
    u64 *start_time = bpf_map_lookup_elem(&link_end, &pid);
    if (start_time)
    {
        metrics->write_lat += current_time - *start_time;
        bpf_map_delete_elem(&link_begin, &pid);
    }

    // 更新写操作计数和字节数
    __sync_fetch_and_add(&metrics->write_count, 1);
    __sync_fetch_and_add(&metrics->write_size, res_count);

    // 更新 io_metrics map
    bpf_map_update_elem(&io_metrics, &key, metrics, BPF_ANY);

    // bpf_printk("Write - dev: %llu, file: %llu, bytes: %u, count: %d, total_bytes: %d, latency: %d\n",
    //            dev, fileid, res_count, metrics->write_count, metrics->write_size, metrics->write_lat);

    return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
