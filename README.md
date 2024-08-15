# nfs-trace

尝试追踪 NFS 包在内核中的调用路径

## 命令行参数

以下是 `nfs-trace` 支持的命令行参数：

- `--filter-struct`：指定要过滤的结构体名称。例如：`--filter-struct=rpc_task`
- `--all-kmods`：指定是否获取所有内核模块。接受 `true` 或 `false`。例如：`--all-kmods=true`
- `--skip-attach`：指定是否跳过附加 kprobes，仅打印内核函数名称以及入参索引。接受 `true` 或 `false`。例如：`--skip-attach=true`
- `--filter-func`：指定要过滤的函数名称。例如：`--filter-func="^nfs.*"`
- `--kernel-btf`：指定内核 BTF 文件。例如：`--kernel-btf=/sys/kernel/btf/vmlinux`
- `--model-btf-dir`：指定内核模块 BTF 目录。例如：`--model-btf-dir=/sys/kernel/btf`

## 使用示例

### 搜索内核函数
以下命令是用于搜索入参参数结构体为 `kiocb` 的内核函数名称，同时会答应该参数的位置索引：
```sh
# ./cmd/nfs-trace-linux-amd64 -filter-struct=kiocb -skip-attach=true -all-kmods=true -filter-func="^nfs.*"
I0815 02:15:41.692055    9232 filter.go:17] nfs_swap_rw 1
I0815 02:15:41.692222    9232 filter.go:17] nfs_file_read 1
I0815 02:15:41.692239    9232 filter.go:17] nfs_file_write 1
I0815 02:15:41.692249    9232 filter.go:17] nfs_file_direct_read 1
I0815 02:15:41.692261    9232 filter.go:17] nfs_file_direct_write 1
I0815 02:15:41.692338    9232 main.go:85] Skipping attaching kprobes
```

### 自定义 BTF 文件
```shell
# ./cmd/nfs-trace-linux-amd64 -kernel-btf=/data/gb/external.btf -filter-struct=kiocb -filter-func="^nfs.*"
```

### 自定义 BTF 目录
```shell
# ./cmd/nfs-trace-linux-amd64 -model-btf-dir=/data/btf -filter-struct=kiocb -all-kmods=true -filter-func="^nfs.*"
```