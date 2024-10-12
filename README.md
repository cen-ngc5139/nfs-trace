# NFS Trace

NFS Trace 是一个强大的工具，使用 eBPF 技术监控和分析 NFS（网络文件系统）操作。它提供了 NFS 性能指标的实时洞察，并帮助诊断分布式文件系统中的问题。

## 功能

- 实时监控 NFS 读写操作
- 性能指标收集（IOPS、延迟、吞吐量）
- Kubernetes 集成，用于 Pod 级别的 NFS 使用跟踪
- Prometheus 指标导出，便于与监控系统集成
- 可定制的函数探测和过滤

## 前提条件

- 支持 BTF 的 Linux 内核 4.19+
- Go 1.22+
- Kubernetes 集群（用于 K8s 集成）

已测试的操作系统和内核版本：
- KylinOS 10 SP3 (ARM64) - kernel 4.19.90
- Ubuntu 24.04 (AMD64) - kernel 6.8.0
- Ubuntu 22.04 (AMD64) - kernel 5.15.0
- Alibaba Cloud Linux OS 3 (AMD64) - kernel 5.10.134-16.3.al8 

## 安装

1. 克隆仓库：
   ```bash
   git clone https://github.com/cen-ngc5139/nfs-trace.git
   cd nfs-trace
   ```

2. 构建项目：
   ```bash
   make build
   ```

## 使用

使用默认设置运行 NFS Trace：

```
./nfs-trace
```

获取更多高级用法和配置选项：

```
./nfs-trace --help
```

### 阿里云 OS 专门启动方式

在阿里云 OS 上启动监控时，可以使用 `--kernel-btf` 参数指定 BTF 文件。以下是具体的启动命令示例：

```
./nfs-trace --kernel-btf=./deploy/btf/linux-5.10.134-16.3.al8-vmlinux.btf
```

请确保 `linux-5.10.134-16.3.al8-vmlinux.btf` 文件位于 `./deploy/btf/` 目录下。

## 配置

NFS Trace 支持各种命令行标志进行自定义。主要选项包括：

```
- `--filter-func`：通过名称过滤要探测的内核函数（精确匹配，支持 RE2 正则表达式）
- `--filter-struct`：通过名称过滤要探测的内核结构体（例如：sk_buff/rpc_task）
- `--kernel-btf`：指定内核 BTF 文件
- `--model-btf-dir`：指定内核模型 BTF 目录
- `--all-kmods`：附加到所有可用的内核模块
- `--skip-attach`：跳过附加 kprobes
- `--add-funcs`：添加要探测的函数名称（例如：rpc_task:1,sk_buff:2）
- `--output-type`：指定输出类型（例如：file, stdout, kafka, es, logstash, redis）
- `--enable-debug`：启用调试模式
- `--enable-dns`：启用 DNS 模式
- `--enable-nfs-metrics`：启用 NFS 指标模式
- `--config-path`：指定配置文件路径
```

同时支持通过配置文件进行配置，配置文件路径可以通过 `--config-path` 指定。

配置文件示例：

```yaml
filter:
  func: "^(vfs_|nfs_).*"
  struct: "kiocb"

probing:
  all_kmods: true
  skip_attach: false
  add_funcs: "nfs_file_direct_read:1,nfs_file_direct_write:1,nfs_swap_rw:1,nfs_file_read:1,nfs_file_write:1"

features:
  debug: false
  dns: true
  nfs_metrics: true

output:
  type: file
```

## 指标

NFS Trace 收集并导出以下指标：

- NFS 读/写次数
- NFS 读/写大小
- NFS 读/写延迟

这些指标可以通过 `/metrics` 的 Prometheus 端点获取。

## Kubernetes 集成

NFS Trace 可以作为 DaemonSet / Deployment 部署在您的 Kubernetes 集群中，以监控所有节点上的 NFS 操作。它提供了 Pod 级别的 NFS 使用可见性。

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 许可证

本项目采用 Dual BSD/GPL 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 致谢

- [Cilium eBPF](https://github.com/cilium/ebpf) 库
- [PWRU](https://github.com/cilium/pwru)
- [T Dubuc](http://perso.ens-lyon.fr/theophile.dubuc/files/CHEOPS24-TrackIOps.pdf)
- [DeepFlow](https://github.com/deepflow-tech/deepflow)
- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [Prometheus Go Client](https://github.com/prometheus/client_golang)

有关实现细节的更多信息，请参阅项目中的源代码和注释。