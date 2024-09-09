# NFS Trace

NFS Trace is a powerful tool designed to monitor and analyze NFS (Network File System) operations using eBPF technology. It provides real-time insights into NFS performance metrics and helps diagnose issues in distributed file systems.

## Features

- Real-time monitoring of NFS read and write operations
- Performance metrics collection (IOPS, latency, throughput)
- Kubernetes integration for pod-level NFS usage tracking
- Prometheus metrics export for easy integration with monitoring systems
- Customizable function probing and filtering

## Prerequisites

- Linux kernel 6.8.0+ with BTF support
- Go 1.22+
- Kubernetes cluster (for K8s integration)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/cen-ngc5139/nfs-trace.git
   cd nfs-trace
   ```

2. Build the project:
   ```
   make build
   ```

## Usage

Run NFS Trace with default settings:

```
./nfs-trace
```

For more advanced usage and configuration options:

```
./nfs-trace --help
```

## Configuration

NFS Trace supports various command-line flags for customization. Some key options include:


```20:35:internal/types.go
func (f *Flags) SetFlags() {
	flag.StringVar(&f.FilterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	flag.StringVar(&f.FilterStruct, "filter-struct", "", "filter kernel structs to be probed by name (ex. sk_buff/rpc_task)")
	flag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	flag.StringVar(&f.ModelBTF, "model-btf-dir", "", "specify kernel model BTF dir")
	flag.BoolVar(&f.AllKMods, "all-kmods", false, "attach to all available kernel modules")
	flag.BoolVar(&f.SkipAttach, "skip-attach", false, "skip attaching kprobes")
	flag.StringVar(&f.AddFuncs, "add-funcs", "", "add functions to be probed by name (ex. rpc_task:1,sk_buff:2)")
	flag.IntVar(&f.LogLevel, "log-level", 2, "set log level(ex. 0: no log, 1: error, 2: info, 3: debug)")
	flag.BoolVar(&f.OutputDetails, "output-details", false, "output details of the probed functions")
	flag.BoolVar(&f.OutPerformanceMetrics, "output-metrics", false, "output performance metrics")
	// 禁用 klog 的默认输出
	flag.Set("logtostderr", "false")
	flag.Set("alsologtostderr", "false")
	flag.Set("log_file", "")
}
```


## Metrics

NFS Trace collects and exports the following metrics:

- NFS read/write count
- NFS read/write size
- NFS read/write latencies

These metrics are available via Prometheus endpoint at `/metrics`.

## Kubernetes Integration

NFS Trace can be deployed as a DaemonSet in your Kubernetes cluster to monitor NFS operations across all nodes. It provides pod-level visibility into NFS usage.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Dual BSD/GPL License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Cilium eBPF](https://github.com/cilium/ebpf) library
- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [Prometheus Go Client](https://github.com/prometheus/client_golang)

For more information on the implementation details, please refer to the source code and comments within the project.