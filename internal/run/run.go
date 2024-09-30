package run

import (
	"context"
	"errors"
	"fmt"

	"github.com/cen-ngc5139/nfs-trace/internal/bpf"
	"github.com/cen-ngc5139/nfs-trace/internal/config"

	ebpfbinary "github.com/cen-ngc5139/nfs-trace/internal/binary"
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cen-ngc5139/nfs-trace/internal/metadata"
	"github.com/cen-ngc5139/nfs-trace/internal/output"
	"github.com/cen-ngc5139/nfs-trace/internal/queue"
	"github.com/cen-ngc5139/nfs-trace/internal/server"
	"github.com/cen-ngc5139/nfs-trace/internal/watch"
	k8sclient "github.com/cen-ngc5139/nfs-trace/pkg/client"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"os"
	"os/signal"
	"syscall"
	"time"
)

func Run(cfg config.Configuration) {
	if cfg.ConfigPath != "" {
		err := config.LoadConfig(&cfg)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	}

	stopChan := make(chan struct{})
	defer close(stopChan)

	monitor := metadata.NewMountInfoMonitor(metadata.UpdateMountInfoCache, 5*time.Second)

	monitor.Start()
	defer monitor.Stop()

	// 移除 eBPF 程序的内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 设置临时 rlimit
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}

	// 获取 BPF 程序的入口函数名
	var btfSpec *btf.Spec
	var err error
	if cfg.BTF.Kernel != "" {
		btfSpec, err = btf.LoadSpec(cfg.BTF.Kernel)
	} else {
		// 从 /sys/kernel/btf/vmlinux 加载内核 BTF 规范
		btfSpec, err = btf.LoadKernelSpec()
	}

	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}

	if cfg.BTF.ModelDir == "" {
		cfg.BTF.ModelDir = "/sys/kernel/btf"
	}

	// 获取所有内核模块
	kmods := make([]string, 0)
	if cfg.Probing.AllKMods {
		// 获取所有内核模块
		files, err := os.ReadDir(cfg.BTF.ModelDir)
		if err != nil {
			log.Fatalf("Failed to read directory: %s", err)
		}

		for _, file := range files {
			if !file.IsDir() && file.Name() != "vmlinux" {
				kmods = append(kmods, file.Name())
			}
		}
	}

	// 获取需要添加的函数
	var addFuncs bpf.Funcs
	addFuncs = make(map[string]int)
	if cfg.Probing.AddFuncs != "" {
		addFuncs = bpf.SplitCustomFunList(cfg.Probing.AddFuncs)
	}

	// 获取需要过滤的函数
	funcs, err := bpf.GetFuncs(cfg.Filter.Func, cfg.Filter.Struct, cfg.BTF.ModelDir, btfSpec, kmods, false)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
	}

	// 添加函数
	if len(addFuncs) != 0 {
		funcs = bpf.MergerFunList(funcs, addFuncs)
	}

	funcs.ToString()

	if cfg.Probing.SkipAttach {
		log.Info("Skipping attaching kprobes")
		return
	}

	// 获取函数地址
	addr2name, _, err := bpf.ParseKallsyms(funcs, true)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction

	// 加载 ebpf 程序集
	var bpfSpec *ebpf.CollectionSpec
	bpfSpec, err = ebpfbinary.LoadNFSTrace()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	// 根据 flag 更新 bpfSpec
	upateBpfSpecWithFlags(bpfSpec, cfg)

	// 获取配置
	traceConfig, err := bpf.GetConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to get trace config: %v", err)
	}

	// 将配置写入到 bpf 程序中
	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": traceConfig,
	}); err != nil {
		log.Fatalf("Failed to rewrite config: %v", err)
	}

	// 加载 ebpf 程序集
	coll, err := ebpf.NewCollectionWithOptions(bpfSpec, opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}
	defer coll.Close()

	// 根据 flag 获取 kprobe 附加关系
	nfsKprobeProgs := getKprobeAttachMap(cfg)

	// 如果启用 NFS 指标，则附加 tracepoint
	if cfg.Features.NFSMetrics {
		trace, hasError, err := bpf.AttachTracepoint(coll)
		if err != nil {
			log.Fatalf("Failed to attach tracepoint: %v", err)
		}
		defer trace.Detach()

		// 如果 tracepoint 附加 rpc_task_begin/rpc_task_end 成功
		// 说明当前内核版本支持以上两个 tracepoint
		// 则删除 rpc_exit_task 和 rpc_execute 的 kprobe
		// tracepoint rpc_task_begin/rpc_task_end 挂载点与 kprobe rpc_exit_task/rpc_execute 挂载点冲突

		if !hasError {
			delete(nfsKprobeProgs, "rpc_exit_task")
			delete(nfsKprobeProgs, "rpc_execute")
		}
	}

	// 将 NFS 追踪的 kprobe 附加到内核
	k := bpf.NewKprober(ctx, funcs, coll, addr2name, false, 10)
	defer k.DetachKprobes()

	if len(nfsKprobeProgs) != 0 {
		// 将 NFS 追踪的 kprobe 附加到内核
		c := bpf.NewCustomFuncsKprober(nfsKprobeProgs, coll)
		defer c.DetachKprobes()
	}

	log.Info("Listening for events..")

	defer func() {
		select {
		case <-ctx.Done():
			log.Info("Received signal, exiting program..")
		default:
			log.Info("exiting program..\n")
		}
	}()

	// 初始化 k8s 客户端
	mgr := k8sclient.NewK8sManager()
	if err = mgr.CreateClient(); err != nil {
		log.Fatalf("Create k8s client failed, error :%v", err)
	}

	// 监听当前节点容器 pid 变化
	if err = watch.SyncPodStatus(mgr, stopChan); err != nil {
		log.Fatalf("Sync pod status failed, error :%v", err)
	}

	// 容器 pid 变化后，更新 ebpf map
	queue.Source.WithEbpfMap(coll.Maps["pid_cgroup_map"])
	go queue.Source.Export()

	// 启动任务管理器，从 ebpf map 中获取数据并进行处理
	tm := NewTaskManager()

	// 添加任务

	tm.Add("处理事件", func() error { output.ProcessEvents(coll, ctx, addr2name, cfg); return nil })
	tm.Add("处理文件", func() error { output.ProcessFiles(coll, ctx); return nil })

	if cfg.Features.NFSMetrics {
		tm.Add("服务器", func() error { return server.NewServer().Start() })
		tm.Add("处理指标", func() error { output.ProcessMetrics(coll, ctx); return nil })
	}

	if cfg.Features.DNS {
		tm.Add("处理 DNS", func() error { output.ProcessDNS(coll, ctx, cfg); return nil })
	}

	// 运行所有任务
	if err := tm.Run(); err != nil {
		fmt.Printf("错误: %v\n", err)
	}
}
