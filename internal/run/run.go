package run

import (
	"context"
	"errors"
	"fmt"

	"github.com/cen-ngc5139/nfs-trace/internal/bpf"

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
	"sync"
	"syscall"
	"time"
)

func Run(flag bpf.Flags) {
	stopChan := make(chan struct{})
	defer close(stopChan)

	monitor := metadata.NewMountInfoMonitor(metadata.UpdateMountInfoCache, 5*time.Second)

	monitor.Start()
	defer monitor.Stop()

	// Remove memory limit for eBPF programs
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Set the rlimit for the number of open file descriptors to 8192.
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}

	// 获取 BPF 程序的入口函数名
	var btfSpec *btf.Spec
	var err error
	if flag.KernelBTF != "" {
		btfSpec, err = btf.LoadSpec(flag.KernelBTF)
	} else {
		// load kernel BTF spec from /sys/kernel/btf/vmlinux
		btfSpec, err = btf.LoadKernelSpec()
	}

	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}

	if len(flag.ModelBTF) == 0 {
		flag.ModelBTF = "/sys/kernel/btf"
	}

	// 获取所有内核模块
	kmods := make([]string, 0)
	if flag.AllKMods {
		// get all kernel modules
		files, err := os.ReadDir(flag.ModelBTF)
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
	if flag.AddFuncs != "" {
		addFuncs = bpf.SplitCustomFunList(flag.AddFuncs)
	}

	// filter functions
	funcs, err := bpf.GetFuncs(flag.FilterFunc, flag.FilterStruct, flag.ModelBTF, btfSpec, kmods, false)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
	}

	// add functions
	if len(addFuncs) != 0 {
		funcs = bpf.MergerFunList(funcs, addFuncs)
	}

	funcs.ToString()

	if flag.SkipAttach {
		log.Info("Skipping attaching kprobes")
		return
	}

	// get function addresses
	addr2name, _, err := bpf.ParseKallsyms(funcs, true)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction

	// load bpf spec
	var bpfSpec *ebpf.CollectionSpec
	bpfSpec, err = ebpfbinary.LoadKProbePWRU()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	// 将配置写入到 bpf 程序中
	pwruConfig, err := bpf.GetConfig(&flag)
	if err != nil {
		log.Fatalf("Failed to get pwru config: %v", err)
	}
	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": pwruConfig,
	}); err != nil {
		log.Fatalf("Failed to rewrite config: %v", err)
	}

	// load ebpf collection, collection is a set of programs
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

	trace, hasError, err := bpf.AttachTracepoint(coll)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer trace.Detach()

	// 如果 tracepoint 附加 rpc_task_begin/rpc_task_end 成功
	// 说明当前内核版本支持以上两个 tracepoint
	// 则删除 rpc_exit_task 和 rpc_execute 的 kprobe
	// tracepoint rpc_task_begin/rpc_task_end 挂载点与 kprobe rpc_exit_task/rpc_execute 挂载点冲突
	nfsKprobeProgs := bpf.NFSKprobeProgs
	if !hasError {
		delete(nfsKprobeProgs, "rpc_exit_task")
		delete(nfsKprobeProgs, "rpc_execute")
	}

	// attach kprobes
	k := bpf.NewKprober(ctx, funcs, coll, addr2name, false, 10)
	defer k.DetachKprobes()

	c := bpf.NewCustomFuncsKprober(nfsKprobeProgs, coll)
	defer c.DetachKprobes()

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

	if err = watch.SyncPodStatus(mgr, stopChan); err != nil {
		log.Fatalf("Sync pod status failed, error :%v", err)
	}

	pidMap := coll.Maps["pid_cgroup_map"]
	queue.Source.WithEbpfMap(pidMap)
	// 启动 spark job pod 就绪清理控制器
	go queue.Source.Export()

	s := server.NewServer()

	var wg sync.WaitGroup

	tasks := []struct {
		name string
		fn   func() error
	}{
		{"服务器", func() error { return s.Start() }},
		{"处理指标", func() error { output.ProcessMetrics(coll, ctx, flag.OutPerformanceMetrics); return nil }},
		{"处理事件", func() error { output.ProcessEvents(coll, ctx, addr2name); return nil }},
	}

	for _, task := range tasks {
		wg.Add(1)
		go func(t struct {
			name string
			fn   func() error
		}) {
			defer wg.Done()
			if err := t.fn(); err != nil {
				log.Errorf("%s 停止: %v", t.name, err)
			}
		}(task)
	}

	// 等待所有 goroutine 结束
	wg.Wait()
}
