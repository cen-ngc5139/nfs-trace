package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cen-ngc5139/nfs-trace/internal"
	"github.com/cen-ngc5139/nfs-trace/internal/metadata"
	"github.com/cen-ngc5139/nfs-trace/internal/queue"
	"github.com/cen-ngc5139/nfs-trace/internal/watch"
	k8sclient "github.com/cen-ngc5139/nfs-trace/pkg/client"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	flag := internal.Flags{}
	flag.SetFlags()
	flag.Parse()

	stopChan := make(chan struct{})
	defer close(stopChan)

	monitor := metadata.NewMountInfoMonitor(metadata.UpdateMountInfoCache, 5*time.Second)

	monitor.Start()
	defer monitor.Stop()

	// Remove memory limit for eBPF programs
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Set the rlimit for the number of open file descriptors to 8192.
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		klog.Fatalf("failed to set temporary rlimit: %s", err)
	}

	var btfSpec *btf.Spec
	var err error
	if flag.KernelBTF != "" {
		btfSpec, err = btf.LoadSpec(flag.KernelBTF)
	} else {
		// load kernel BTF spec from /sys/kernel/btf/vmlinux
		btfSpec, err = btf.LoadKernelSpec()
	}

	if err != nil {
		klog.Fatalf("Failed to load BTF spec: %s", err)
	}

	if len(flag.ModelBTF) == 0 {
		flag.ModelBTF = "/sys/kernel/btf"
	}

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

	var addFuncs internal.Funcs
	addFuncs = make(map[string]int)
	if flag.AddFuncs != "" {
		addFuncs = internal.SplitCustomFunList(flag.AddFuncs)
	}

	// filter functions
	funcs, err := internal.GetFuncs(flag.FilterFunc, flag.FilterStruct, flag.ModelBTF, btfSpec, kmods, false)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
	}

	// add functions
	if len(addFuncs) != 0 {
		funcs = internal.MergerFunList(funcs, addFuncs)
	}

	funcs.ToString()

	if flag.SkipAttach {
		klog.Info("Skipping attaching kprobes")
		return
	}

	// get function addresses
	addr2name, _, err := internal.ParseKallsyms(funcs, true)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction

	// load bpf spec
	var bpfSpec *ebpf.CollectionSpec
	bpfSpec, err = LoadKProbePWRU()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
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

	// attach kprobes
	k := internal.NewKprober(ctx, funcs, coll, addr2name, false, 10)
	defer k.DetachKprobes()

	log.Println("Listening for events..")

	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Received signal, exiting program..")
		default:
			log.Printf("exiting program..\n")
		}
	}()

	events := coll.Maps["rpc_task_map"]
	// Set up a perf reader to read events from the eBPF program
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating perf reader failed: %v\n", err)
		os.Exit(1)
	}
	defer rd.Close()

	// 初始化 k8s 客户端
	mgr := k8sclient.NewK8sManager()
	if err = mgr.CreateClient(); err != nil {
		log.Panicf("Create k8s client failed, error :%v", err)
	}

	if err = watch.SyncPodStatus(mgr, stopChan); err != nil {
		log.Panicf("Sync pod status failed, error :%v", err)
	}

	pidMap := coll.Maps["pid_cgroup_map"]
	queue.Source.WithEbpfMap(pidMap)
	// 启动 spark job pod 就绪清理控制器
	go queue.Source.Export()

	fmt.Printf("Addr \t\t PID \t\t Pod Name \t\t Container ID \t\t Mount \t\t NFS Mount \t\t File \t\t MountID \n")
	var event KProbePWRURpcTaskFields
	for {
		for {
			if err := parseEvent(rd, &event); err == nil {
				break
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		mountList, err := metadata.ParseMountInfo(fmt.Sprintf("/proc/%d/mountinfo", event.Pid))
		if err != nil {
			klog.Errorf("Failed to get mount info: %v", err)
			continue
		}

		mountInfo, err := metadata.GetMountInfoFormObj(fmt.Sprintf("%d", event.MountId), mountList)
		if err != nil {
			klog.Errorf("Failed to get mount info: %v", err)
			continue
		}

		funcName := addr2name.FindNearestSym(event.CallerAddr)
		fmt.Printf("%s \t\t%d \t\t%s \t\t%s \t\t%s \t\t%s \t\t%s \t\t%d \n",
			funcName, event.Pid, convertInt8ToString(event.Pod[:]), convertInt8ToString(event.Container[:]),
			mountInfo.LocalMountDir, mountInfo.RemoteNFSAddr, parseFileName(event.File[:]), event.MountId)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func parseEvent(rd *perf.Reader, event *KProbePWRURpcTaskFields) error {
	record, err := rd.Read()
	if err != nil {
		return err
	}

	if record.RawSample == nil {
		return errors.New("record.RawSample is nil")
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, event); err != nil {
		return err
	}

	return nil
}

func convertInt8ToString(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return string(ba)
}

func parseFileName(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return strings.ReplaceAll(filterNonASCII(ba), "//", "/")
}

func filterNonASCII(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 { // 只保留可见 ASCII 字符
			sb.WriteByte(b)
		}
	}
	return sb.String()
}
