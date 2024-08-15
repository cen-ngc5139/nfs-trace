package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cen-ngc5139/nfs-trace/internal"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	flag := internal.Flags{}
	flag.SetFlags()
	flag.Parse()

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

	// filter functions
	funcs, err := internal.GetFuncs(flag.FilterFunc, flag.FilterStruct, flag.ModelBTF, btfSpec, kmods, false)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
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

	var event KProbePWRURpcTaskFields
	events := coll.Maps["rpc_task_map"]
	// Set up a perf reader to read events from the eBPF program
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating perf reader failed: %v\n", err)
		os.Exit(1)
	}
	defer rd.Close()

	fmt.Printf("Addr \t\tPID \t\tCgroup Name \n")
	for {
		record, err := rd.Read()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Reading from perf reader failed: %v\n", err)
			os.Exit(1)
		}

		if record.RawSample == nil {
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			fmt.Fprintf(os.Stderr, "Parsing event data failed: %v\n", err)
			os.Exit(1)
		}

		funcName := addr2name.FindNearestSym(event.CallerAddr)
		fmt.Printf("%s \t\t%d \t\t%s \n",
			funcName, event.OwnerPid, convertInt8ToString(event.CgroupName[:]))

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func convertInt8ToString(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return string(ba)
}
