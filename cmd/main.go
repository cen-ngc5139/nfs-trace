package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/cen-ngc5139/nfs-trace/internal"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	filterFunc, filterStruct string
)

func main() {
	flag.StringVar(&filterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	flag.StringVar(&filterStruct, "filter-struct", "", "filter kernel structs to be probed by name (ex. sk_buff/rpc_task)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Set the rlimit for the number of open file descriptors to 8192.
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		klog.Fatalf("failed to set temporary rlimit: %s", err)
	}

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		klog.Fatalf("Failed to load BTF spec: %s", err)
	}

	files, err := os.ReadDir("/sys/kernel/btf")
	if err != nil {
		log.Fatalf("Failed to read directory: %s", err)
	}

	kmods := make([]string, 0)
	for _, file := range files {
		if !file.IsDir() && file.Name() != "vmlinux" {
			kmods = append(kmods, file.Name())
		}
	}

	funcs, err := internal.GetFuncs(filterFunc, filterStruct, btfSpec, kmods, false)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
	}

	funcs.ToString()
	addr2name, _, err := internal.ParseKallsyms(funcs, false)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100

	var bpfSpec *ebpf.CollectionSpec
	bpfSpec, err = LoadKProbePWRU()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

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

	k := internal.NewKprober(ctx, funcs, coll, addr2name, false, 10)
	defer k.DetachKprobes()

	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Received signal, exiting program..")
		default:
			log.Printf("exiting program..\n")
		}
	}()

	select {
	case <-ctx.Done():
		return
	default:
	}
}
