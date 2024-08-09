// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package internal

import (
	"bufio"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"os"
)

// getAvailableFilterFunctions return list of functions to which it is possible
// to attach kprobes.
func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}
func GetFuncsByPos(funcs Funcs) map[int][]string {
	ret := make(map[int][]string, len(funcs))
	for fn, pos := range funcs {
		ret[pos] = append(ret[pos], fn)
	}
	return ret
}

// Very hacky way to check whether multi-link kprobe is supported.
func HaveBPFLinkKprobeMulti() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_kpm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceKprobeMulti,
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	opts := link.KprobeMultiOptions{Symbols: []string{"vprintk"}}
	link, err := link.KretprobeMulti(prog, opts)
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

// Very hacky way to check whether tracing link is supported.
func HaveBPFLinkTracing() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "fexit_skb_clone",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceFExit,
		AttachTo:   "skb_clone",
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

func HaveAvailableFilterFunctions() bool {
	_, err := getAvailableFilterFunctions()
	return err == nil
}
