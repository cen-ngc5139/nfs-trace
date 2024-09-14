package bpf

import (
	"flag"

	"github.com/spf13/pflag"
)

type Flags struct {
	FilterFunc            string
	FilterStruct          string
	ModelBTF              string
	KernelBTF             string
	AllKMods              bool
	SkipAttach            bool
	AddFuncs              string
	LogLevel              int
	OutputDetails         bool
	OutPerformanceMetrics bool
	EnableDebug           bool
}

func (f *Flags) SetFlags(pflag *pflag.FlagSet) {
	pflag.AddGoFlagSet(flag.CommandLine)
	pflag.StringVar(&f.FilterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	pflag.StringVar(&f.FilterStruct, "filter-struct", "", "filter kernel structs to be probed by name (ex. sk_buff/rpc_task)")
	pflag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	pflag.StringVar(&f.ModelBTF, "model-btf-dir", "", "specify kernel model BTF dir")
	pflag.BoolVar(&f.AllKMods, "all-kmods", false, "attach to all available kernel modules")
	pflag.BoolVar(&f.SkipAttach, "skip-attach", false, "skip attaching kprobes")
	pflag.StringVar(&f.AddFuncs, "add-funcs", "", "add functions to be probed by name (ex. rpc_task:1,sk_buff:2)")
	pflag.IntVar(&f.LogLevel, "log-level", 2, "set log level(ex. 0: no log, 1: error, 2: info, 3: debug)")
	pflag.BoolVar(&f.OutputDetails, "output-details", false, "output details of the probed functions")
	pflag.BoolVar(&f.OutPerformanceMetrics, "output-metrics", false, "output performance metrics")
	pflag.BoolVar(&f.EnableDebug, "enable-debug", false, "enable debug mode")

	pflag.Set("logtostderr", "false")
	pflag.Set("alsologtostderr", "false")
	pflag.Set("log_file", "")
}
