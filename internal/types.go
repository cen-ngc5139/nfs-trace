package internal

import (
	"flag"
)

type Flags struct {
	FilterFunc   string
	FilterStruct string
	ModelBTF     string
	KernelBTF    string
	AllKMods     bool
	SkipAttach   bool
	AddFuncs     string
	LogLevel     int
}

func (f *Flags) SetFlags() {
	flag.StringVar(&f.FilterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	flag.StringVar(&f.FilterStruct, "filter-struct", "", "filter kernel structs to be probed by name (ex. sk_buff/rpc_task)")
	flag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	flag.StringVar(&f.ModelBTF, "model-btf-dir", "", "specify kernel model BTF dir")
	flag.BoolVar(&f.AllKMods, "all-kmods", false, "attach to all available kernel modules")
	flag.BoolVar(&f.SkipAttach, "skip-attach", false, "skip attaching kprobes")
	flag.StringVar(&f.AddFuncs, "add-funcs", "", "add functions to be probed by name (ex. rpc_task:1,sk_buff:2)")
	flag.IntVar(&f.LogLevel, "log-level", 2, "set log level(ex. 0: no log, 1: error, 2: info, 3: debug)")
}

func (f *Flags) Parse() {
	flag.Parse()
}
