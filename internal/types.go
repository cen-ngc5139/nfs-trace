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
}

func (f *Flags) SetFlags() {
	flag.StringVar(&f.FilterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	flag.StringVar(&f.FilterStruct, "filter-struct", "", "filter kernel structs to be probed by name (ex. sk_buff/rpc_task)")
	flag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	flag.StringVar(&f.ModelBTF, "model-btf-dir", "", "specify kernel model BTF dir")
	flag.BoolVar(&f.AllKMods, "all-kmods", false, "attach to all available kernel modules")
	flag.BoolVar(&f.SkipAttach, "skip-attach", false, "skip attaching kprobes")
}

func (f *Flags) Parse() {
	flag.Parse()
}
