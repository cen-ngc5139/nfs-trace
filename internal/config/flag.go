package config

import (
	"flag"

	"github.com/spf13/pflag"
)

func SetFlags(pflag *pflag.FlagSet) {
	pflag.AddGoFlagSet(flag.CommandLine)
	pflag.StringVar(&Config.Filter.Func, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	pflag.StringVar(&Config.Filter.Struct, "filter-struct", "", "filter kernel structs to be probed by name (ex. sk_buff/rpc_task)")

	pflag.StringVar(&Config.BTF.Kernel, "kernel-btf", "", "specify kernel BTF file")
	pflag.StringVar(&Config.BTF.ModelDir, "model-btf-dir", "", "specify kernel model BTF dir")
	pflag.BoolVar(&Config.Probing.AllKMods, "all-kmods", false, "attach to all available kernel modules")
	pflag.BoolVar(&Config.Probing.SkipAttach, "skip-attach", false, "skip attaching kprobes")
	pflag.StringVar(&Config.Probing.AddFuncs, "add-funcs", "", "add functions to be probed by name (ex. rpc_task:1,sk_buff:2)")

	pflag.StringVar(&Config.Output.Type, "output-type", "file", "output type(ex. file, stdout, kafka, es, logstash, redis)")
	pflag.BoolVar(&Config.Features.Debug, "enable-debug", false, "enable debug mode")

	pflag.BoolVar(&Config.Features.DNS, "enable-dns", false, "enable dns mode")
	pflag.BoolVar(&Config.Features.NFSMetrics, "enable-nfs-metrics", false, "enable nfs metrics mode")
	pflag.StringVar(&Config.ConfigPath, "config-path", "", "specify config file path")

	pflag.Set("logtostderr", "false")
	pflag.Set("alsologtostderr", "false")
	pflag.Set("log_file", "")
}
