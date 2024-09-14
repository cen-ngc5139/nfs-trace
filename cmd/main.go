package main

import (
	"os"

	"github.com/cen-ngc5139/nfs-trace/internal/log"

	"github.com/cen-ngc5139/nfs-trace/internal/bpf"
	"github.com/cen-ngc5139/nfs-trace/internal/run"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	log.InitLogger("./log/", 100, 5, 30)
	defer klog.Flush()

	flag := bpf.Flags{}
	var rootCmd = &cobra.Command{
		Use:   "nfs-trace",
		Short: "A tool to trace nfs operations",
		Run: func(cmd *cobra.Command, args []string) {
			run.Run(flag)
		},
	}

	flag.SetFlags(rootCmd.Flags())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
