package bpf

import (
	"github.com/cen-ngc5139/nfs-trace/internal/config"
)

type FilterCfg struct {
	EnableDebug uint8
}

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func GetConfig(flags config.Configuration) (cfg FilterCfg, err error) {
	cfg = FilterCfg{
		EnableDebug: boolToUint8(flags.Features.Debug),
	}

	return
}
