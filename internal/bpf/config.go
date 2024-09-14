package bpf

type FilterCfg struct {
	EnableDebug uint8
}

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func GetConfig(flags *Flags) (cfg FilterCfg, err error) {
	cfg = FilterCfg{
		EnableDebug: boolToUint8(flags.EnableDebug),
	}

	return
}
