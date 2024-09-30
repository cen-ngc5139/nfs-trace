package metadata

import "github.com/cen-ngc5139/nfs-trace/internal/binary"

type NFSFile struct {
	MountPath     string `json:"mount_path"`
	RemoteNFSAddr string `json:"remote_nfs_addr"`
	LocalMountDir string `json:"local_mount_dir"`
	FilePath      string `json:"file_path"`
	Pod           string `json:"pod"`
	Container     string `json:"container"`
}

type NFSTraceInfo struct {
	Traffic binary.NFSTraceRawMetrics `json:"traffic"`
	File    NFSFile                   `json:"file"`
}
