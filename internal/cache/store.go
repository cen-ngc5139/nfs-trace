package cache

import "sync"

// PodContainerPIDMap 保存pod container id 和 pid的映射关系
// key: container id
// value: pid
var PodContainerPIDMap *sync.Map

// MountInfoMap 保存mount id 和 mount info的映射关系
// key: mount id
// value: metadata.MountInfo
var MountInfoMap *sync.Map

// NFSPerformanceMap 保存nfs地址和性能信息的映射关系
// key: devID+fileID
// value: metadata.NFSTraceInfo
var NFSPerformanceMap *sync.Map

// NFSDevIDFileIDFileInfoMap 保存devID+fileID和文件信息的映射关系
// key: devID+fileID
// value: metadata.NFSFile
var NFSDevIDFileIDFileInfoMap *sync.Map

// NFSFileDetailMap 保存文件的详细信息
// key: devID+fileID
// value: string
var NFSFileDetailMap *sync.Map

func init() {
	PodContainerPIDMap = new(sync.Map)
	MountInfoMap = new(sync.Map)
	NFSPerformanceMap = new(sync.Map)
	NFSDevIDFileIDFileInfoMap = new(sync.Map)
	NFSFileDetailMap = new(sync.Map)
}
