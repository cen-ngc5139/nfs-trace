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
// value: binary.KProbePWRURawMetrics
var NFSPerformanceMap *sync.Map

func init() {
	PodContainerPIDMap = new(sync.Map)
	MountInfoMap = new(sync.Map)
	NFSPerformanceMap = new(sync.Map)
}
