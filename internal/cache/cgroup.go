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

func init() {
	PodContainerPIDMap = new(sync.Map)
	MountInfoMap = new(sync.Map)
}
