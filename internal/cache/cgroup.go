package cache

import "sync"

// PodContainerPIDMap 保存pod container id 和 pid的映射关系
// key: container id
// value: pid
var PodContainerPIDMap *sync.Map

func init() {
	PodContainerPIDMap = new(sync.Map)
}
