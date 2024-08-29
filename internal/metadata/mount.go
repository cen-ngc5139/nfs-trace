package metadata

import (
	"fmt"
	"github.com/cen-ngc5139/nfs-trace/internal/cache"
)

func UpdateMountInfoCache(mounts []MountInfo) {
	// 遍历所有的mount信息，更新到cache中
	for _, mount := range mounts {
		cache.MountInfoMap.LoadOrStore(mount.MountID, mount)
	}

	// 删除cache中不存在的mount信息
	cache.MountInfoMap.Range(func(key, value interface{}) bool {
		mountID := key.(string)
		if !isMountExist(mounts, mountID) {
			cache.MountInfoMap.Delete(mountID)
		}
		return true
	})

}

func isMountExist(mounts []MountInfo, id string) bool {
	for _, mount := range mounts {
		if mount.MountID == id {
			return true
		}
	}
	return false
}

func GetMountInfoFromCache(id string) (MountInfo, error) {
	if mount, ok := cache.MountInfoMap.Load(id); ok {
		return mount.(MountInfo), nil
	}
	return MountInfo{}, fmt.Errorf("mount info not found for id %s", id)
}

func GetMountInfoFormObj(id string, mounts []MountInfo) (MountInfo, error) {
	for _, mount := range mounts {
		if mount.MountID == id {
			return mount, nil
		}
	}
	return MountInfo{}, fmt.Errorf("mount info not found for id %s", id)
}
