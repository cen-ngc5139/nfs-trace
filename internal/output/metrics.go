package output

import (
	"context"
	"time"

	ebpfbinary "github.com/cen-ngc5139/nfs-trace/internal/binary"
	"github.com/cen-ngc5139/nfs-trace/internal/bpf"
	"github.com/cen-ngc5139/nfs-trace/internal/cache"
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cen-ngc5139/nfs-trace/internal/metadata"
	"github.com/cilium/ebpf"
)

// 解析 key 为 dev id 和 file id
func parseKey(key uint64) (devID uint32, fileID uint32) {
	devID = uint32(key >> 32)
	fileID = uint32(key & 0xFFFFFFFF)
	return
}

func ProcessMetrics(coll *ebpf.Collection, ctx context.Context, flag *bpf.Flags) {
	events := coll.Maps["io_metrics"]
	var event ebpfbinary.KProbePWRURawMetrics

	for {
		var nextKey uint64
		var count int
		iter := events.Iterate()
		for iter.Next(&nextKey, &event) {
			// 从 metadata 中获取文件信息
			var file metadata.NFSFile
			fileInfo, ok := cache.NFSDevIDFileIDFileInfoMap.Load(nextKey)
			if ok {
				file = fileInfo.(metadata.NFSFile)
			}

			traceInfo := metadata.NFSTraceInfo{Traffic: event, File: file}

			// 持久化数据到 cache.NFSPerformanceMap 缓存中
			cache.NFSPerformanceMap.Store(nextKey, traceInfo)

			// 统计文件的读写次数
			count++
		}
		if err := iter.Err(); err != nil {
			log.Fatalf("遍历 map 时发生错误: %v", err)
		}

		log.Infof("统计文件的读写次数: %d\n", count)

		select {
		case <-ctx.Done():
			log.Infof("退出指标处理")
			return
		case <-time.After(time.Second):
			continue
		}
	}

}
