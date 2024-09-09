package output

import (
	"context"
	"fmt"
	"log"
	"time"

	ebpfbinary "github.com/cen-ngc5139/nfs-trace/internal/binary"
	"github.com/cen-ngc5139/nfs-trace/internal/cache"
	"github.com/cilium/ebpf"
)

// 解析 key 为 dev id 和 file id
func parseKey(key uint64) (devID uint32, fileID uint32) {
	devID = uint32(key >> 32)
	fileID = uint32(key & 0xFFFFFFFF)
	return
}

func ProcessMetrics(coll *ebpf.Collection, ctx context.Context) {
	events := coll.Maps["io_metrics"]

	fmt.Printf("DEV \t\t File \t\t Read IOPS \t\t Write IOPS \t\t Read Bytes \t\t Write Bytes \n")
	var event ebpfbinary.KProbePWRURawMetrics

	for {
		var nextKey uint64
		var count int
		iter := events.Iterate()
		for iter.Next(&nextKey, &event) {
			devID, fileID := parseKey(nextKey)
			// TODO：此处 fileID 为 inode id，该 id 为 NFS server 侧的 inode id ，后续需要实现从 server inode id 获取文件的目录路径
			fmt.Printf("%d \t\t%d \t\t%d \t\t\t%d \t\t\t%d \t\t\t%d \n",
				devID, fileID, event.ReadCount, event.WriteCount, event.ReadSize, event.WriteSize)

			// 持久化数据到 cache.NFSPerformanceMap 缓存中
			cache.NFSPerformanceMap.Store(nextKey, event)

			// 统计文件的读写次数
			count++
		}
		if err := iter.Err(); err != nil {
			log.Fatalf("遍历 map 时发生错误: %v", err)
		}

		fmt.Printf("统计文件的读写次数: %d\n", count)

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
			continue
		}
	}

}
