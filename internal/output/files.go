package output

import (
	"context"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cen-ngc5139/nfs-trace/internal/binary"
	"github.com/cen-ngc5139/nfs-trace/internal/cache"
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type PathCache struct {
	paths         *sync.Map
	partialBuffer map[uint64][]binary.KProbePWRUPathSegment
}

func NewPathCache() *PathCache {
	return &PathCache{
		paths:         cache.NFSFileDetailMap,
		partialBuffer: make(map[uint64][]binary.KProbePWRUPathSegment),
	}
}

func (pc *PathCache) Get(devID, fileID uint64) (string, bool) {
	key := (devID << 32) | fileID
	if value, ok := pc.paths.Load(key); ok {
		return value.(string), true
	}
	return "", false
}

func (pc *PathCache) Set(devID, fileID uint64, path string) {
	key := (devID << 32) | fileID
	pc.paths.Store(key, path)
}

// rebuildPath 重建路径
func rebuildPath(segments []binary.KProbePWRUPathSegment) string {
	sort.Slice(segments, func(i, j int) bool {
		return segments[i].Depth > segments[j].Depth
	})

	var path strings.Builder
	for _, seg := range segments {
		fileName := unix.ByteSliceToString(seg.Name[:])
		if fileName != "/" {
			path.WriteByte('/')
		}
		path.Write([]byte(fileName))
	}
	return strings.ReplaceAll(path.String(), "//", "/")
}

func ProcessFiles(coll *ebpf.Collection, ctx context.Context) {
	events := coll.Maps["path_ringbuf"]
	// Set up a perf reader to read events from the eBPF program
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf reader failed: %v\n", err)
	}
	defer rd.Close()

	pc := NewPathCache()
	var event binary.KProbePWRUPathSegment
	for {
		for {
			if err := parseEvent(rd, &event); err == nil {
				break
			}

			select {
			case <-ctx.Done():
				log.Infof("退出文件处理")
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		key := (event.DevId << 32) | event.FileId
		if event.IsComplete != 0 {
			partial := pc.partialBuffer[key]
			partial = append(partial, event)

			path := rebuildPath(partial)
			pc.Set(event.DevId, event.FileId, path)
			delete(pc.partialBuffer, key)
		} else {
			// 如果是部分路径段，放入 partialBuffer
			pc.partialBuffer[key] = append(pc.partialBuffer[key], event)
		}

		select {
		case <-ctx.Done():
			log.Infof("退出文件处理")
			return
		default:
		}
	}
}
