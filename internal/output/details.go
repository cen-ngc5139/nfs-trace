package output

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	ebpfbinary "github.com/cen-ngc5139/nfs-trace/internal/binary"
	"github.com/cen-ngc5139/nfs-trace/internal/bpf"
	"github.com/cen-ngc5139/nfs-trace/internal/cache"
	"github.com/cen-ngc5139/nfs-trace/internal/config"
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cen-ngc5139/nfs-trace/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"k8s.io/klog/v2"
)

func ProcessEvents(coll *ebpf.Collection, ctx context.Context, addr2name bpf.Addr2Name, cfg config.Configuration) {
	events := coll.Maps["nfs_trace_map"]
	// Set up a perf reader to read events from the eBPF program
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf reader failed: %v\n", err)
	}
	defer rd.Close()

	var event ebpfbinary.NFSTraceRpcTaskFields
	for {
		for {
			if err := parseEvent(rd, &event); err == nil {
				break
			}

			select {
			case <-ctx.Done():
				log.Infof("退出事件处理")
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		mountPath := config.GetProcPath(fmt.Sprintf("%d/mountinfo", event.Pid))
		mountList, err := metadata.ParseMountInfo(mountPath)
		if err != nil {
			klog.Errorf("Failed to get mount info: %v", err)
			continue
		}

		mountInfo, err := metadata.GetMountInfoFormObj(fmt.Sprintf("%d", event.MountId), mountList)
		if err != nil {
			klog.Errorf("Failed to get mount info: %v", err)
			continue
		}

		funcName := addr2name.FindNearestSym(event.CallerAddr)
		podName := sanitizeString(convertInt8ToString(event.Pod[:]))
		containerName := sanitizeString(convertInt8ToString(event.Container[:]))

		mount := metadata.NFSFile{
			MountPath:     mountInfo.LocalMountDir,
			RemoteNFSAddr: mountInfo.RemoteNFSAddr,
			LocalMountDir: mountInfo.LocalMountDir,
			Pod:           podName,
			Container:     containerName,
		}

		filePath, ok := cache.NFSFileDetailMap.Load(event.Key)
		if ok {
			mount.FilePath = filePath.(string)
		}

		log.StdoutOrFile(cfg.Output.Type, mount, map[string]interface{}{"funcName": funcName})

		// 保存devID+fileID和文件信息的映射关系, 如果已经存在，则覆盖
		cache.NFSDevIDFileIDFileInfoMap.Store(event.Key, mount)

		select {
		case <-ctx.Done():
			log.Infof("退出事件处理")
			return
		default:
		}
	}
}

func sanitizeString(s string) string {
	return strings.TrimSpace(s)
}
