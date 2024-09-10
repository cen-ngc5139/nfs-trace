package output

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cen-ngc5139/nfs-trace/internal"
	ebpfbinary "github.com/cen-ngc5139/nfs-trace/internal/binary"
	"github.com/cen-ngc5139/nfs-trace/internal/cache"
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cen-ngc5139/nfs-trace/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"k8s.io/klog/v2"
)

func ProcessEvents(coll *ebpf.Collection, ctx context.Context, addr2name internal.Addr2Name) {
	events := coll.Maps["rpc_task_map"]
	// Set up a perf reader to read events from the eBPF program
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf reader failed: %v\n", err)
	}
	defer rd.Close()

	fmt.Printf("Addr \t\t PID \t\t Pod Name \t\t Container ID \t\t Mount \t\t NFS Mount \t\t File \t\t MountID \t\t DevID \t\t FileID \n")
	var event ebpfbinary.KProbePWRURpcTaskFields
	for {
		for {
			if err := parseEvent(rd, &event); err == nil {
				break
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		mountList, err := metadata.ParseMountInfo(fmt.Sprintf("/proc/%d/mountinfo", event.Pid))
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
		filePath := parseFileName(event.File[:])

		podName := sanitizeString(convertInt8ToString(event.Pod[:]))
		containerName := sanitizeString(convertInt8ToString(event.Container[:]))

		fmt.Printf("%s \t\t%d \t\t%s \t\t%s \t\t%s \t\t%s \t\t%s \t\t%d \t\t%d \t\t%d \n",
			funcName, event.Pid, podName, containerName,
			mountInfo.LocalMountDir, mountInfo.RemoteNFSAddr, filePath, event.MountId, event.DevId, event.FileId)

		mount := metadata.NFSFile{
			MountPath:     mountInfo.LocalMountDir,
			RemoteNFSAddr: mountInfo.RemoteNFSAddr,
			LocalMountDir: mountInfo.LocalMountDir,
			FilePath:      filePath,
			Pod:           podName,
			Container:     containerName,
		}
		// 保存devID+fileID和文件信息的映射关系, 如果已经存在，则覆盖
		cache.NFSDevIDFileIDFileInfoMap.Store(event.Key, mount)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func sanitizeString(s string) string {
	return strings.TrimSpace(s)
}
