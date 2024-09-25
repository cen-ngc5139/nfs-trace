package metadata

import (
	"bufio"

	"github.com/cen-ngc5139/nfs-trace/internal/config"
	"github.com/cen-ngc5139/nfs-trace/internal/log"

	"os"
	"strings"
	"sync"
	"time"
)

type MountInfo struct {
	MountID       string
	LocalMountDir string
	RemoteNFSAddr string
}

type MountInfoMonitor struct {
	callback      func([]MountInfo)
	stopChan      chan struct{}
	doneChan      chan struct{}
	isRunning     bool
	mutex         sync.Mutex
	pollInterval  time.Duration
	lastMountInfo []MountInfo
}

func NewMountInfoMonitor(callback func([]MountInfo), pollInterval time.Duration) *MountInfoMonitor {
	return &MountInfoMonitor{
		callback:     callback,
		stopChan:     make(chan struct{}),
		doneChan:     make(chan struct{}),
		pollInterval: pollInterval,
	}
}

func (m *MountInfoMonitor) Start() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.isRunning {
		return
	}

	m.isRunning = true
	go m.poll()
}

func (m *MountInfoMonitor) Stop() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.isRunning {
		return
	}

	close(m.stopChan)
	<-m.doneChan
	m.isRunning = false
}

func (m *MountInfoMonitor) poll() {
	defer close(m.doneChan)

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkMountInfo()
		case <-m.stopChan:
			return
		}
	}
}

func (m *MountInfoMonitor) checkMountInfo() {
	mountInfo, err := ParseMountInfo(config.GetProcPath("self/mountinfo"))
	if err != nil {
		log.Errorf("解析 mountinfo 失败: %v", err)
		return
	}

	if !compareMountInfo(m.lastMountInfo, mountInfo) {
		log.Info("检测到 mountinfo 变化")
		m.callback(mountInfo)
		m.lastMountInfo = mountInfo
	}
}

func ParseMountInfo(filePath string) ([]MountInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mountInfos []MountInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		mountInfo := MountInfo{
			MountID:       fields[0],
			LocalMountDir: fields[4],
		}

		// 检查是否为 NFS 挂载
		if strings.HasPrefix(fields[8], "nfs") || strings.HasPrefix(fields[8], "nfs4") {
			mountInfo.RemoteNFSAddr = fields[9]
		} else if strings.HasPrefix(fields[7], "nfs") || strings.HasPrefix(fields[7], "nfs4") {
			mountInfo.RemoteNFSAddr = fields[8]
		}

		mountInfos = append(mountInfos, mountInfo)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return mountInfos, nil
}

func compareMountInfo(a, b []MountInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
