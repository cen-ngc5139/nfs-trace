package cri

import (
	"fmt"
	"net"
)

type Handler interface {
	GetPids() ([]int, error)
}

// GetCriType 获取 CRI 类型
func GetCriType() string {
	// 检查 containerd 是否正在运行
	if isRuntimeRunning("/run/containerd/containerd.sock") {
		return "containerd"
	}

	// 检查 docker 是否正在运行
	if isRuntimeRunning("/var/run/docker.sock") {
		return "docker"
	}

	// 如果都不在运行，返回 "unknown"
	return "unknown"
}

// NewCriHandler 根据 CRI 类型创建相应的 Handler
func NewCriHandler(criType string, containerID string) (Handler, error) {
	switch criType {
	case "containerd":
		return NewContainerd(containerID), nil
	case "docker":
		return NewDocker(containerID), nil
	default:
		return nil, fmt.Errorf("不支持的 CRI 类型: %s", criType)
	}
}

// GetPid 根据 CRI 类型获取容器的 PID
func GetPids(containerID string) ([]int, error) {
	criType := GetCriType()
	handler, err := NewCriHandler(criType, containerID)
	if err != nil {
		return nil, err
	}
	return handler.GetPids()
}

func isRuntimeRunning(socketPath string) bool {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
