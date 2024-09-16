package cri

import (
	"fmt"
	"os"
)

type Handler interface {
	GetPids() ([]int, error)
}

// GetCriType 获取 CRI 类型
func GetCriType() string {
	// 检查 containerd socket 是否存在
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		return "containerd"
	}

	// 检查 docker socket 是否存在
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return "docker"
	}

	// 如果都不存在，返回 "unknown"
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
