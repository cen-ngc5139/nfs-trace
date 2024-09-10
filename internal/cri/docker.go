package cri

import (
	"context"
	"fmt"

	"github.com/docker/docker/client"
)

type Docker struct {
	ID string
}

func (m Docker) GetPid() (int, error) {
	// 创建 Docker 客户端
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return 0, fmt.Errorf("无法创建 Docker 客户端: %v", err)
	}
	defer cli.Close()

	// 设置上下文
	ctx := context.Background()

	// 获取容器信息
	containerJSON, err := cli.ContainerInspect(ctx, m.ID)
	if err != nil {
		return 0, fmt.Errorf("无法获取容器信息: %v", err)
	}
	// 检查容器是否正在运行
	if !containerJSON.State.Running {
		return 0, fmt.Errorf("容器未运行")
	}

	// 获取 PID
	pid := containerJSON.State.Pid
	return pid, nil
}

func NewDocker(id string) Handler {
	return &Docker{
		ID: id,
	}
}
