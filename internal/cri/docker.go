package cri

import (
	"context"
	"fmt"
	"strconv"

	"github.com/docker/docker/client"
)

type Docker struct {
	ID string
}

func (m Docker) GetPids() ([]int, error) {
	// 创建 Docker 客户端
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("无法创建 Docker 客户端: %v", err)
	}
	defer cli.Close()

	// 设置上下文
	ctx := context.Background()

	// 获取容器的详细信息
	containerJSON, err := cli.ContainerInspect(ctx, m.ID)
	if err != nil {
		return nil, fmt.Errorf("无法获取容器信息: %v", err)
	}

	// 检查容器是否正在运行
	if !containerJSON.State.Running {
		return nil, fmt.Errorf("容器未运行")
	}

	// 获取容器的进程列表
	top, err := cli.ContainerTop(ctx, m.ID, []string{})
	if err != nil {
		return nil, fmt.Errorf("无法获取容器进程列表: %v", err)
	}

	// 解析进程列表,提取 PID
	var pids []int
	pidIndex := -1
	for i, title := range top.Titles {
		if title == "PID" {
			pidIndex = i
			break
		}
	}

	if pidIndex == -1 {
		return nil, fmt.Errorf("无法在进程列表中找到 PID 列")
	}

	for _, process := range top.Processes {
		if pidIndex < len(process) {
			pid, err := strconv.Atoi(process[pidIndex])
			if err == nil {
				pids = append(pids, pid)
			}
		}
	}

	return pids, nil
}

func NewDocker(id string) Handler {
	return &Docker{
		ID: id,
	}
}
