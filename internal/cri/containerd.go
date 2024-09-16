package cri

import (
	"context"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
)

type Containerd struct {
	ID string
}

func (m Containerd) GetPids() ([]int, error) {
	var pids []int
	// 连接到 containerd
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return pids, fmt.Errorf("failed to connect to containerd: %v", err)
	}
	defer client.Close()

	// 设置上下文
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")

	// 获取容器
	container, err := client.LoadContainer(ctx, m.ID)
	if err != nil {
		return pids, fmt.Errorf("failed to load container: %v", err)
	}

	// 获取任务
	task, err := container.Task(ctx, nil)
	if err != nil {
		return pids, fmt.Errorf("failed to get task: %v", err)
	}

	processes, err := task.Pids(ctx)
	if err != nil {
		return pids, fmt.Errorf("failed to get pids: %v", err)
	}

	pids = make([]int, len(processes))
	for i, p := range processes {
		pids[i] = int(p.Pid)
	}

	return pids, nil

}

func NewContainerd(id string) Handler {
	return &Containerd{
		ID: id,
	}
}
