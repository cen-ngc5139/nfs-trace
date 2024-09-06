package queue

import (
	"fmt"
	"github.com/cen-ngc5139/nfs-trace/internal/cache"
	"github.com/cen-ngc5139/nfs-trace/internal/cri"
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cilium/ebpf"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"strings"
	"time"
)

var Source *KubernetesEventSource

type EventType string

var (
	AddEventType    EventType = "add"
	DelEventType    EventType = "del"
	UpdateEventType EventType = "update"
)

type Event struct {
	Pod  *v1.Pod
	Type EventType
}

func init() {
	Source = &KubernetesEventSource{
		LocalEventsBuffer: make(chan *Event, LocalEventsBufferSize),
	}
}

type KubernetesEventSource struct {
	LocalEventsBuffer chan *Event
	PidCgroupMap      *ebpf.Map
}

type LogBatch struct {
	Timestamp time.Time
	Events    []*Event
}

const (
	LocalEventsBufferSize   = 10000
	DefaultPushLogFrequency = 5 * time.Second
	DefaultThreadPoolSize   = 10
	DefaultRetry            = 3
)

func (k *KubernetesEventSource) PushPodEvent(event *Event) {
	if event != nil {
		select {
		case k.LocalEventsBuffer <- event:
			// Ok, buffer not full.
		default:
			// Buffer full, need to drop the event.
			klog.Errorf("pod event buffer full, dropping event")
		}
	}
}

func (k *KubernetesEventSource) WithEbpfMap(m *ebpf.Map) {
	k.PidCgroupMap = m
}

func (k *KubernetesEventSource) Export() {
	for {
		now := time.Now()
		start := now.Truncate(DefaultPushLogFrequency)
		end := start.Add(DefaultPushLogFrequency)
		timeToNextSync := end.Sub(now)

		select {
		case <-time.After(timeToNextSync):
			logs := k.GetNewPods()
			if len(logs.Events) > 0 {
				k.ExportEvents(logs)
			}
		}
	}
}

func (k *KubernetesEventSource) GetNewPods() *LogBatch {
	result := &LogBatch{
		Timestamp: time.Now(),
		Events:    []*Event{},
	}
logLoop:
	for {
		select {
		case event := <-k.LocalEventsBuffer:
			result.Events = append(result.Events, event)
		default:
			break logLoop
		}
	}

	return result
}

func (k *KubernetesEventSource) ExportEvents(logBatch *LogBatch) {
	k.Controller(logBatch)
}

func (k *KubernetesEventSource) Controller(logBatch *LogBatch) {
	var thread int
	thread = DefaultThreadPoolSize
	chJobs := make(chan *Event, len(logBatch.Events))

	for w := 1; w <= thread; w++ {
		go k.Work(chJobs)
	}

	for _, event := range logBatch.Events {
		chJobs <- event
	}
	close(chJobs)

}

func (k *KubernetesEventSource) Work(jobs <-chan *Event) {
	for j := range jobs {
		rt := DefaultRetry
		for {
			err := k.worker(j)
			if err != nil {
				klog.Errorf("fail to handler pod,retry: %d, err: %v", rt, err)
				rt--
				if rt == 0 {
					break
				}
				continue
			}
			break
		}
	}
}

func (k *KubernetesEventSource) worker(pod *Event) error {
	// TODO: Implement the worker method.
	if pod.Pod == nil {
		klog.Errorf("pod is nil")
		return nil
	}

	if pod.Pod.Status.ContainerStatuses == nil {
		klog.Errorf("container status is nil")
		return nil
	}

	statuses := pod.Pod.Status.ContainerStatuses

	for _, status := range statuses {
		if status.ContainerID == "" {
			klog.Infof("pod %s container %s id is empty", pod.Pod.Name, status.Name)
			continue
		}

		// 移除可能的前缀
		containerID := status.ContainerID
		containerID = strings.TrimPrefix(containerID, "docker://")
		containerID = strings.TrimPrefix(containerID, "containerd://")

		switch pod.Type {
		case UpdateEventType:
			if pod.Pod.DeletionTimestamp != nil {
				klog.Infof("pod is deleting, skip to find pid, pod: %s", pod.Pod.Name)
				return nil
			}

			klog.Infof("start to process update event, pod: %s ", pod.Pod.Name)
			return updatePidCgroupMap(k.PidCgroupMap, containerID, pod.Pod.Name, status.Name)
		case DelEventType:
			klog.Infof("start to process delete event, pod: %s ", pod.Pod.Name)
			return deletePidCgroupMap(k.PidCgroupMap, containerID)

		}
	}

	return nil
}

type Metadata struct {
	Pod       [100]int8
	Container [100]int8
	Pid       uint64
}

func stringToInt8Array(s string, arr *[100]int8) {
	for i, b := range []byte(s) {
		if i >= 100 {
			break
		}
		arr[i] = int8(b)
	}
}

func int8ArrayToString(arr [100]int8) string {
	b := make([]byte, 0, 100)
	for _, v := range arr {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func updatePidCgroupMap(m *ebpf.Map, containerID, pod, container string) error {
	klog.Infof("update pid cgroup map, pid: %s", containerID)
	pid, err := cri.NewContainerd(containerID).GetPid()
	if err != nil {
		klog.Errorf("failed to get pid: %v", err)
		return err
	}

	klog.Infof("get pid: %d", pid)
	pidKey := uint64(pid)
	meta := Metadata{Pid: uint64(pid)}
	stringToInt8Array(pod, &meta.Pod)
	stringToInt8Array(container, &meta.Container)

	if err = m.Put(&pidKey, &meta); err != nil {
		klog.Errorf("failed to put pid cgroup map: %v", err)
		return err
	}

	defer func() {
		cache.PodContainerPIDMap.LoadOrStore(containerID, pidKey)
	}()

	// 读取并验证数据（可选）
	var retrievedValue Metadata
	if err := m.Lookup(&pidKey, &retrievedValue); err != nil {
		log.Fatalf("failed to read from map: %v", err)
	}

	// 将 [100]int8 转换回字符串进行打印
	log.Infof("Retrieved value: Pod: %s, Container: %s, PID: %d\n",
		int8ArrayToString(retrievedValue.Pod),
		int8ArrayToString(retrievedValue.Container),
		retrievedValue.Pid)
	return nil
}

func deletePidCgroupMap(m *ebpf.Map, pid string) error {
	klog.Infof("delete pid cgroup map, pid: %s", pid)
	pidKey, ok := cache.PodContainerPIDMap.Load(pid)
	if !ok {
		return nil
	}

	pidKeyUint64, ok := pidKey.(uint64)
	if !ok {
		klog.Errorf("failed to convert pid [%v] key to uint64", pid)
		return nil
	}

	var value Metadata
	if err := m.Lookup(&pidKeyUint64, &value); err != nil {
		klog.Errorf("failed to lookup pid cgroup map: %v", err)
		return err
	}

	fmt.Printf("get value: Pod: %s, Container: %s, PID: %d\n",
		int8ArrayToString(value.Pod),
		int8ArrayToString(value.Container),
		value.Pid)

	if err := m.Delete(&pidKeyUint64); err != nil {
		klog.Errorf("failed to delete pid cgroup map: %v", err)
		return err
	}

	klog.Infof("delete pid cgroup map success, pid: %s", pid)
	// 读取并验证数据（可选）
	var retrievedValue Metadata
	if err := m.Lookup(&pidKeyUint64, &retrievedValue); err != nil {
		klog.Warningf("failed to read from map: %v", err)
	}

	fmt.Printf("Retrieved value: Pod: %s, Container: %s, PID: %d\n",
		int8ArrayToString(retrievedValue.Pod),
		int8ArrayToString(retrievedValue.Container),
		retrievedValue.Pid)

	return nil
}
