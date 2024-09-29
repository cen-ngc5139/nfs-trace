package run

import (
	"fmt"
	"sync"
)

// Task 定义单个任务
type Task struct {
	Name string
	Fn   func() error
}

// TaskManager 管理任务的结构
type TaskManager struct {
	tasks []Task
	mu    sync.RWMutex
	wg    sync.WaitGroup
}

// NewTaskManager 创建一个新的 TaskManager
func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks: []Task{},
	}
}

// Add 添加一个新任务
func (tm *TaskManager) Add(name string, fn func() error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.tasks = append(tm.tasks, Task{Name: name, Fn: fn})
}

// Get 获取指定名称的任务
func (tm *TaskManager) Get(name string) (Task, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	for _, task := range tm.tasks {
		if task.Name == name {
			return task, true
		}
	}
	return Task{}, false
}

// Delete 删除指定名称的任务
func (tm *TaskManager) Delete(name string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for i, task := range tm.tasks {
		if task.Name == name {
			tm.tasks = append(tm.tasks[:i], tm.tasks[i+1:]...)
			return true
		}
	}
	return false
}

// List 列出所有任务
func (tm *TaskManager) List() []Task {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return append([]Task{}, tm.tasks...)
}

// Run 并发运行所有任务
func (tm *TaskManager) Run() error {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	errChan := make(chan error, len(tm.tasks))

	for _, task := range tm.tasks {
		tm.wg.Add(1)
		go func(t Task) {
			defer tm.wg.Done()
			if err := t.Fn(); err != nil {
				errChan <- fmt.Errorf("任务 '%s' 执行失败: %w", t.Name, err)
			}
		}(task)
	}

	// 等待所有任务完成
	go func() {
		tm.wg.Wait()
		close(errChan)
	}()

	// 收集错误
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("一些任务执行失败: %v", errors)
	}

	return nil
}
