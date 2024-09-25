package config

import (
	"fmt"
	"os"
)

var (
	// ProcPath 是访问 /proc 文件系统的路径
	ProcPath string
)

func init() {
	// 从环境变量中获取 PROC_PATH，如果未设置则使用默认值 "/proc"
	ProcPath = os.Getenv("PROC_PATH")
	if ProcPath == "" {
		ProcPath = "/proc"
	}
}

func GetProcPath(path string) string {
	return fmt.Sprintf("%s/%s", ProcPath, path)
}
