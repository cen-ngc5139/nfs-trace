package log

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog/v2"
)

const (
	InfoLogName  = "info.log"
	WarnLogName  = "warn.log"
	ErrorLogName = "error.log"
)

var (
	infoLogger  *lumberjack.Logger
	warnLogger  *lumberjack.Logger
	errorLogger *lumberjack.Logger
	logMu       sync.Mutex
)

// 初始化日志设置
func InitLogger(logDir string, maxSize, maxBackups, maxAge int) error {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %v", err)
	}

	infoLogger = &lumberjack.Logger{
		Filename:   filepath.Join(logDir, InfoLogName),
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
		Compress:   true,
	}

	warnLogger = &lumberjack.Logger{
		Filename:   filepath.Join(logDir, WarnLogName),
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
		Compress:   true,
	}

	errorLogger = &lumberjack.Logger{
		Filename:   filepath.Join(logDir, ErrorLogName),
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
		Compress:   true,
	}

	// 设置 klog 输出到自定义的 writer
	klog.SetOutput(&logWriter{})

	return nil
}

// logWriter 实现了 io.Writer 接口
type logWriter struct{}

func (w *logWriter) Write(p []byte) (n int, err error) {
	logMu.Lock()
	defer logMu.Unlock()

	if len(p) > 0 {
		var logger *lumberjack.Logger
		switch p[0] {
		case 'I':
			logger = infoLogger
		case 'W':
			logger = warnLogger
		case 'E', 'F':
			logger = errorLogger
		default:
			logger = infoLogger
		}

		n, err = logger.Write(p)
		if err != nil {
			fmt.Printf("写入日志失败: %v\n", err)
		}
		return n, err
	}
	return len(p), nil
}

// Info 写入信息日志
func Info(args ...interface{}) {
	klog.Info(args...)
}

// Infof 写入格式化的信息日志
func Infof(format string, args ...interface{}) {
	klog.Infof(format, args...)
}

// Warning 写入警告日志
func Warning(args ...interface{}) {
	klog.Warning(args...)
}

// Warningf 写入格式化的警告日志
func Warningf(format string, args ...interface{}) {
	klog.Warningf(format, args...)
}

// Error 写入错误日志
func Error(args ...interface{}) {
	klog.Error(args...)
}

// Errorf 写入格式化的错误日志
func Errorf(format string, args ...interface{}) {
	klog.Errorf(format, args...)
}

// Fatal 写入致命错误日志并退出程序
func Fatal(args ...interface{}) {
	klog.Fatal(args...)
}

// Fatalf 写入格式化的致命错误日志并退出程序
func Fatalf(format string, args ...interface{}) {
	klog.Fatalf(format, args...)
}

// MergeToUnstructured 将多个参数合并为一个 map[string]interface{}
func MergeToUnstructured(args ...interface{}) map[string]interface{} {
	mergedMap := make(map[string]interface{})
	for _, arg := range args {
		unstructured, err := toUnstructured(arg)
		if err != nil {
			klog.Warningf("无法转换参数为 unstructured 格式: %v", err)
			continue
		}
		merge(mergedMap, unstructured)
	}
	return mergedMap
}

// merge 递归合并两个 map
func merge(target, source map[string]interface{}) {
	for k, v := range source {
		if existing, ok := target[k]; ok {
			if existingMap, isMap := existing.(map[string]interface{}); isMap {
				if sourceMap, isMap := v.(map[string]interface{}); isMap {
					merge(existingMap, sourceMap)
				} else {
					target[k] = v
				}
			} else {
				target[k] = v
			}
		} else {
			target[k] = v
		}
	}
}

// toUnstructured 将任意类型转换为 map[string]interface{}
func toUnstructured(v interface{}) (map[string]interface{}, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		return t, nil
	case string:
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(t), &m); err == nil {
			return m, nil
		}
		return map[string]interface{}{"value": t}, nil
	default:
		if reflect.TypeOf(v).Kind() == reflect.Struct {
			b, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			var m map[string]interface{}
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, err
			}
			return m, nil
		}
		return map[string]interface{}{"value": v}, nil
	}
}

// StdoutOrFile 输出合并后的 JSON 到标准输出或文件
func StdoutOrFile(outputType string, args ...interface{}) {
	mergedMap := MergeToUnstructured(args...)

	raw, err := json.Marshal(mergedMap)
	if err != nil {
		klog.Errorf("无法将参数转换为 JSON: %v", err)
		return
	}

	switch outputType {
	case "stdout":
		fmt.Println(string(raw))
	case "file":
		klog.Info(string(raw))
	default:
		klog.Info(string(raw))
	}
}
