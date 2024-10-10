package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	baseNFSMountDir = "/data/mount"
	baseLocalDir    = "/data/nfs"
)

var (
	scenario     = flag.String("scenario", "default", "选择模拟场景 (default, heavy_write, heavy_read, mixed, lru_test)")
	duration     = flag.Duration("duration", 5*time.Minute, "模拟持续时间")
	waitInterval = flag.Duration("wait", 500*time.Millisecond, "操作间等待时间")
	fileCount    = flag.Int("file-count", 20, "LRU 测试场景中的文件数量")
)

func simulateNFSRead(filename string) {
	path := filepath.Join(baseNFSMountDir, filename)
	content, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Error reading file %s: %v", filename, err)
		return
	}
	log.Printf("Read %d bytes from %s", len(content), filename)
}

func simulateNFSWrite(fPath, filename string, content string) {
	path := filepath.Join(fPath, filename)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		log.Printf("Error writing to file %s: %v", filename, err)
		return
	}
	log.Printf("Wrote %d bytes to %s", len(content), filename)
}

func simulateNFSList(dirname string) {
	path := filepath.Join(baseNFSMountDir, dirname)
	files, err := os.ReadDir(path)
	if err != nil {
		log.Printf("Error listing directory %s: %v", dirname, err)
		return
	}
	log.Printf("Listing directory %s:", dirname)
	for _, file := range files {
		log.Printf("- %s", file.Name())
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func main() {
	flag.Parse()

	log.Printf("开始执行 %s 场景，持续时间 %v，操作间隔 %v\n", *scenario, *duration, *waitInterval)

	switch *scenario {
	case "default":
		runDefaultScenario(*duration, *waitInterval)
	case "heavy_write":
		runHeavyWriteScenario(*duration, *waitInterval)
	case "heavy_read":
		runHeavyReadScenario(*duration, *waitInterval)
	case "mixed":
		runMixedScenario(*duration, *waitInterval)
	case "lru_test":
		runLRUTestScenario(*duration, *waitInterval, *fileCount)
	default:
		log.Fatalf("未知场景: %s", *scenario)
	}

	log.Println("NFS 模拟完成")
}

func dnsMock() {
	// 设置要解析的域名
	domain := "www.baidu.com"

	// 创建一个带有 1 秒超时的 context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// 使用带超时的 context 进行 DNS 解析
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip", domain)

	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			fmt.Printf("DNS 解析 %s 超时\n", domain)
		} else {
			fmt.Printf("DNS 解析 %s 失败: %v\n", domain, err)
		}
		return
	}

	// 打印解析结果
	fmt.Printf("DNS 解析 %s 成功:\n", domain)
	for _, ip := range ips {
		fmt.Printf("  IP: %s\n", ip.String())
	}
}

func runDefaultScenario(duration, waitInterval time.Duration) {
	startTime := time.Now()
	for time.Since(startTime) < duration {
		for i := 0; i < 10; i++ {
			simulateNFSWrite(baseLocalDir, fmt.Sprintf("file_%d.txt", i), RandStringBytes(20))
			time.Sleep(waitInterval)

			simulateNFSRead(fmt.Sprintf("file_%d.txt", i))
			time.Sleep(waitInterval)

			simulateNFSWrite(baseNFSMountDir, fmt.Sprintf("file_%d.txt", i), RandStringBytes(20))
			time.Sleep(waitInterval)

			// 模拟 dns 解析
			dnsMock()
		}
	}
}

func runHeavyWriteScenario(duration, waitInterval time.Duration) {
	startTime := time.Now()
	for time.Since(startTime) < duration {
		for i := 0; i < 20; i++ {
			simulateNFSWrite(baseNFSMountDir, fmt.Sprintf("heavy_write_%d.txt", i), RandStringBytes(1024))
			time.Sleep(waitInterval)
		}
	}
}

func runHeavyReadScenario(duration, waitInterval time.Duration) {
	// 先创建一些文件
	for i := 0; i < 20; i++ {
		simulateNFSWrite(baseNFSMountDir, fmt.Sprintf("heavy_read_%d.txt", i), RandStringBytes(1024))
	}

	startTime := time.Now()
	for time.Since(startTime) < duration {
		for i := 0; i < 20; i++ {
			simulateNFSRead(fmt.Sprintf("heavy_read_%d.txt", i))
			time.Sleep(waitInterval)
		}
	}
}

func runMixedScenario(duration, waitInterval time.Duration) {
	startTime := time.Now()
	for time.Since(startTime) < duration {
		// 混合读写操作
		for i := 0; i < 10; i++ {
			if rand.Float32() < 0.6 {
				simulateNFSRead(fmt.Sprintf("mixed_%d.txt", i))
			} else {
				simulateNFSWrite(baseNFSMountDir, fmt.Sprintf("mixed_%d.txt", i), RandStringBytes(512))
			}
			time.Sleep(waitInterval)
		}
	}
}

func runLRUTestScenario(duration, waitInterval time.Duration, maxFiles int) {
	log.Printf("开始执行 LRU 测试场景，最大文件数: %d", maxFiles)
	startTime := time.Now()
	fileIndex := 0

	for time.Since(startTime) < duration {
		// 创建新文件
		filename := fmt.Sprintf("lru_test_file_%d.txt", fileIndex%maxFiles)
		content := RandStringBytes(1024) // 1KB 的随机内容
		simulateNFSWrite(baseNFSMountDir, filename, content)
		log.Printf("创建/更新文件: %s", filename)

		// 读取文件
		simulateNFSRead(filename)
		log.Printf("读取文件: %s", filename)

		// 每创建/更新 5 个文件后，随机写入之前的文件
		if fileIndex > 0 && fileIndex%5 == 0 {
			for i := 0; i < 3; i++ {
				randomFileIndex := rand.Intn(maxFiles)
				randomFilename := fmt.Sprintf("lru_test_file_%d.txt", randomFileIndex)
				randomContent := RandStringBytes(512) // 0.5KB 的随机内容
				simulateNFSWrite(baseNFSMountDir, randomFilename, randomContent)
				log.Printf("随机写入文件: %s", randomFilename)
			}
		}

		fileIndex++
		time.Sleep(waitInterval)
	}

	log.Printf("LRU 测试场景完成，共操作 %d 次文件", fileIndex)
}
