package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

const (
	baseNFSMountDir = "/data/mount"
	baseLocalDir    = "/data/nfs"
)

var (
	scenario     = flag.String("scenario", "default", "选择模拟场景 (default, heavy_write, heavy_read, mixed)")
	duration     = flag.Duration("duration", 5*time.Minute, "模拟持续时间")
	waitInterval = flag.Duration("wait", 500*time.Millisecond, "操作间等待时间")
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
	files, err := ioutil.ReadDir(path)
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
	default:
		log.Fatalf("未知场景: %s", *scenario)
	}

	log.Println("NFS 模拟完成")
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
