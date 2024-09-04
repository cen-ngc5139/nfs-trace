package main

import (
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
	// 创建基础目录
	err := os.MkdirAll(baseNFSMountDir, 0755)
	if err != nil {
		log.Fatalf("Error creating base directory: %v", err)
	}

	// 模拟NFS操作
	for i := 0; i < 50; i++ {
		for count := 5; count > 0; count-- {
			simulateNFSWrite(baseLocalDir, fmt.Sprintf("file_%d.txt", i), RandStringBytes(20))
			time.Sleep(time.Second)

			simulateNFSRead(fmt.Sprintf("file_%d.txt", i))
			time.Sleep(time.Second)

			simulateNFSWrite(baseNFSMountDir, fmt.Sprintf("file_%d.txt", i), RandStringBytes(20))
			time.Sleep(time.Second)
		}
	}

	simulateNFSList(".")
	time.Sleep(time.Second)

	log.Println("NFS simulation completed")
}
