package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	baseDir = "/data/mount"
)

func simulateNFSRead(filename string) {
	path := filepath.Join(baseDir, filename)
	content, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Error reading file %s: %v", filename, err)
		return
	}
	log.Printf("Read %d bytes from %s", len(content), filename)
}

func simulateNFSWrite(filename string, content string) {
	path := filepath.Join(baseDir, filename)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		log.Printf("Error writing to file %s: %v", filename, err)
		return
	}
	log.Printf("Wrote %d bytes to %s", len(content), filename)
}

func simulateNFSList(dirname string) {
	path := filepath.Join(baseDir, dirname)
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

func main() {
	// 创建基础目录
	err := os.MkdirAll(baseDir, 0755)
	if err != nil {
		log.Fatalf("Error creating base directory: %v", err)
	}

	// 模拟NFS操作
	for i := 0; i < 50; i++ {
		simulateNFSWrite(fmt.Sprintf("file_%d.txt", i), fmt.Sprintf("Content of file %d", i))
		time.Sleep(time.Second)

		simulateNFSRead(fmt.Sprintf("file_%d.txt", i))
		time.Sleep(time.Second)
	}

	simulateNFSList(".")
	time.Sleep(time.Second)

	log.Println("NFS simulation completed")
}
