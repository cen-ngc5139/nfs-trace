package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

var (
	ProcPath string
	Config   Configuration
)

func init() {
	ProcPath = os.Getenv("PROC_PATH")
	if ProcPath == "" {
		ProcPath = "/proc"
	}
}

func LoadConfig(cfg *Configuration) error {
	file, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(file, &cfg)
	if err != nil {
		return err
	}

	return nil
}

func GetProcPath(path string) string {
	return fmt.Sprintf("%s/%s", ProcPath, path)
}
