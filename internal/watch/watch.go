package watch

import (
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cen-ngc5139/nfs-trace/pkg/client"
	"os"
)

func SyncPodStatus(mgr client.K8sClusterInterface, stopChan chan struct{}) error {
	kCli := mgr.GetK8sClientSet()

	// 获取当前节点主机名
	nodeName, err := os.Hostname()
	if err != nil {
		log.Errorf("Failed to get the hostname: %v", err)
		return err
	}

	tc := NewAIPodStatusController(kCli, "", nodeName)
	go func() {
		log.Info("Start sync the training job status")
		tc.Run(2, stopChan)
	}()

	return nil
}
