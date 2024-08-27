package client

import (
	"fmt"
	"github.com/pkg/errors"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	Scheme = k8sruntime.NewScheme()
)

func init() {
	_ = clientgoscheme.AddToScheme(Scheme)
	// +kubebuilder:scaffold:scheme
}

type K8sClusterInterface interface {
	GetK8sClientSet() *kubernetes.Clientset
	GetK8sConfig() *rest.Config
	CreateClient() error
}

type K8sClusterManager struct {
	K8sCli  client.Client
	K8sSet  *kubernetes.Clientset
	K8sConf *rest.Config
}

func (m *K8sClusterManager) GetK8sConfig() *rest.Config {
	return m.K8sConf
}

func (m *K8sClusterManager) GetK8sClientSet() *kubernetes.Clientset {
	return m.K8sSet
}

// CreateClient 用于创建 k8s 客户端
func (m *K8sClusterManager) CreateClient() error {
	logf.SetLogger(zap.New(zap.WriteTo(os.Stdout), zap.UseDevMode(true)))

	var err error

	kubeConfig := os.Getenv("KUBECONFIG")
	if kubeConfig == "" {
		kubeConfig = os.Getenv("HOME") + "/.kube/config"
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("error creating k8s client: %v", err)
		}
	}
	m.K8sConf = config

	cli, err := client.New(config, client.Options{Scheme: Scheme})
	if err != nil {
		return errors.Wrapf(err, "创建 k8s client 客户端失败")
	}
	m.K8sCli = cli

	set, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrapf(err, "创建 k8s set 客户端失败")
	}
	m.K8sSet = set

	return nil
}

func NewK8sManager() K8sClusterInterface {
	return &K8sClusterManager{
		K8sSet:  &kubernetes.Clientset{},
		K8sConf: &rest.Config{},
	}
}
