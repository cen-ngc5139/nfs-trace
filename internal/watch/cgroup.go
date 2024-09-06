package watch

import (
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	queue "github.com/cen-ngc5139/nfs-trace/internal/queue"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type AIPodController struct {
	*Controller
}

func filterPod(pod *v1.Pod, nodeName string) bool {
	if pod.Spec.NodeName == "" || pod.Spec.NodeName != nodeName {
		return false
	}

	return true
}

func NewAIPodStatusController(cluster *kubernetes.Clientset, namespace, nodeName string) (c *AIPodController) {
	podListWatcher := cache.NewListWatchFromClient(cluster.CoreV1().RESTClient(), ResourceTypePod, namespace, fields.Everything())
	q := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	indexer, informer := cache.NewIndexerInformer(podListWatcher, &v1.Pod{}, 0, cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			_, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err != nil {
				return
			}

			pod := obj.(*v1.Pod)
			if ok := filterPod(pod, nodeName); !ok {
				return
			}

			log.Infof("Pod %s has been deleted", pod.Name)
			queue.Source.PushPodEvent(&queue.Event{Pod: pod, Type: queue.DelEventType})

		},
		UpdateFunc: func(old interface{}, new interface{}) {
			_, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}

			pod := new.(*v1.Pod)
			if ok := filterPod(pod, nodeName); !ok {
				return
			}

			log.Infof("Pod %s has been updated", pod.Name)
			queue.Source.PushPodEvent(&queue.Event{Pod: pod, Type: queue.UpdateEventType})
		},
		AddFunc: func(obj interface{}) {
			_, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				return
			}

			pod := obj.(*v1.Pod)
			if ok := filterPod(pod, nodeName); !ok {
				return
			}

			log.Infof("Pod %s has been add", pod.Name)
			queue.Source.PushPodEvent(&queue.Event{Pod: pod, Type: queue.UpdateEventType})
		},
	}, cache.Indexers{})

	podController := &AIPodController{}
	podController.Controller = NewController(q, indexer, informer, podController.processNextItem)
	return podController
}

func (c *AIPodController) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	err := c.syncToMap(key.(string))
	c.handleErr(err, key)
	return true
}

func (c *AIPodController) syncToMap(key string) error {
	return nil
}
