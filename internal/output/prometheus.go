package output

import (
	"fmt"
	"github.com/cen-ngc5139/nfs-trace/internal/binary"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"sync"
)

const (
	NFSReadCount      = "nfs_read_count"
	NFSWriteCount     = "nfs_write_count"
	NFSReadSize       = "nfs_read_size"
	NFSWriteSize      = "nfs_write_size"
	NFSReadLatencies  = "nfs_read_latencies"
	NFSWriteLatencies = "nfs_write_latencies"
)

// NFSMetrics holds all the NFS related metrics
type NFSMetrics struct {
	ReadCount      *prometheus.GaugeVec
	WriteCount     *prometheus.GaugeVec
	ReadSize       *prometheus.GaugeVec
	WriteSize      *prometheus.GaugeVec
	ReadLatencies  *prometheus.GaugeVec
	WriteLatencies *prometheus.GaugeVec
	performanceMap *sync.Map
}

// createCounterVec 创建并注册一个 prometheus.CounterVec
func createCounterVec(name, help string) *prometheus.GaugeVec {
	return promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: name,
			Help: help,
		},
		[]string{"dev_id", "file_id", "node_name"},
	)
}

// NewNFSMetrics 创建并注��� NFS 指标
func NewNFSMetrics(performanceMap *sync.Map) *NFSMetrics {
	return &NFSMetrics{
		ReadCount:      createCounterVec(NFSReadCount, "NFS read count"),
		WriteCount:     createCounterVec(NFSWriteCount, "NFS write count"),
		ReadSize:       createCounterVec(NFSReadSize, "NFS read size"),
		WriteSize:      createCounterVec(NFSWriteSize, "NFS write size"),
		ReadLatencies:  createCounterVec(NFSReadLatencies, "NFS read latencies"),
		WriteLatencies: createCounterVec(NFSWriteLatencies, "NFS write latencies"),
		performanceMap: performanceMap,
	}
}

// UpdateMetricsFromCache updates the Prometheus metrics from the NFSPerformanceMap
func (m *NFSMetrics) UpdateMetricsFromCache() {
	m.performanceMap.Range(func(key, value interface{}) bool {
		keyStr := key.(uint64)
		metrics := value.(binary.KProbePWRURawMetrics)

		// 假设 keyStr 的格式是 "devID:fileID"
		devID, fileID := parseKey(keyStr)

		// devID fileID 转换成字符串
		devIDStr := fmt.Sprintf("%d", devID)
		fileIDStr := fmt.Sprintf("%d", fileID)

		// 使用一个固定的 nodeName，或者从某处获取
		nodeName := "default_node"

		// 更新所有指标
		m.ReadCount.WithLabelValues(devIDStr, fileIDStr, nodeName).Set(float64(metrics.ReadCount))
		m.WriteCount.WithLabelValues(devIDStr, fileIDStr, nodeName).Set(float64(metrics.WriteCount))
		m.ReadSize.WithLabelValues(devIDStr, fileIDStr, nodeName).Set(float64(metrics.ReadSize))
		m.WriteSize.WithLabelValues(devIDStr, fileIDStr, nodeName).Set(float64(metrics.WriteSize))
		m.ReadLatencies.WithLabelValues(devIDStr, fileIDStr, nodeName).Set(float64(metrics.ReadLat))
		m.WriteLatencies.WithLabelValues(devIDStr, fileIDStr, nodeName).Set(float64(metrics.WriteLat))

		return true
	})
}

func (m *NFSMetrics) MetricsHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		m.UpdateMetricsFromCache()
		h.ServeHTTP(c.Writer, c.Request)
	}
}
