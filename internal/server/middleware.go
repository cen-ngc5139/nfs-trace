package server

import (
	"github.com/cen-ngc5139/nfs-trace/internal/cache"
	"github.com/cen-ngc5139/nfs-trace/internal/output"
	"github.com/gin-gonic/gin"
)

func InitPrometheusMetrics(r *gin.Engine) {
	nfsMetrics := output.NewNFSMetrics(cache.NFSPerformanceMap, cache.NFSFileDetailMap)
	r.GET("/metrics", nfsMetrics.MetricsHandler())
}
