package server

import (
	"context"
	"errors"
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"io"
	"k8s.io/klog/v2"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
)

// ginLogger 实现了 io.Writer 接口
type ginLogger struct{}

func (g *ginLogger) Write(p []byte) (n int, err error) {
	log.Info(string(p)) // 使用您的日志包记录 Gin 的日志
	return len(p), nil
}

type Server struct {
	router *gin.Engine
	server http.Server
}

func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

func NewServer(middleware ...gin.HandlerFunc) *Server {
	// 设置 Gin 的模式为发布模式
	gin.SetMode(gin.ReleaseMode)

	// 创建一个新的 Gin 引擎，不使用默认的中间件
	r := gin.New()

	// 使用自定义的日志输出
	r.Use(gin.LoggerWithWriter(io.MultiWriter(&ginLogger{})))
	r.Use(gin.Recovery()) // 添加 Recovery 中间件

	r.GET("/ping", Ping)

	InitProbe(r)
	InitPrometheusMetrics(r)
	pprof.Register(r, "pprof")

	r.Use(middleware...)
	return &Server{
		router: r,
		server: http.Server{
			Addr:    ":8080",
			Handler: r,
		},
	}
}

func (s *Server) Start() error {
	// Initializing the server in a goroutine so that it won't block the graceful shutdown handling below
	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Fatal("Listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with a timeout of 5 seconds.
	quit := make(chan os.Signal, 2)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	klog.Info("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		klog.Fatal("Server forced to shutdown:", err)
	}

	klog.Info("Server exiting")
	return nil
}

func InitProbe(r *gin.Engine) {
	r.GET("/healthz", func(c *gin.Context) {
		c.String(200, "ok")
	})
}

func liveness() gin.HandlerFunc {
	return func(c *gin.Context) {

	}
}

func readiness() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Add readiness check

	}
}
