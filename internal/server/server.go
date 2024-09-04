package server

import (
	"context"
	"errors"
	"k8s.io/klog/v2"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
)

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
	r := gin.Default()
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
	r.GET("/readiness", readiness())
	r.GET("/liveness", liveness())
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
