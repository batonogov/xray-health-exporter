package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/batonogov/xray-health-exporter/internal/checker"
	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

func main() {
	logLevel := slog.LevelInfo
	if os.Getenv("DEBUG") == "true" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = config.DefaultConfigFile
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = config.DefaultListenAddr
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	logger.Debug("Loaded config", "tunnels", len(cfg.Tunnels))

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tm := tunnel.NewManager(m, logger, checker.Run)

	if err := tm.Initialize(cfg); err != nil {
		logger.Error("Failed to initialize tunnels", "error", err)
		os.Exit(1)
	}
	defer tm.StopAll()

	go func() {
		if err := tunnel.WatchConfigFile(ctx, tm, configFile, logger); err != nil {
			logger.Error("File watcher stopped", "error", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", tm.HealthHandler)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	logger.Info("Metrics server listening", "addr", listenAddr)
	logger.Info("Config auto-reload enabled", "file", configFile)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("Shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server shutdown error", "error", err)
		}
		if err := <-serverErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error after shutdown", "error", err)
			os.Exit(1)
		}
	}

	fmt.Fprintln(os.Stderr, "Exiting")
}
