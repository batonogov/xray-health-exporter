package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/batonogov/xray-health-exporter/internal/checker"
	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/leaderelection"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

// Version is set via -ldflags at build time.
var Version = "dev"

// Commit is set via -ldflags at build time.
var Commit = "unknown"

func setupLogger() {
	levelStr := os.Getenv("LOG_LEVEL")

	if os.Getenv("DEBUG") == "true" {
		if levelStr != "" {
			slog.Warn("DEBUG is deprecated, use LOG_LEVEL=debug instead; using LOG_LEVEL value", "log_level", levelStr)
		} else {
			levelStr = "debug"
		}
	}

	if levelStr == "" {
		levelStr = "info"
	}

	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		slog.Warn("unknown LOG_LEVEL, falling back to info", "log_level", levelStr)
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(handler))
}

func main() {
	setupLogger()

	metrics.InitStartTime()
	metrics.SetBuildInfo(Version, runtime.Version(), Commit)

	slog.Info("xray-health-exporter starting", "version", Version)

	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = config.DefaultConfigFile
	}

	// RUN_ONCE mode: load config, check every tunnel once, print metrics to
	// stdout, and exit. No HTTP server, watchers, or leader election.
	if os.Getenv("RUN_ONCE") == "true" {
		metrics.SetLeader(true)

		slog.Info("running in run-once mode")

		allUp, err := tunnel.RunOnce(configFile, checker.DefaultChecker{}, tunnel.NewPrometheusMetrics(), os.Stdout)
		if err != nil {
			slog.Error("run-once failed", "error", err)
			os.Exit(1)
		}

		if !allUp {
			os.Exit(1)
		}
		os.Exit(0)
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = config.DefaultListenAddr
	}

	lec, err := leaderelection.ReadLeaderElectionConfig()
	if err != nil {
		slog.Error("invalid leader election config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// When leader election is disabled this instance is the implicit leader for the
	// lifetime of the process. Set the gauge before serving /metrics to avoid a
	// brief window where scrapes see leader=0.
	if lec == nil {
		metrics.SetLeader(true)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	slog.Info("metrics server listening", "address", listenAddr)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	// Resolve the host's real public IP once for ip-method checks.
	// If this fails, the checker will resolve lazily on first ip check.
	ipCheckURL := os.Getenv("IP_CHECK_URL")
	if ipCheckURL == "" {
		ipCheckURL = metrics.DefaultIPCheckURL
	}
	ipResolveCtx, ipResolveCancel := context.WithTimeout(context.Background(), 10*time.Second)
	realIP, ipErr := checker.ResolveRealIP(ipResolveCtx, ipCheckURL)
	ipResolveCancel()
	if ipErr != nil {
		slog.Warn("failed to resolve real IP at startup, ip check method will resolve lazily", "error", ipErr)
	}

	probeChecker := checker.NewDefaultChecker(realIP)
	probeMetrics := tunnel.NewPrometheusMetrics()

	// Configure optional Prometheus Pushgateway push. The push loop only runs
	// when this instance is the leader (checked via the xray_exporter_leader
	// gauge inside PushLoop), so it is safe to start even with leader election
	// enabled.
	pushCfg, err := metrics.ReadPushConfig(minCheckInterval(configFile))
	if err != nil {
		slog.Error("invalid push gateway config", "error", err)
		os.Exit(1)
	}
	if pushCfg != nil {
		slog.Info("push gateway enabled", "url", pushCfg.URL, "interval", pushCfg.Interval, "instance", pushCfg.Instance)
		go metrics.PushLoop(ctx, *pushCfg)
	}

	probingDone := make(chan struct{})
	go func() {
		defer close(probingDone)
		if lec != nil {
			if err := leaderelection.RunWithLeaderElection(ctx, lec, configFile, probeChecker, probeMetrics); err != nil {
				slog.Info("leader election stopped", "error", err)
			}
			return
		}
		if err := tunnel.RunProbing(ctx, configFile, probeChecker, probeMetrics); err != nil {
			slog.Info("probing stopped", "error", err)
		}
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server error", "error", err)
		}
	case <-ctx.Done():
	case <-probingDone:
		slog.Warn("probing exited unexpectedly, shutting down")
	}

	slog.Info("shutdown signal received, stopping HTTP server")
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HTTP server shutdown error", "error", err)
	}

	select {
	case <-probingDone:
	case <-time.After(15 * time.Second):
		slog.Warn("probing did not stop within timeout, exiting anyway", "timeout", "15s")
	}
}

// minCheckInterval loads the config file and returns the smallest check_interval
// among all tunnels (after defaults are applied). Returns 0 if the config
// cannot be loaded or no tunnels are configured.
func minCheckInterval(configFile string) time.Duration {
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return 0
	}
	var min time.Duration
	for _, t := range cfg.Tunnels {
		d, parseErr := time.ParseDuration(t.CheckInterval)
		if parseErr != nil {
			continue
		}
		if min == 0 || d < min {
			min = d
		}
	}
	return min
}
