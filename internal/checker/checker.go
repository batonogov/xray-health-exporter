package checker

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

// Result holds the outcome of a tunnel check.
type Result struct {
	Up         bool
	Latency    time.Duration
	StatusCode int
	Error      error
}

// Check performs a single tunnel health check and updates metrics.
func Check(ti *tunnel.TunnelInstance, m *metrics.Metrics, logger *slog.Logger) Result {
	start := time.Now()

	serverLabel := fmt.Sprintf("%s:%d", ti.VLESSConfig.Address, ti.VLESSConfig.Port)
	baseLabels := metrics.BaseLabels(ti.Name, serverLabel, ti.VLESSConfig.Security, ti.VLESSConfig.SNI)
	failLabels := metrics.CheckLabels(ti.Name, serverLabel, ti.VLESSConfig.Security, ti.VLESSConfig.SNI, "failure")

	socksProxy := fmt.Sprintf("127.0.0.1:%d", ti.SocksPort)

	// Check SOCKS5 proxy is reachable
	conn, err := net.DialTimeout("tcp", socksProxy, 5*time.Second)
	if err != nil {
		logger.Warn("Tunnel DOWN", "name", ti.Name, "error", err)
		m.TunnelUp.With(baseLabels).Set(0)
		m.TunnelCheckTotal.With(failLabels).Inc()
		ti.Up.Store(false)
		return Result{Up: false, Error: err}
	}
	_ = conn.Close()

	resp, err := ti.HTTPClient.Get(ti.CheckURL)
	if err != nil {
		logger.Warn("Tunnel DOWN", "name", ti.Name, "error", err)
		m.TunnelUp.With(baseLabels).Set(0)
		m.TunnelCheckTotal.With(failLabels).Inc()
		ti.Up.Store(false)
		return Result{Up: false, Error: err}
	}
	defer func() { _ = resp.Body.Close() }()

	m.TunnelHTTPStatus.With(baseLabels).Set(float64(resp.StatusCode))

	if resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusMovedPermanently &&
		resp.StatusCode != http.StatusFound &&
		resp.StatusCode != http.StatusTemporaryRedirect {
		logger.Warn("Tunnel DOWN", "name", ti.Name, "status", resp.StatusCode)
		m.TunnelUp.With(baseLabels).Set(0)
		m.TunnelCheckTotal.With(failLabels).Inc()
		ti.Up.Store(false)
		return Result{Up: false, StatusCode: resp.StatusCode}
	}

	// Read some body to ensure connection works
	buf := make([]byte, 1024)
	_, _ = resp.Body.Read(buf)

	duration := time.Since(start)
	logger.Info("Tunnel UP", "name", ti.Name, "latency", duration.Round(time.Millisecond))

	m.TunnelUp.With(baseLabels).Set(1)
	m.TunnelLatency.With(baseLabels).Set(duration.Seconds())
	m.TunnelLastSuccess.With(baseLabels).Set(float64(time.Now().Unix()))
	m.TunnelCheckTotal.With(metrics.CheckLabels(ti.Name, serverLabel, ti.VLESSConfig.Security, ti.VLESSConfig.SNI, "success")).Inc()
	ti.Up.Store(true)

	return Result{Up: true, Latency: duration, StatusCode: resp.StatusCode}
}

// Run starts periodic tunnel checks until context is cancelled.
func Run(ctx context.Context, ti *tunnel.TunnelInstance, m *metrics.Metrics, logger *slog.Logger) {
	ticker := time.NewTicker(ti.CheckInterval)
	defer ticker.Stop()

	// Initial check
	Check(ti, m, logger)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			Check(ti, m, logger)
		}
	}
}
