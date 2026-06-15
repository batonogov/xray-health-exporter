package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// TunnelManager manages tunnel instances with thread-safe access.
type TunnelManager struct {
	mu            sync.RWMutex
	instances     []*TunnelInstance
	NextSocksPort int
	config        *config.Config
	checker       HealthChecker
	metrics       MetricsUpdater
}

// NewTunnelManager creates a TunnelManager with the given dependencies.
// Pass nil for defaults; the caller (cmd/exporter) should inject production
// implementations.
func NewTunnelManager(checker HealthChecker, mu MetricsUpdater) *TunnelManager {
	return &TunnelManager{checker: checker, metrics: mu}
}

// InitTunnel creates and starts a single tunnel instance from config.
func InitTunnel(tunnel *config.Tunnel, socksPort int) (*TunnelInstance, error) {
	checkInterval, err := time.ParseDuration(tunnel.CheckInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid check_interval: %v", err)
	}

	checkTimeout, err := time.ParseDuration(tunnel.CheckTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid check_timeout: %v", err)
	}

	maxBackoffStr := tunnel.MaxBackoff
	if maxBackoffStr == "" {
		maxBackoffStr = metrics.DefaultMaxBackoff.String()
	}
	maxBackoff, err := time.ParseDuration(maxBackoffStr)
	if err != nil {
		return nil, fmt.Errorf("invalid max_backoff: %v", err)
	}

	backoffMultiplier := metrics.DefaultBackoffMult
	if tunnel.BackoffMultiplier != nil {
		backoffMultiplier = *tunnel.BackoffMultiplier
	}
	if backoffMultiplier < 1.0 {
		return nil, fmt.Errorf("backoff_multiplier must be >= 1.0, got %v", backoffMultiplier)
	}

	// Check method fields (issue #114).
	checkMethod := tunnel.CheckMethod
	if checkMethod == "" {
		checkMethod = metrics.DefaultCheckMethod
	}

	ipCheckURL := tunnel.IPCheckURL
	if ipCheckURL == "" {
		ipCheckURL = metrics.DefaultIPCheckURL
	}

	downloadURL := tunnel.DownloadURL
	if downloadURL == "" {
		downloadURL = metrics.DefaultDownloadURL
	}

	downloadTimeoutStr := tunnel.DownloadTimeout
	if downloadTimeoutStr == "" {
		downloadTimeoutStr = metrics.DefaultDownloadTimeout.String()
	}
	downloadTimeout, err := time.ParseDuration(downloadTimeoutStr)
	if err != nil {
		return nil, fmt.Errorf("invalid download_timeout: %v", err)
	}

	downloadMinSize := tunnel.DownloadMinSize
	if downloadMinSize == 0 {
		downloadMinSize = metrics.DefaultDownloadMinSize
	}

	var xrayConfigJSON []byte
	var vlessConfig *VLESSConfig
	var metricLabels MetricLabels

	if tunnel.XrayConfigFile != "" {
		// xray_config_file mode
		xrayConfigJSON, metricLabels, err = LoadXrayConfigFile(tunnel.XrayConfigFile, socksPort)
		if err != nil {
			return nil, fmt.Errorf("failed to load xray config file: %v", err)
		}
	} else {
		// VLESS URL mode
		vlessConfig, err = ParseVLESSURL(tunnel.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VLESS URL: %v", err)
		}

		metricLabels = MetricLabels{
			Server:   fmt.Sprintf("%s:%d", vlessConfig.Address, vlessConfig.Port),
			Security: vlessConfig.Security,
			SNI:      vlessConfig.SNI,
		}

		xrayConfigJSON, err = CreateXrayConfig(vlessConfig, socksPort)
		if err != nil {
			return nil, fmt.Errorf("failed to create Xray config: %v", err)
		}
	}

	slog.Debug("xray config", "tunnel", tunnel.Name, "config", slog.String("config_json", string(xrayConfigJSON)))

	xrayInstance, err := StartXray(xrayConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to start Xray: %v", err)
	}

	name := tunnel.Name
	if name == "" {
		if metricLabels.Server != "" {
			name = metricLabels.Server
		} else {
			name = fmt.Sprintf("tunnel-port-%d", socksPort)
		}
	}

	return &TunnelInstance{
		Name:              name,
		VLESSConfig:       vlessConfig,
		MetricLabels:      metricLabels,
		XrayInstance:      xrayInstance,
		SocksPort:         socksPort,
		CheckURL:          tunnel.CheckURL,
		CheckInterval:     checkInterval,
		CheckTimeout:      checkTimeout,
		MaxBackoff:        maxBackoff,
		BackoffMultiplier: backoffMultiplier,
		CheckMethod:       checkMethod,
		IPCheckURL:        ipCheckURL,
		DownloadURL:       downloadURL,
		DownloadTimeout:   downloadTimeout,
		DownloadMinSize:   downloadMinSize,
	}, nil
}

// InitializeTunnels creates and starts all tunnel instances from config.
// Returns the instances and the next available auto-port (past all assigned auto-ports).
func InitializeTunnels(cfg *config.Config, baseSocksPort int, checker HealthChecker, mu MetricsUpdater) ([]*TunnelInstance, int, error) {
	if len(cfg.Tunnels) == 0 {
		return nil, baseSocksPort, fmt.Errorf("no tunnels to initialize")
	}

	var tunnelInstances []*TunnelInstance

	// Collect custom ports to avoid conflicts during auto-assignment.
	reserved := make(map[int]bool)
	for _, t := range cfg.Tunnels {
		if t.SocksPort > 0 {
			reserved[t.SocksPort] = true
		}
	}

	nextAutoPort := baseSocksPort

	for i, tunnel := range cfg.Tunnels {
		var socksPort int
		if tunnel.SocksPort > 0 {
			socksPort = tunnel.SocksPort
		} else {
			for reserved[nextAutoPort] {
				nextAutoPort++
			}
			socksPort = nextAutoPort
			nextAutoPort++
		}

		slog.Debug("initializing tunnel", "index", i+1, "tunnel", tunnel.Name, "socks_port", socksPort)

		ti, err := InitTunnel(&tunnel, socksPort)
		if err != nil {
			// Cleanup already created instances
			for _, instance := range tunnelInstances {
				instance.XrayInstance.Close()
				if instance.cancelFunc != nil {
					instance.cancelFunc()
				}
			}
			return nil, baseSocksPort, fmt.Errorf("failed to initialize tunnel %d: %v", i+1, err)
		}

		tunnelInstances = append(tunnelInstances, ti)

		slog.Info("started tunnel",
			"tunnel", ti.Name,
			"server", ti.MetricLabels.Server,
			"security", ti.MetricLabels.Security,
			"socks_port", socksPort)
	}

	// Wait for all SOCKS ports to become ready
	for _, ti := range tunnelInstances {
		if err := WaitForSOCKSPort(ti.SocksPort, metrics.SocksStartupTimeout); err != nil {
			slog.Warn("SOCKS port not ready", "tunnel", ti.Name, "port", ti.SocksPort, "error", err)
		}
	}

	// Start checker goroutines for all tunnels
	for _, ti := range tunnelInstances {
		ctx, cancel := context.WithCancel(context.Background())
		ti.cancelFunc = cancel
		go RunTunnelChecker(ctx, ti, checker, mu)
	}

	return tunnelInstances, nextAutoPort, nil
}

// StopTunnels gracefully stops all tunnel instances.
func StopTunnels(instances []*TunnelInstance) {
	for _, ti := range instances {
		if ti.cancelFunc != nil {
			ti.cancelFunc()
		}
		if ti.XrayInstance != nil {
			ti.XrayInstance.Close()
		}
	}
}

// checkAndRecord performs a single health-check through the given checker and
// records the result via metrics, with appropriate logging.
func checkAndRecord(ti *TunnelInstance, checker HealthChecker, mu MetricsUpdater) {
	result := checker.Check(ti)

	if !result.Up && result.Err != nil {
		mu.RecordError(ti.Name, ti.MetricLabels, result.Err)
	}

	if result.Up {
		if result.Err != nil {
			slog.Warn("failed to read response body", "tunnel", ti.Name, "error", result.Err)
		}
		slog.Info("tunnel UP", "tunnel", ti.Name, "latency", result.Latency.Round(time.Millisecond))
	} else {
		if result.Err != nil {
			slog.Error("tunnel DOWN", "tunnel", ti.Name, "error", result.Err)
		}
	}

	mu.Update(ti.Name, ti.MetricLabels, result)
}

// RunTunnelChecker runs periodic health-checks on a tunnel instance until ctx
// is canceled. It applies exponential backoff on consecutive failures.
func RunTunnelChecker(ctx context.Context, ti *TunnelInstance, checker HealthChecker, mu MetricsUpdater) {
	// Jitter for initial check — prevents thundering herd
	jitter := time.Duration(rand.Int64N(int64(ti.CheckInterval)))
	slog.Debug("staggering initial check", "tunnel", ti.Name, "jitter", jitter)
	timer := time.NewTimer(jitter)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return
	}

	consecutiveFailures := 0
	checkAndRecord(ti, checker, mu)

	ticker := time.NewTicker(ti.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if consecutiveFailures > 0 {
				interval := BackoffDuration(ti.CheckInterval, ti.BackoffMultiplier, ti.MaxBackoff, consecutiveFailures)
				slog.Debug("backoff active", "tunnel", ti.Name, "consecutive_failures", consecutiveFailures, "next_check_in", interval)
				ticker.Reset(interval)
			}

			result := checker.Check(ti)
			if result.Up {
				if result.Err != nil {
					slog.Warn("failed to read response body", "tunnel", ti.Name, "error", result.Err)
				}
				slog.Info("tunnel UP", "tunnel", ti.Name, "latency", result.Latency.Round(time.Millisecond))
				consecutiveFailures = 0
				ticker.Reset(ti.CheckInterval)
			} else {
				if result.Err != nil {
					slog.Error("tunnel DOWN", "tunnel", ti.Name, "error", result.Err)
				}
				consecutiveFailures++
			}

			mu.Update(ti.Name, ti.MetricLabels, result)
		}
	}
}

// BackoffDuration calculates the next check interval using exponential backoff.
func BackoffDuration(base time.Duration, multiplier float64, maxBackoff time.Duration, failures int) time.Duration {
	d := float64(base) * math.Pow(multiplier, float64(failures))
	if d > float64(maxBackoff) {
		return maxBackoff
	}
	result := time.Duration(d)
	if result > maxBackoff {
		return maxBackoff
	}
	if result < base {
		return base
	}
	return result
}

// WaitForSOCKSPort polls the SOCKS port until it accepts connections or the
// timeout expires.
func WaitForSOCKSPort(port int, timeout time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready after %v", port, timeout)
}

// tunnelMetricLabels returns the Prometheus label values for a tunnel instance.
func tunnelMetricLabels(ti *TunnelInstance) []string {
	return []string{
		ti.Name,
		ti.MetricLabels.Server,
		ti.MetricLabels.Security,
		ti.MetricLabels.SNI,
	}
}

// CleanupRemovedTunnelMetrics removes all Prometheus metrics for tunnel
// instances that exist in oldInstances but not in newInstances.
func CleanupRemovedTunnelMetrics(oldInstances, newInstances []*TunnelInstance) {
	if len(oldInstances) == 0 {
		return
	}

	newKeys := make(map[string]struct{}, len(newInstances))
	for _, ti := range newInstances {
		key := strings.Join(tunnelMetricLabels(ti), "|")
		newKeys[key] = struct{}{}
	}

	for _, ti := range oldInstances {
		key := strings.Join(tunnelMetricLabels(ti), "|")
		if _, exists := newKeys[key]; exists {
			continue
		}

		labels := tunnelMetricLabels(ti)
		metrics.TunnelUp.DeleteLabelValues(labels...)
		metrics.TunnelLatency.DeleteLabelValues(labels...)
		metrics.TunnelLatencyHistogram.DeleteLabelValues(labels...)
		metrics.TunnelLastSuccess.DeleteLabelValues(labels...)
		metrics.TunnelHTTPStatus.DeleteLabelValues(labels...)
		metrics.TunnelCheckTotal.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], "success")
		metrics.TunnelCheckTotal.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], "failure")

		// Delete error metrics for all known reason categories
		for _, reason := range metrics.ErrorReasons {
			metrics.TunnelErrorTotal.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], reason)
		}
	}
}

// reloadConfig gracefully reloads configuration using a "start new, then stop
// old" strategy to avoid downtime: new tunnels are started on fresh ports
// before old ones are stopped.
func (tm *TunnelManager) reloadConfig(configFile string) error {
	slog.Info("reloading configuration", "config_file", configFile)

	metrics.IncConfigReloadTotal()

	// Load new config
	newConfig, err := config.LoadConfig(configFile)
	if err != nil {
		slog.Error("failed to load new config", "error", err)
		metrics.IncConfigReloadErrorsTotal()
		return fmt.Errorf("failed to load config: %v", err)
	}

	// Resolve subscriptions
	subTunnels := config.ResolveSubscriptions(newConfig)
	newConfig.Tunnels = append(newConfig.Tunnels, subTunnels...)

	if len(newConfig.Tunnels) == 0 {
		slog.Error("no tunnels after resolving subscriptions, keeping current config")
		metrics.IncConfigReloadErrorsTotal()
		return fmt.Errorf("no tunnels to initialize")
	}

	// Validate all tunnels before attempting to start new ones
	if err := config.ValidateTunnels(newConfig); err != nil {
		slog.Error("config validation failed, keeping current tunnels", "error", err)
		metrics.IncConfigReloadErrorsTotal()
		return fmt.Errorf("config validation failed: %v", err)
	}

	// Start new tunnels on next available ports (no overlap with current)
	tm.mu.RLock()
	newBasePort := tm.NextSocksPort
	tm.mu.RUnlock()

	newInstances, nextAutoPort, err := InitializeTunnels(newConfig, newBasePort, tm.checker, tm.metrics)
	if err != nil {
		slog.Error("failed to start new tunnels, keeping current", "error", err)
		metrics.IncConfigReloadErrorsTotal()
		return fmt.Errorf("failed to initialize tunnels: %v", err)
	}

	// New tunnels are running — safe to swap and stop old ones
	tm.mu.Lock()
	oldInstances := tm.instances
	tm.instances = newInstances
	tm.NextSocksPort = nextAutoPort
	tm.config = newConfig
	tm.mu.Unlock()

	StopTunnels(oldInstances)
	CleanupRemovedTunnelMetrics(oldInstances, newInstances)

	metrics.SetTunnelsConfigured(len(newInstances))

	slog.Info("configuration reloaded successfully", "tunnel_count", len(newInstances))
	return nil
}

// prometheusMetrics is the production MetricsUpdater backed by the global
// Prometheus gauge/counter vectors.
type prometheusMetrics struct{}

func (prometheusMetrics) Update(name string, ml MetricLabels, r CheckResult) {
	labels := prometheus.Labels{
		"name":     name,
		"server":   ml.Server,
		"security": ml.Security,
		"sni":      ml.SNI,
	}

	resultLabels := func(result string) prometheus.Labels {
		return prometheus.Labels{
			"name":     name,
			"server":   ml.Server,
			"security": ml.Security,
			"sni":      ml.SNI,
			"result":   result,
		}
	}

	if r.Up {
		metrics.TunnelUp.With(labels).Set(1)
		if r.Err == nil {
			metrics.TunnelLatency.With(labels).Set(r.Latency.Seconds())
			metrics.TunnelLatencyHistogram.With(labels).Observe(r.Latency.Seconds())
		}
		metrics.TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
		metrics.TunnelCheckTotal.With(resultLabels("success")).Inc()
	} else {
		metrics.TunnelUp.With(labels).Set(0)
		metrics.TunnelCheckTotal.With(resultLabels("failure")).Inc()
	}

	if r.HTTPStatus > 0 {
		metrics.TunnelHTTPStatus.With(labels).Set(float64(r.HTTPStatus))
	}
}

func (prometheusMetrics) RecordError(name string, ml MetricLabels, err error) {
	errorLabels := prometheus.Labels{
		"name":     name,
		"server":   ml.Server,
		"security": ml.Security,
		"sni":      ml.SNI,
		"reason":   metrics.ClassifyError(err),
	}
	metrics.TunnelErrorTotal.With(errorLabels).Inc()
}

// NewPrometheusMetrics returns a MetricsUpdater backed by the global Prometheus
// metric variables from the metrics package.
func NewPrometheusMetrics() MetricsUpdater {
	return prometheusMetrics{}
}

// RunProbing initializes tunnels, starts watchers, and blocks until ctx is
// canceled. On return all tunnel instances are stopped and per-tunnel metrics
// are cleared.
func RunProbing(ctx context.Context, configFile string, checker HealthChecker, mu MetricsUpdater) error {
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	subTunnels := config.ResolveSubscriptions(cfg)
	cfg.Tunnels = append(cfg.Tunnels, subTunnels...)

	if len(cfg.Tunnels) == 0 {
		return fmt.Errorf("no tunnels to initialize (including subscriptions)")
	}

	slog.Debug("loaded config", "tunnel_count", len(cfg.Tunnels))

	tunnelManager := NewTunnelManager(checker, mu)

	tunnelInstances, nextAutoPort, err := InitializeTunnels(cfg, metrics.DefaultSocksPort, tunnelManager.checker, tunnelManager.metrics)
	if err != nil {
		return fmt.Errorf("failed to initialize tunnels: %v", err)
	}

	tunnelManager.mu.Lock()
	tunnelManager.instances = tunnelInstances
	tunnelManager.NextSocksPort = nextAutoPort
	tunnelManager.config = cfg
	tunnelManager.mu.Unlock()

	metrics.SetTunnelsConfigured(len(tunnelInstances))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := WatchConfigFile(ctx, tunnelManager, configFile); err != nil {
			slog.Error("file watcher stopped", "error", err)
		}
	}()
	go func() {
		defer wg.Done()
		WatchSubscriptions(ctx, tunnelManager, configFile)
	}()

	slog.Info("probing started", "tunnel_count", len(tunnelInstances))
	slog.Info("config auto-reload enabled", "config_file", configFile)

	<-ctx.Done()

	tunnelManager.mu.Lock()
	finalInstances := tunnelManager.instances
	tunnelManager.instances = nil
	tunnelManager.mu.Unlock()

	StopTunnels(finalInstances)
	CleanupRemovedTunnelMetrics(finalInstances, nil)
	metrics.SetTunnelsConfigured(0)

	wg.Wait()
	slog.Info("probing stopped")
	return nil
}
