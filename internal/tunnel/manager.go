package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
)

// CheckerFunc is a function that runs periodic checks on a tunnel instance.
type CheckerFunc func(ctx context.Context, ti *TunnelInstance, m *metrics.Metrics, logger *slog.Logger)

// TunnelManager manages tunnel instances with thread-safe access.
type TunnelManager struct {
	mu        sync.RWMutex
	instances []*TunnelInstance
	metrics   *metrics.Metrics
	logger    *slog.Logger
	checkerFn CheckerFunc
}

// NewManager creates a new TunnelManager.
func NewManager(m *metrics.Metrics, logger *slog.Logger, checkerFn CheckerFunc) *TunnelManager {
	return &TunnelManager{
		metrics:   m,
		logger:    logger,
		checkerFn: checkerFn,
	}
}

// Initialize creates and starts all tunnel instances from config.
func (tm *TunnelManager) Initialize(cfg *config.Config) error {
	if len(cfg.Tunnels) == 0 {
		return fmt.Errorf("no tunnels to initialize")
	}

	var tunnelInstances []*TunnelInstance

	for i, t := range cfg.Tunnels {
		socksPort := cfg.SocksBasePort + i

		tm.logger.Debug("Initializing tunnel", "index", i+1, "name", t.Name, "socks_port", socksPort)

		ti, err := InitInstance(&t, socksPort, tm.logger, tm.metrics)
		if err != nil {
			for _, instance := range tunnelInstances {
				_ = instance.XrayInstance.Close()
				if instance.CancelFunc != nil {
					instance.CancelFunc()
				}
			}
			return fmt.Errorf("failed to initialize tunnel %d: %w", i+1, err)
		}

		tunnelInstances = append(tunnelInstances, ti)

		tm.logger.Info("Started tunnel",
			"name", ti.Name,
			"server", fmt.Sprintf("%s:%d", ti.VLESSConfig.Address, ti.VLESSConfig.Port),
			"security", ti.VLESSConfig.Security,
			"socks_port", socksPort,
		)
	}

	// Wait for all SOCKS ports to become ready
	for _, ti := range tunnelInstances {
		if err := WaitForSOCKSPort(ti.SocksPort, 10*time.Second); err != nil {
			tm.logger.Warn("SOCKS port not ready", "name", ti.Name, "port", ti.SocksPort, "error", err)
		}
	}

	// Start checker goroutines for all tunnels
	for _, ti := range tunnelInstances {
		ctx, cancel := context.WithCancel(context.Background())
		ti.CancelFunc = cancel
		go tm.checkerFn(ctx, ti, tm.metrics, tm.logger)
	}

	tm.mu.Lock()
	tm.instances = tunnelInstances
	tm.mu.Unlock()

	return nil
}

// StopAll gracefully stops all tunnel instances.
func (tm *TunnelManager) StopAll() {
	tm.mu.Lock()
	instances := tm.instances
	tm.instances = nil
	tm.mu.Unlock()

	stopTunnels(instances)
}

func stopTunnels(instances []*TunnelInstance) {
	for _, ti := range instances {
		if ti.CancelFunc != nil {
			ti.CancelFunc()
		}
		if ti.XrayInstance != nil {
			_ = ti.XrayInstance.Close()
		}
	}
}

// Reload gracefully reloads configuration. Validates before stopping tunnels.
func (tm *TunnelManager) Reload(configFile string) error {
	tm.logger.Info("Reloading configuration", "file", configFile)

	newConfig, err := config.Load(configFile)
	if err != nil {
		tm.logger.Error("Failed to load new config", "error", err)
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate before stopping existing tunnels (#7)
	if err := newConfig.Validate(); err != nil {
		tm.logger.Error("New config validation failed", "error", err)
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Capture existing instances for metric cleanup
	tm.mu.Lock()
	oldInstances := tm.instances
	tm.instances = nil
	tm.mu.Unlock()

	oldLabelSets := make([]metrics.LabelSet, len(oldInstances))
	for i, ti := range oldInstances {
		oldLabelSets[i] = ti.LabelSet()
	}

	stopTunnels(oldInstances)

	// Initialize new tunnels
	if err := tm.Initialize(newConfig); err != nil {
		tm.logger.Error("Failed to initialize new tunnels", "error", err)
		return fmt.Errorf("failed to initialize tunnels: %w", err)
	}

	// Collect new label sets
	tm.mu.RLock()
	newLabelSets := make([]metrics.LabelSet, len(tm.instances))
	for i, ti := range tm.instances {
		newLabelSets[i] = ti.LabelSet()
	}
	tm.mu.RUnlock()

	// Cleanup metrics for removed tunnels
	tm.metrics.CleanupRemoved(oldLabelSets, newLabelSets)

	tm.logger.Info("Configuration reloaded successfully", "tunnels", len(newLabelSets))
	return nil
}

// WaitForSOCKSPort polls the SOCKS port until it accepts connections or the timeout expires.
func WaitForSOCKSPort(port int, timeout time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready after %v", port, timeout)
}

// HealthHandler returns 200 if at least one tunnel is UP, else 503.
func (tm *TunnelManager) HealthHandler(w http.ResponseWriter, r *http.Request) {
	tm.mu.RLock()
	instances := tm.instances
	tm.mu.RUnlock()

	if len(instances) == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, "no tunnels configured")
		return
	}

	for _, ti := range instances {
		if ti.Up.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "OK")
			return
		}
	}

	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = fmt.Fprint(w, "all tunnels down")
}
