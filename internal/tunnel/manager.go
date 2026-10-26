package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"os"
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
	reloadMu      sync.Mutex
	sources       map[string]subscriptionState
	desiredConfig *config.Config
	fingerprints  map[*TunnelInstance]string
	changed       chan struct{}
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
	return &TunnelManager{checker: checker, metrics: mu, sources: make(map[string]subscriptionState), fingerprints: make(map[*TunnelInstance]string), changed: make(chan struct{}, 1)}
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

	if len(tunnel.XrayConfigJSON) > 0 {
		xrayConfigJSON, metricLabels, err = LoadXrayConfigJSON(tunnel.XrayConfigJSON, socksPort)
		if err != nil {
			return nil, err
		}
	} else if tunnel.URL != "" && !strings.HasPrefix(tunnel.URL, "vless://") {
		xrayConfigJSON, metricLabels, err = CreateShareLinkConfig(tunnel.URL, socksPort)
		if err != nil {
			return nil, err
		}
	} else if tunnel.XrayConfigFile != "" {
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

	slog.Debug("starting Xray instance", "tunnel", tunnel.Name, "socks_port", socksPort)

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

// createTunnelInstances creates and starts all tunnel instances from config,
// assigns SOCKS ports, and waits for the ports to become ready. It does NOT
// start periodic checker goroutines — that is the caller's responsibility.
// This is shared between InitializeTunnels (daemon) and RunOnce (one-shot).
func createTunnelInstances(cfg *config.Config, baseSocksPort int) ([]*TunnelInstance, int, error) {
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

	return tunnelInstances, nextAutoPort, nil
}

// InitializeTunnels creates and starts all tunnel instances from config and
// launches periodic checker goroutines for each.
// Returns the instances and the next available auto-port (past all assigned auto-ports).
func InitializeTunnels(cfg *config.Config, baseSocksPort int, checker HealthChecker, mu MetricsUpdater) ([]*TunnelInstance, int, error) {
	tunnelInstances, nextAutoPort, err := createTunnelInstances(cfg, baseSocksPort)
	if err != nil {
		return nil, baseSocksPort, err
	}

	// Start checker goroutines for all tunnels
	for _, ti := range tunnelInstances {
		ctx, cancel := context.WithCancel(context.Background())
		ti.cancelFunc = cancel
		ti.checkerDone = make(chan struct{})
		go func() { defer close(ti.checkerDone); RunTunnelChecker(ctx, ti, checker, mu) }()
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
	// A check already in flight may still record metrics after cancellation.
	// Join before callers remove its metric series.
	for _, ti := range instances {
		if ti.checkerDone != nil {
			<-ti.checkerDone
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

// subscriptionState keeps the last successfully applied response separately from
// the attempt time, so a temporary outage never deletes working tunnels.
type subscriptionState struct {
	tunnels         []config.Tunnel
	staged          []config.Tunnel // Fetched successfully, awaiting an atomic candidate apply.
	lastAttempt     time.Time
	stagedAt        time.Time
	lastSuccess     time.Time
	lastFetchFailed bool
}

func subscriptionKey(sub config.Subscription) string {
	sub.UpdateInterval = ""
	data, _ := json.Marshal(sub)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func tunnelFingerprint(t config.Tunnel) (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	if t.XrayConfigFile != "" {
		contents, err := os.ReadFile(t.XrayConfigFile)
		if err != nil {
			return "", err
		}
		data = append(data, contents...)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func (tm *TunnelManager) reloadConfig(configFile string) error {
	return tm.reloadConfigContext(context.Background(), configFile, false)
}

// reloadConfigContext serializes file changes and subscription refreshes. File
// changes reuse cached responses; scheduled refreshes fetch only due sources.
func (tm *TunnelManager) reloadConfigContext(ctx context.Context, configFile string, refresh bool) (err error) {
	tm.reloadMu.Lock()
	defer tm.reloadMu.Unlock()
	metrics.IncConfigReloadTotal()
	defer func() {
		if err != nil {
			metrics.IncConfigReloadErrorsTotal()
		}
	}()
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	// Keep retry scheduling separate from the currently applied tunnels. A
	// newly added source must be retried even if its first response fails.
	tm.desiredConfig = cfg
	defer func() {
		select {
		case tm.changed <- struct{}{}:
		default:
		}
	}()
	if tm.sources == nil {
		tm.sources = make(map[string]subscriptionState)
	}
	pending := make(map[string]subscriptionState)
	names := make(map[string]string)
	var activeNames []string
	var unresolved error
	validatingCandidate := false
	defer func() {
		// A staged response is counted as rejected only once. Keep accepted state
		// intact, and retain any later failed HTTP status when publishing metrics.
		if err != nil && validatingCandidate {
			for key := range names {
				state := tm.sources[key]
				if len(state.staged) != 0 {
					metrics.IncSubscriptionRefreshErrors(names[key])
					state.lastFetchFailed = true
					state.staged = nil
					state.stagedAt = time.Time{}
					tm.sources[key] = state
				}
			}
		}
		for key, name := range names {
			state := tm.sources[key]
			metrics.UpdateSubscriptionStatus(name, len(state.tunnels) > 0 && !state.lastFetchFailed, state.lastSuccess, len(state.tunnels))
		}
	}()
	for i, sub := range cfg.Subscriptions {
		name := sub.Name
		if name == "" {
			name = fmt.Sprintf("subscription-%d", i+1)
		}
		activeNames = append(activeNames, name)
		key := subscriptionKey(sub)
		names[key] = name
		state, exists := tm.sources[key]
		interval, _ := time.ParseDuration(sub.UpdateInterval)
		if !exists || (!refresh && len(state.tunnels) == 0 && len(state.staged) == 0) || (refresh && !time.Now().Before(state.lastAttempt.Add(interval))) {
			tunnels, fetchErr := config.FetchSubscriptionContext(ctx, sub)
			state.lastAttempt = time.Now()
			if fetchErr == nil && len(tunnels) == 0 {
				fetchErr = fmt.Errorf("empty subscription response")
			}
			if fetchErr != nil {
				state.lastFetchFailed = true
				metrics.IncSubscriptionRefreshErrors(name)
				slog.Warn("subscription refresh failed; retaining previous tunnels", "subscription_index", i, "error", fetchErr)
			} else {
				state.lastFetchFailed = false
				state.staged = tunnels
				state.stagedAt = state.lastAttempt
			}
			tm.sources[key] = state
		}
		// Preserve successful responses across other sources' retry deadlines,
		// but promote them to last-good only after the entire candidate applies.
		if len(state.staged) != 0 {
			state.tunnels = state.staged
			state.lastSuccess = state.stagedAt
			state.staged = nil
			state.stagedAt = time.Time{}
		}
		if len(state.tunnels) == 0 {
			unresolved = fmt.Errorf("subscription %d has no usable cached response", i+1)
			continue
		}
		pending[key] = state
		for _, tunnel := range state.tunnels {
			config.ApplyTunnelDefaults(&tunnel, cfg.Defaults)
			cfg.Tunnels = append(cfg.Tunnels, tunnel)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if unresolved != nil {
		return unresolved
	}
	validatingCandidate = true
	if len(cfg.Tunnels) == 0 {
		return fmt.Errorf("no tunnels to initialize")
	}
	if err := config.ValidateTunnels(cfg); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	if err := tm.reconcile(ctx, cfg); err != nil {
		return err
	}
	tm.sources = pending
	metrics.CleanupSubscriptionMetrics(activeNames)
	return nil
}

// reconcile starts only changed tunnels and keeps the old set intact if a new
// instance cannot start. Ports still owned by the old set remain reserved.
func (tm *TunnelManager) reconcile(ctx context.Context, cfg *config.Config) error {
	tm.mu.RLock()
	old := append([]*TunnelInstance(nil), tm.instances...)
	tm.mu.RUnlock()
	available := make(map[string][]*TunnelInstance)
	occupied := make(map[int]bool)
	for _, ti := range old {
		occupied[ti.SocksPort] = true
		if key := tm.fingerprints[ti]; key != "" {
			available[key] = append(available[key], ti)
		}
	}
	for _, t := range cfg.Tunnels {
		if t.SocksPort != 0 {
			occupied[t.SocksPort] = true
		}
	}
	var next, created []*TunnelInstance
	keys := make(map[*TunnelInstance]string)
	retained := make(map[*TunnelInstance]bool)
	rollback := func(err error) error { StopTunnels(created); return err }
	for _, t := range cfg.Tunnels {
		key, err := tunnelFingerprint(t)
		if err != nil {
			return rollback(err)
		}
		if candidates := available[key]; len(candidates) > 0 {
			ti := candidates[0]
			available[key] = candidates[1:]
			retained[ti] = true
			keys[ti] = key
			next = append(next, ti)
			continue
		}
		port := t.SocksPort
		if port == 0 {
			port = metrics.DefaultSocksPort
			for port <= 65535 && occupied[port] {
				port++
			}
			if port > 65535 {
				return rollback(fmt.Errorf("no SOCKS ports available"))
			}
		} else {
			for _, ti := range old {
				if ti.SocksPort == port {
					return rollback(fmt.Errorf("cannot replace active tunnel on explicit socks_port %d; restart required", port))
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return rollback(err)
		}
		ti, err := InitTunnel(&t, port)
		if err != nil {
			return rollback(fmt.Errorf("failed to initialize tunnel %q: %w", t.Name, err))
		}
		created = append(created, ti)
		if err := WaitForSOCKSPort(port, metrics.SocksStartupTimeout); err != nil {
			return rollback(err)
		}
		occupied[port] = true
		next = append(next, ti)
		keys[ti] = key
	}
	if err := ctx.Err(); err != nil {
		return rollback(err)
	}
	for _, ti := range created {
		checkCtx, cancel := context.WithCancel(ctx)
		ti.cancelFunc = cancel
		ti.checkerDone = make(chan struct{})
		go func() { defer close(ti.checkerDone); RunTunnelChecker(checkCtx, ti, tm.checker, tm.metrics) }()
	}
	tm.mu.Lock()
	tm.instances = next
	tm.config = cfg
	tm.fingerprints = keys
	tm.NextSocksPort = metrics.DefaultSocksPort
	for occupied[tm.NextSocksPort] {
		tm.NextSocksPort++
	}
	tm.mu.Unlock()
	var removed []*TunnelInstance
	for _, ti := range old {
		if !retained[ti] {
			removed = append(removed, ti)
		}
	}
	StopTunnels(removed)
	CleanupRemovedTunnelMetrics(removed, next)
	metrics.SetTunnelsConfigured(len(next))
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
	tunnelManager := NewTunnelManager(checker, mu)
	if err := tunnelManager.reloadConfigContext(ctx, configFile, false); err != nil {
		return err
	}
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

	slog.Info("probing started")
	slog.Info("config auto-reload enabled", "config_file", configFile)

	<-ctx.Done()
	wg.Wait()
	tunnelManager.reloadMu.Lock()
	defer tunnelManager.reloadMu.Unlock()

	tunnelManager.mu.Lock()
	finalInstances := tunnelManager.instances
	tunnelManager.instances = nil
	tunnelManager.mu.Unlock()

	StopTunnels(finalInstances)
	CleanupRemovedTunnelMetrics(finalInstances, nil)
	metrics.SetTunnelsConfigured(0)

	slog.Info("probing stopped")
	return nil
}
