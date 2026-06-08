package tunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// mockChecker is a test-only HealthChecker that does nothing.
type mockChecker struct{}

func (mockChecker) Check(ti *TunnelInstance) CheckResult {
	return CheckResult{Up: true, HTTPStatus: 200, Latency: time.Millisecond}
}

var _ HealthChecker = mockChecker{}

func TestInitializeTunnels(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		config := &config.Config{
			Tunnels: []config.Tunnel{},
		}

		instances, _, err := InitializeTunnels(config, metrics.DefaultSocksPort, mockChecker{}, NewPrometheusMetrics())
		if err == nil {
			t.Error("expected error for empty tunnels")
		}
		if instances != nil {
			t.Error("expected nil instances for empty config")
		}
	})

	t.Run("invalid tunnel URL", func(t *testing.T) {
		config := &config.Config{
			Tunnels: []config.Tunnel{
				{
					Name:          "invalid",
					URL:           "invalid-url",
					CheckURL:      "https://example.com",
					CheckInterval: "30s",
					CheckTimeout:  "10s",
				},
			},
		}

		instances, _, err := InitializeTunnels(config, metrics.DefaultSocksPort, mockChecker{}, NewPrometheusMetrics())
		if err == nil {
			t.Error("expected error for invalid URL")
		}
		if instances != nil {
			t.Error("expected nil instances for invalid config")
		}
	})
}

func TestInitializeTunnels_SocksPort(t *testing.T) {
	t.Run("custom socks_port is used", func(t *testing.T) {
		tmpDir := t.TempDir()
		xrayConfigPath := filepath.Join(tmpDir, "xray.json")
		xrayJSON := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"test-uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`
		os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644)

		cfg := &config.Config{
			Tunnels: []config.Tunnel{
				{
					Name:           "custom-port",
					XrayConfigFile: xrayConfigPath,
					CheckURL:       "https://example.com",
					CheckInterval:  "30s",
					CheckTimeout:   "10s",
					SocksPort:      25000,
				},
			},
		}

		instances, _, err := InitializeTunnels(cfg, metrics.DefaultSocksPort, mockChecker{}, NewPrometheusMetrics())
		if err != nil {
			t.Fatalf("InitializeTunnels() error = %v", err)
		}
		defer StopTunnels(instances)

		if instances[0].SocksPort != 25000 {
			t.Errorf("SocksPort = %v, want 25000", instances[0].SocksPort)
		}
	})

	t.Run("auto-assigned ports skip custom ports", func(t *testing.T) {
		tmpDir := t.TempDir()
		xrayConfigPath := filepath.Join(tmpDir, "xray.json")
		xrayJSON := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"test-uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`
		os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644)

		cfg := &config.Config{
			Tunnels: []config.Tunnel{
				{
					Name:           "auto1",
					XrayConfigFile: xrayConfigPath,
					CheckURL:       "https://example.com",
					CheckInterval:  "30s",
					CheckTimeout:   "10s",
				},
				{
					Name:           "custom",
					XrayConfigFile: xrayConfigPath,
					CheckURL:       "https://example.com",
					CheckInterval:  "30s",
					CheckTimeout:   "10s",
					SocksPort:      25000,
				},
				{
					Name:           "auto2",
					XrayConfigFile: xrayConfigPath,
					CheckURL:       "https://example.com",
					CheckInterval:  "30s",
					CheckTimeout:   "10s",
				},
			},
		}

		instances, _, err := InitializeTunnels(cfg, 1080, mockChecker{}, NewPrometheusMetrics())
		if err != nil {
			t.Fatalf("InitializeTunnels() error = %v", err)
		}
		defer StopTunnels(instances)

		if instances[0].SocksPort != 1080 {
			t.Errorf("auto1 SocksPort = %v, want 1080", instances[0].SocksPort)
		}
		if instances[1].SocksPort != 25000 {
			t.Errorf("custom SocksPort = %v, want 25000", instances[1].SocksPort)
		}
		if instances[2].SocksPort != 1081 {
			t.Errorf("auto2 SocksPort = %v, want 1081", instances[2].SocksPort)
		}
	})

	t.Run("auto ports skip custom ports that fall in auto range", func(t *testing.T) {
		tmpDir := t.TempDir()
		xrayConfigPath := filepath.Join(tmpDir, "xray.json")
		xrayJSON := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"test-uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`
		os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644)

		cfg := &config.Config{
			Tunnels: []config.Tunnel{
				{Name: "auto1", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s"},
				{Name: "custom", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s", SocksPort: 1081},
				{Name: "auto2", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s"},
				{Name: "auto3", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s"},
			},
		}

		instances, _, err := InitializeTunnels(cfg, 1080, mockChecker{}, NewPrometheusMetrics())
		if err != nil {
			t.Fatalf("InitializeTunnels() error = %v", err)
		}
		defer StopTunnels(instances)

		if instances[0].SocksPort != 1080 {
			t.Errorf("auto1 SocksPort = %v, want 1080", instances[0].SocksPort)
		}
		if instances[1].SocksPort != 1081 {
			t.Errorf("custom SocksPort = %v, want 1081", instances[1].SocksPort)
		}
		if instances[2].SocksPort != 1082 {
			t.Errorf("auto2 SocksPort = %v, want 1082", instances[2].SocksPort)
		}
		if instances[3].SocksPort != 1083 {
			t.Errorf("auto3 SocksPort = %v, want 1083", instances[3].SocksPort)
		}
	})

	t.Run("nextAutoPort skips custom ports and returns correct next port", func(t *testing.T) {
		tmpDir := t.TempDir()
		xrayConfigPath := filepath.Join(tmpDir, "xray.json")
		xrayJSON := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"test-uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`
		os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644)

		cfg := &config.Config{
			Tunnels: []config.Tunnel{
				{Name: "auto1", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s"},
				{Name: "custom", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s", SocksPort: 1081},
				{Name: "auto2", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s"},
			},
		}

		instances, nextAutoPort, err := InitializeTunnels(cfg, 1080, mockChecker{}, NewPrometheusMetrics())
		if err != nil {
			t.Fatalf("InitializeTunnels() error = %v", err)
		}
		defer StopTunnels(instances)

		if nextAutoPort != 1083 {
			t.Errorf("nextAutoPort = %v, want 1083", nextAutoPort)
		}
	})

	t.Run("nextAutoPort not affected by high custom port", func(t *testing.T) {
		tmpDir := t.TempDir()
		xrayConfigPath := filepath.Join(tmpDir, "xray.json")
		xrayJSON := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"test-uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`
		os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644)

		cfg := &config.Config{
			Tunnels: []config.Tunnel{
				{Name: "auto1", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s"},
				{Name: "custom", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s", SocksPort: 20000},
				{Name: "auto2", XrayConfigFile: xrayConfigPath, CheckURL: "https://example.com", CheckInterval: "30s", CheckTimeout: "10s"},
			},
		}

		instances, nextAutoPort, err := InitializeTunnels(cfg, 1080, mockChecker{}, NewPrometheusMetrics())
		if err != nil {
			t.Fatalf("InitializeTunnels() error = %v", err)
		}
		defer StopTunnels(instances)

		if nextAutoPort != 1082 {
			t.Errorf("nextAutoPort = %v, want 1082 (should not be affected by custom port 20000)", nextAutoPort)
		}
	})
}

func TestInitializeTunnels_CleanupOnError(t *testing.T) {
	tmpDir := t.TempDir()
	xrayConfig := filepath.Join(tmpDir, "xray.json")
	xrayJSON := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"test","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`
	os.WriteFile(xrayConfig, []byte(xrayJSON), 0644)

	cfg := &config.Config{
		Tunnels: []config.Tunnel{
			{
				Name:           "valid-xray",
				XrayConfigFile: xrayConfig,
				CheckURL:       "https://example.com",
				CheckInterval:  "30s",
				CheckTimeout:   "10s",
			},
			{
				Name:          "invalid",
				URL:           "not-vless://bad",
				CheckURL:      "https://example.com",
				CheckInterval: "30s",
				CheckTimeout:  "10s",
			},
		},
	}

	instances, _, err := InitializeTunnels(cfg, 15000, mockChecker{}, NewPrometheusMetrics())
	if err == nil {
		t.Error("expected error for second invalid tunnel")
		if instances != nil {
			StopTunnels(instances)
		}
	}
}

func TestStopTunnels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	ti := &TunnelInstance{
		Name:       "test-tunnel",
		cancelFunc: cancel,
		VLESSConfig: &VLESSConfig{
			Address:  "test.com",
			Port:     443,
			Security: "tls",
		},
		MetricLabels: MetricLabels{
			Server:   "test.com:443",
			Security: "tls",
		},
		SocksPort: 1080,
	}

	instances := []*TunnelInstance{ti}
	StopTunnels(instances)

	select {
	case <-ctx.Done():
	case <-time.After(1 * time.Second):
		t.Error("context was not cancelled")
	}
}

func TestStopTunnels_NilXrayInstance(t *testing.T) {
	ti := &TunnelInstance{
		Name:         "nil-xray",
		XrayInstance: nil,
		cancelFunc:   nil,
	}
	StopTunnels([]*TunnelInstance{ti})
}

func TestTunnelManagerReloadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	initialConfig := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("config.LoadConfig() error = %v", err)
	}

	if len(cfg.Tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(cfg.Tunnels))
	}

	newConfig := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
  - name: "tunnel2"
    url: "vless://uuid2@example2.com:443?type=tcp&security=tls&sni=test2.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(newConfig), 0644); err != nil {
		t.Fatalf("failed to update config: %v", err)
	}

	cfg2, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("config.LoadConfig() error = %v", err)
	}

	if len(cfg2.Tunnels) != 2 {
		t.Errorf("expected 2 tunnels, got %d", len(cfg2.Tunnels))
	}
}

func TestWaitForSOCKSPort(t *testing.T) {
	t.Run("port ready immediately", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		_, portStr, _ := net.SplitHostPort(listener.Addr().String())
		port := 0
		fmt.Sscanf(portStr, "%d", &port)

		err = WaitForSOCKSPort(port, 2*time.Second)
		if err != nil {
			t.Errorf("WaitForSOCKSPort() error = %v, expected nil", err)
		}
	})

	t.Run("port becomes ready after delay", func(t *testing.T) {
		tmpListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to find free port: %v", err)
		}
		_, portStr, _ := net.SplitHostPort(tmpListener.Addr().String())
		port := 0
		fmt.Sscanf(portStr, "%d", &port)
		tmpListener.Close()

		go func() {
			time.Sleep(500 * time.Millisecond)
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return
			}
			defer l.Close()
			time.Sleep(3 * time.Second)
		}()

		err = WaitForSOCKSPort(port, 3*time.Second)
		if err != nil {
			t.Errorf("WaitForSOCKSPort() error = %v, expected nil", err)
		}
	})

	t.Run("port never ready", func(t *testing.T) {
		err := WaitForSOCKSPort(59999, 1*time.Second)
		if err == nil {
			t.Error("WaitForSOCKSPort() expected error for unavailable port")
		}
	})
}

func TestTunnelMetricLabels(t *testing.T) {
	ti := &TunnelInstance{
		Name: "metrics-test",
		MetricLabels: MetricLabels{
			Server:   "example.com:443",
			Security: "tls",
			SNI:      "example.com",
		},
	}

	want := []string{"metrics-test", "example.com:443", "tls", "example.com"}
	got := tunnelMetricLabels(ti)

	if len(got) != len(want) {
		t.Fatalf("labels length = %d, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("label[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestCleanupRemovedTunnelMetrics(t *testing.T) {
	resetAllMetrics := func() {
		metrics.TunnelUp.Reset()
		metrics.TunnelLatency.Reset()
		metrics.TunnelLatencyHistogram.Reset()
		metrics.TunnelLastSuccess.Reset()
		metrics.TunnelHTTPStatus.Reset()
		metrics.TunnelCheckTotal.Reset()
		metrics.TunnelErrorTotal.Reset()
	}

	resetAllMetrics()
	defer resetAllMetrics()

	removed := &TunnelInstance{
		Name: "removed",
		MetricLabels: MetricLabels{
			Server:   "removed.example.com:1443",
			Security: "reality",
			SNI:      "google.com",
		},
	}

	kept := &TunnelInstance{
		Name: "kept",
		MetricLabels: MetricLabels{
			Server:   "kept.example.com:2443",
			Security: "tls",
			SNI:      "kept.example.com",
		},
	}

	newInstance := &TunnelInstance{
		Name: "new",
		MetricLabels: MetricLabels{
			Server:   "new.example.com:3443",
			Security: "tls",
			SNI:      "new.example.com",
		},
	}

	populateMetrics := func(ti *TunnelInstance) {
		labelVals := prometheus.Labels{
			"name":     ti.Name,
			"server":   ti.MetricLabels.Server,
			"security": ti.MetricLabels.Security,
			"sni":      ti.MetricLabels.SNI,
		}
		metrics.TunnelUp.With(labelVals).Set(1)
		metrics.TunnelLatency.With(labelVals).Set(0.2)
		metrics.TunnelLatencyHistogram.With(labelVals).Observe(0.2)
		metrics.TunnelLastSuccess.With(labelVals).Set(float64(time.Now().Unix()))
		metrics.TunnelHTTPStatus.With(labelVals).Set(200)

		successLabels := prometheus.Labels{
			"name": labelVals["name"], "server": labelVals["server"],
			"security": labelVals["security"], "sni": labelVals["sni"], "result": "success",
		}
		failLabels := prometheus.Labels{
			"name": labelVals["name"], "server": labelVals["server"],
			"security": labelVals["security"], "sni": labelVals["sni"], "result": "failure",
		}
		metrics.TunnelCheckTotal.With(successLabels).Inc()
		metrics.TunnelCheckTotal.With(failLabels).Inc()
	}

	populateMetrics(removed)
	populateMetrics(kept)
	populateMetrics(newInstance)

	CleanupRemovedTunnelMetrics([]*TunnelInstance{removed, kept}, []*TunnelInstance{kept, newInstance})

	if metricExistsWithLabels(t, "xray_tunnel_up", prometheus.Labels{
		"name": "removed", "server": "removed.example.com:1443", "security": "reality", "sni": "google.com",
	}) {
		t.Errorf("expected metrics for removed tunnel to be deleted")
	}

	if !metricExistsWithLabels(t, "xray_tunnel_up", prometheus.Labels{
		"name": "kept", "server": "kept.example.com:2443", "security": "tls", "sni": "kept.example.com",
	}) {
		t.Errorf("expected metrics for kept tunnel to remain")
	}

	for _, result := range []string{"success", "failure"} {
		if metricExistsWithLabels(t, "xray_tunnel_check_total", prometheus.Labels{
			"name": "removed", "server": "removed.example.com:1443", "security": "reality", "sni": "google.com", "result": result,
		}) {
			t.Errorf("expected counter metric (%s) for removed tunnel to be deleted", result)
		}
	}

	if !metricExistsWithLabels(t, "xray_tunnel_check_total", prometheus.Labels{
		"name": "kept", "server": "kept.example.com:2443", "security": "tls", "sni": "kept.example.com", "result": "success",
	}) {
		t.Errorf("expected counter metric for kept tunnel to remain")
	}
}

func TestCleanupRemovedTunnelMetrics_ErrorMetrics(t *testing.T) {
	resetAllMetrics := func() {
		metrics.TunnelUp.Reset()
		metrics.TunnelLatency.Reset()
		metrics.TunnelLastSuccess.Reset()
		metrics.TunnelHTTPStatus.Reset()
		metrics.TunnelCheckTotal.Reset()
		metrics.TunnelErrorTotal.Reset()
	}

	resetAllMetrics()
	defer resetAllMetrics()

	removed := &TunnelInstance{
		Name: "err-removed",
		MetricLabels: MetricLabels{
			Server:   "err.example.com:1443",
			Security: "tls",
			SNI:      "err.example.com",
		},
	}

	kept := &TunnelInstance{
		Name: "err-kept",
		MetricLabels: MetricLabels{
			Server:   "kept.example.com:2443",
			Security: "tls",
			SNI:      "kept.example.com",
		},
	}

	for _, ti := range []*TunnelInstance{removed, kept} {
		labels := prometheus.Labels{
			"name": ti.Name, "server": ti.MetricLabels.Server,
			"security": ti.MetricLabels.Security, "sni": ti.MetricLabels.SNI,
		}
		for _, reason := range metrics.ErrorReasons {
			errorLabels := prometheus.Labels{
				"name": labels["name"], "server": labels["server"],
				"security": labels["security"], "sni": labels["sni"], "reason": reason,
			}
			metrics.TunnelErrorTotal.With(errorLabels).Add(1)
		}
	}

	CleanupRemovedTunnelMetrics([]*TunnelInstance{removed, kept}, []*TunnelInstance{kept})

	for _, reason := range metrics.ErrorReasons {
		if metricExistsWithLabels(t, "xray_tunnel_error_total", prometheus.Labels{
			"name": "err-removed", "server": "err.example.com:1443", "security": "tls", "sni": "err.example.com", "reason": reason,
		}) {
			t.Errorf("expected error metric (reason=%s) for removed tunnel to be deleted", reason)
		}
	}

	for _, reason := range metrics.ErrorReasons {
		if !metricExistsWithLabels(t, "xray_tunnel_error_total", prometheus.Labels{
			"name": "err-kept", "server": "kept.example.com:2443", "security": "tls", "sni": "kept.example.com", "reason": reason,
		}) {
			t.Errorf("expected error metric (reason=%s) for kept tunnel to remain", reason)
		}
	}
}

func TestCleanupRemovedTunnelMetrics_EmptyOld(t *testing.T) {
	CleanupRemovedTunnelMetrics(nil, []*TunnelInstance{
		{Name: "new", MetricLabels: MetricLabels{Server: "s:443", Security: "tls", SNI: "s"}},
	})
}

func TestReloadConfig_InvalidConfigKeepsOldTunnels(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	invalidConfig := `tunnels:
  - name: "bad"
    url: "vless://bad-url-no-port"
    check_url: "ftp://bad"
    check_interval: "30s"
    check_timeout: "10s"`

	if err := os.WriteFile(configFile, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	existingInstance := &TunnelInstance{
		Name: "existing-tunnel",
		VLESSConfig: &VLESSConfig{
			Address:  "example.com",
			Port:     443,
			Security: "tls",
			SNI:      "test.com",
		},
		MetricLabels: MetricLabels{
			Server:   "example.com:443",
			Security: "tls",
			SNI:      "test.com",
		},
		SocksPort:     1080,
		CheckTimeout:  10 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{existingInstance}
	tm.NextSocksPort = metrics.DefaultSocksPort + 1

	err := tm.reloadConfig(configFile)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	// The error comes from config validation (check_url is invalid)
	if !strings.Contains(err.Error(), "config validation failed") {
		t.Errorf("expected 'config validation failed' in error, got: %v", err)
	}

	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if len(tm.instances) != 1 {
		t.Errorf("expected 1 existing tunnel to remain, got %d", len(tm.instances))
	}
	if tm.instances[0].Name != "existing-tunnel" {
		t.Errorf("expected existing-tunnel, got %s", tm.instances[0].Name)
	}
}

func TestReloadConfig_LoadError(t *testing.T) {
	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{}
	tm.NextSocksPort = 1080

	err := tm.reloadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent config")
	}
}

func TestReloadConfig_NoTunnelsAfterResolve(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	cfg := fmt.Sprintf(`subscriptions:
  - url: "http://127.0.0.1:1/fail"
    update_interval: "1h"`)

	if err := os.WriteFile(configFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{}
	tm.NextSocksPort = 1080

	err := tm.reloadConfig(configFile)
	if err == nil {
		t.Error("expected error when no tunnels after resolve")
	}
}

func TestReloadConfig_ValidationError(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	cfg := `tunnels:
  - name: "bad"
    url: "vless://bad-no-port"
    check_url: "bad-url"`

	if err := os.WriteFile(configFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{}
	tm.NextSocksPort = 1080

	err := tm.reloadConfig(configFile)
	if err == nil {
		t.Error("expected validation error")
	}
}

func TestInitTunnel_XrayConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	xrayConfigPath := filepath.Join(tmpDir, "xray.json")

	xrayJSON := `{
		"outbounds": [
			{
				"protocol": "vless",
				"settings": {
					"vnext": [{
						"address": "example.com",
						"port": 443,
						"users": [{"id": "test-uuid", "encryption": "none"}]
					}]
				},
				"streamSettings": {
					"network": "tcp",
					"security": "tls",
					"tlsSettings": {
						"serverName": "example.com",
						"fingerprint": "chrome"
					}
				}
			}
		]
	}`
	os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644)

	tunnel := &config.Tunnel{
		Name:           "json-tunnel",
		XrayConfigFile: xrayConfigPath,
		CheckURL:       "https://example.com",
		CheckInterval:  "30s",
		CheckTimeout:   "10s",
	}

	ti, err := InitTunnel(tunnel, 11080)
	if err != nil {
		t.Fatalf("InitTunnel() error = %v", err)
	}
	defer ti.XrayInstance.Close()

	if ti.Name != "json-tunnel" {
		t.Errorf("Name = %v, want json-tunnel", ti.Name)
	}
	if ti.SocksPort != 11080 {
		t.Errorf("SocksPort = %v, want 11080", ti.SocksPort)
	}
	if ti.VLESSConfig != nil {
		t.Error("VLESSConfig should be nil for xray_config_file tunnel")
	}
	if ti.MetricLabels.Server != "example.com:443" {
		t.Errorf("MetricLabels.Server = %v, want example.com:443", ti.MetricLabels.Server)
	}
	if ti.MetricLabels.Security != "tls" {
		t.Errorf("MetricLabels.Security = %v, want tls", ti.MetricLabels.Security)
	}
	if ti.MetricLabels.SNI != "example.com" {
		t.Errorf("MetricLabels.SNI = %v, want example.com", ti.MetricLabels.SNI)
	}
}

func TestInitTunnel_VLESSURLParseError(t *testing.T) {
	tunnel := &config.Tunnel{
		Name:          "bad-vless",
		URL:           "vless://bad-url-no-port",
		CheckURL:      "https://example.com",
		CheckInterval: "30s",
		CheckTimeout:  "10s",
	}

	_, err := InitTunnel(tunnel, 1080)
	if err == nil {
		t.Error("expected error for invalid VLESS URL")
	}
	if !strings.Contains(err.Error(), "failed to parse VLESS URL") {
		t.Errorf("expected VLESS parse error, got: %v", err)
	}
}

func TestInitTunnel_InvalidDurations(t *testing.T) {
	t.Run("invalid check_interval", func(t *testing.T) {
		tunnel := &config.Tunnel{
			Name:          "test",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "https://example.com",
			CheckInterval: "invalid-duration",
			CheckTimeout:  "10s",
		}

		_, err := InitTunnel(tunnel, 1080)
		if err == nil {
			t.Error("expected error for invalid check_interval")
		}
		if !strings.Contains(err.Error(), "invalid check_interval") {
			t.Errorf("expected error message about check_interval, got: %v", err)
		}
	})

	t.Run("invalid check_timeout", func(t *testing.T) {
		tunnel := &config.Tunnel{
			Name:          "test",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "not-a-duration",
		}

		_, err := InitTunnel(tunnel, 1080)
		if err == nil {
			t.Error("expected error for invalid check_timeout")
		}
		if !strings.Contains(err.Error(), "invalid check_timeout") {
			t.Errorf("expected error message about check_timeout, got: %v", err)
		}
	})
}

func TestInitTunnel_InvalidBackoffMultiplier(t *testing.T) {
	mult := 0.5
	tunnel := &config.Tunnel{
		Name:              "bad-mult",
		URL:               "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
		CheckURL:          "https://example.com",
		CheckInterval:     "30s",
		CheckTimeout:      "10s",
		BackoffMultiplier: &mult,
	}

	_, err := InitTunnel(tunnel, 1080)
	if err == nil {
		t.Fatal("expected error for backoff_multiplier < 1.0")
	}
	if !strings.Contains(err.Error(), "backoff_multiplier must be >= 1.0") {
		t.Errorf("expected backoff_multiplier error, got: %v", err)
	}
}

func TestInitTunnel_InvalidMaxBackoff(t *testing.T) {
	tunnel := &config.Tunnel{
		Name:          "bad-backoff",
		URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
		CheckURL:      "https://example.com",
		CheckInterval: "30s",
		CheckTimeout:  "10s",
		MaxBackoff:    "not-a-duration",
	}

	_, err := InitTunnel(tunnel, 1080)
	if err == nil {
		t.Fatal("expected error for invalid max_backoff")
	}
	if !strings.Contains(err.Error(), "invalid max_backoff") {
		t.Errorf("expected max_backoff error, got: %v", err)
	}
}

func TestInitTunnel_XrayConfigFile_AutoName(t *testing.T) {
	tmpDir := t.TempDir()
	xrayConfigPath := filepath.Join(tmpDir, "xray.json")

	xrayJSON := `{
		"outbounds": [{
			"protocol": "vless",
			"settings": {"vnext": [{"address": "auto.example.com", "port": 443, "users": [{"id": "uuid", "encryption": "none"}]}]},
			"streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "auto.example.com"}}
		}]
	}`
	os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644)

	tunnel := &config.Tunnel{
		XrayConfigFile: xrayConfigPath,
		CheckURL:       "https://example.com",
		CheckInterval:  "30s",
		CheckTimeout:   "10s",
	}

	ti, err := InitTunnel(tunnel, 11090)
	if err != nil {
		t.Fatalf("InitTunnel() error = %v", err)
	}
	defer ti.XrayInstance.Close()

	if ti.Name != "auto.example.com:443" {
		t.Errorf("Name = %v, want auto.example.com:443", ti.Name)
	}
}

func TestInitTunnel_XrayConfigFile_FallbackName(t *testing.T) {
	tmpDir := t.TempDir()
	xrayConfigPath := filepath.Join(tmpDir, "xray.json")

	xrayJSON := `{"outbounds": [{"protocol": "freedom"}]}`
	os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644)

	tunnel := &config.Tunnel{
		XrayConfigFile: xrayConfigPath,
		CheckURL:       "https://example.com",
		CheckInterval:  "30s",
		CheckTimeout:   "10s",
	}

	ti, err := InitTunnel(tunnel, 11091)
	if err != nil {
		t.Fatalf("InitTunnel() error = %v", err)
	}
	defer ti.XrayInstance.Close()

	if ti.Name != "tunnel-port-11091" {
		t.Errorf("Name = %v, want tunnel-port-11091", ti.Name)
	}
}

func TestBackoffDuration(t *testing.T) {
	tests := []struct {
		name       string
		base       time.Duration
		multiplier float64
		maxBackoff time.Duration
		failures   int
		want       time.Duration
	}{
		{"single failure doubles interval", 30 * time.Second, 2.0, 5 * time.Minute, 1, 1 * time.Minute},
		{"two failures quadruples interval", 30 * time.Second, 2.0, 5 * time.Minute, 2, 2 * time.Minute},
		{"three failures", 30 * time.Second, 2.0, 5 * time.Minute, 3, 4 * time.Minute},
		{"four failures capped at max_backoff", 30 * time.Second, 2.0, 5 * time.Minute, 4, 5 * time.Minute},
		{"many failures still capped", 30 * time.Second, 2.0, 5 * time.Minute, 20, 5 * time.Minute},
		{"multiplier 1.5", 10 * time.Second, 1.5, 5 * time.Minute, 1, 15 * time.Second},
		{"zero failures returns base", 30 * time.Second, 2.0, 5 * time.Minute, 0, 30 * time.Second},
		{"max_backoff smaller than base", 30 * time.Second, 2.0, 10 * time.Second, 1, 10 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BackoffDuration(tt.base, tt.multiplier, tt.maxBackoff, tt.failures)
			if got != tt.want {
				t.Errorf("BackoffDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunProbing(t *testing.T) {
	t.Run("successful probing lifecycle", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")

		cfg := `defaults:
  check_url: "https://example.com"
  check_interval: "30s"
  check_timeout: "5s"
tunnels:
  - name: "test-tunnel"
    url: "vless://test-uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    check_url: "http://example.com"`

		if err := os.WriteFile(configFile, []byte(cfg), 0644); err != nil {
			t.Fatalf("failed to create config: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)
		go func() {
			done <- RunProbing(ctx, configFile, mockChecker{}, NewPrometheusMetrics())
		}()

		time.Sleep(3 * time.Second)
		cancel()

		err := <-done
		if err != nil {
			t.Errorf("RunProbing() error = %v", err)
		}
	})

	t.Run("config file not found", func(t *testing.T) {
		ctx := context.Background()
		err := RunProbing(ctx, "/nonexistent/config.yaml", mockChecker{}, NewPrometheusMetrics())
		if err == nil {
			t.Error("expected error for nonexistent config")
		}
	})
}

func TestConcurrentTunnelManagerReload(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(configFile, []byte(`tunnels:
  - name: "t"
    url: "vless://bad-no-port"`), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{}
	tm.NextSocksPort = 1080

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tm.reloadConfig(configFile)
		}()
	}
	wg.Wait()
}

// Helper functions for tests

func metricExistsWithLabels(t *testing.T, metricName string, labels prometheus.Labels) bool {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}

		for _, metric := range mf.GetMetric() {
			if metricLabelsMatch(metric, labels) {
				return true
			}
		}
	}

	return false
}

func metricLabelsMatch(metric *dto.Metric, labels prometheus.Labels) bool {
	if len(metric.GetLabel()) != len(labels) {
		return false
	}

	for _, lp := range metric.GetLabel() {
		val, ok := labels[lp.GetName()]
		if !ok || val != lp.GetValue() {
			return false
		}
	}

	return true
}

func getCounterValue(t *testing.T, name string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			for _, m := range mf.GetMetric() {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func getGaugeValue(t *testing.T, name string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			for _, m := range mf.GetMetric() {
				return m.GetGauge().GetValue()
			}
		}
	}
	return 0
}

func TestExporterInternalMetrics_ReloadCounters(t *testing.T) {
	initialReload := getCounterValue(t, "xray_exporter_config_reload_total")
	initialErrors := getCounterValue(t, "xray_exporter_config_reload_errors_total")

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	invalidConfig := "tunnels:\n  - name: \"bad\"\n    url: \"vless://bad-url-no-port\"\n    check_interval: \"30s\"\n    check_timeout: \"10s\""
	os.WriteFile(configFile, []byte(invalidConfig), 0644)

	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{}
	tm.NextSocksPort = metrics.DefaultSocksPort

	err := tm.reloadConfig(configFile)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}

	afterReload := getCounterValue(t, "xray_exporter_config_reload_total")
	afterErrors := getCounterValue(t, "xray_exporter_config_reload_errors_total")

	if afterReload <= initialReload {
		t.Errorf("config_reload_total should have incremented: before=%v after=%v", initialReload, afterReload)
	}
	if afterErrors <= initialErrors {
		t.Errorf("config_reload_errors_total should have incremented: before=%v after=%v", initialErrors, afterErrors)
	}
}

func TestExporterInternalMetrics_TunnelsConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	xrayConfigPath := filepath.Join(tmpDir, "xray.json")
	os.WriteFile(xrayConfigPath, []byte(`{"outbounds":[{"protocol":"freedom"}]}`), 0644)

	cfg := fmt.Sprintf("tunnels:\n  - name: \"test-xray\"\n    xray_config_file: %q\n    check_url: \"https://example.com\"\n    check_interval: \"30s\"\n    check_timeout: \"10s\"", xrayConfigPath)
	os.WriteFile(configFile, []byte(cfg), 0644)

	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{}
	tm.NextSocksPort = metrics.DefaultSocksPort

	err := tm.reloadConfig(configFile)
	if err != nil {
		t.Fatalf("reloadConfig() error = %v", err)
	}

	tm.mu.RLock()
	instances := tm.instances
	tm.mu.RUnlock()
	defer StopTunnels(instances)

	val := getGaugeValue(t, "xray_exporter_tunnels_configured")
	if val != 1 {
		t.Errorf("tunnels_configured = %v, want 1", val)
	}
}

// Benchmarks

func BenchmarkMetricsUpdate(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		labels := prometheus.Labels{
			"name":     fmt.Sprintf("bench-tunnel-%d", i%50),
			"server":   fmt.Sprintf("server-%d.example.com:443", i%50),
			"security": "tls",
			"sni":      "example.com",
		}
		metrics.TunnelUp.With(labels).Set(1)
		metrics.TunnelLatency.With(labels).Set(0.123)
		metrics.TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
		metrics.TunnelHTTPStatus.With(labels).Set(200)
		resultLabels := prometheus.Labels{
			"name": labels["name"], "server": labels["server"],
			"security": labels["security"], "sni": labels["sni"], "result": "success",
		}
		metrics.TunnelCheckTotal.With(resultLabels).Inc()
	}
}

func BenchmarkLoadConfig(b *testing.B) {
	b.ReportAllocs()

	yamlContent := `defaults:
  check_url: "https://example.com"
  check_interval: "1m"
  check_timeout: "10s"
tunnels:
  - name: "bench-tunnel-1"
    url: "vless://uuid@example.com:443?type=tcp&security=reality&pbk=key&sni=test.com&fp=chrome"
  - name: "bench-tunnel-2"
    url: "vless://uuid2@example2.com:8443?type=ws&security=tls&sni=test2.com&fp=firefox&host=test2.com&path=%2Fws"
  - name: "bench-tunnel-3"
    url: "vless://uuid3@grpc.example.com:443/?type=grpc&serviceName=grpc-service&security=reality&pbk=key2&fp=chrome&sni=grpc.example.com&sid=ab12cd34"
`

	tmpDir := b.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte(yamlContent), 0644); err != nil {
		b.Fatalf("failed to write temp config: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := config.LoadConfig(configFile)
		if err != nil {
			b.Fatal(err)
		}
	}
}
