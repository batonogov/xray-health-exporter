package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestExporterInternalMetrics_BuildInfo(t *testing.T) {
	exporterBuildInfo.WithLabelValues("test-version", "go1.26", "abc123").Set(1)

	if !metricExistsWithLabels(t, "xray_exporter_build_info", prometheus.Labels{
		"version":    "test-version",
		"go_version": "go1.26",
		"commit":     "abc123",
	}) {
		t.Error("expected build_info metric with correct labels")
	}
}

func TestExporterInternalMetrics_Uptime(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "xray_exporter_uptime_seconds" {
			found = true
			for _, m := range mf.GetMetric() {
				val := m.GetGauge().GetValue()
				if val < 0 {
					t.Errorf("uptime should be non-negative, got %v", val)
				}
			}
		}
	}
	if !found {
		t.Error("expected xray_exporter_uptime_seconds metric to be registered")
	}
}

func TestExporterInternalMetrics_ReloadCounters(t *testing.T) {
	initialReload := getCounterValue(t, "xray_exporter_config_reload_total")
	initialErrors := getCounterValue(t, "xray_exporter_config_reload_errors_total")

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	invalidConfig := "tunnels:\n  - name: \"bad\"\n    url: \"vless://bad-url-no-port\"\n    check_interval: \"30s\"\n    check_timeout: \"10s\""
	os.WriteFile(configFile, []byte(invalidConfig), 0644)

	tm := NewTunnelManager(nil, nil)
	tm.instances = []*TunnelInstance{}
	tm.nextSocksPort = defaultSocksPort

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

	config := fmt.Sprintf("tunnels:\n  - name: \"test-xray\"\n    xray_config_file: %q\n    check_url: \"https://example.com\"\n    check_interval: \"30s\"\n    check_timeout: \"10s\"", xrayConfigPath)
	os.WriteFile(configFile, []byte(config), 0644)

	tm := NewTunnelManager(nil, nil)
	tm.instances = []*TunnelInstance{}
	tm.nextSocksPort = defaultSocksPort

	err := tm.reloadConfig(configFile)
	if err != nil {
		t.Fatalf("reloadConfig() error = %v", err)
	}

	tm.mu.RLock()
	instances := tm.instances
	tm.mu.RUnlock()
	defer stopTunnels(instances)

	val := getGaugeValue(t, "xray_exporter_tunnels_configured")
	if val != 1 {
		t.Errorf("tunnels_configured = %v, want 1", val)
	}
}

func TestExporterInternalMetrics_InMetricsOutput(t *testing.T) {
	exporterBuildInfo.WithLabelValues("1.0.0", "go1.26", "").Set(1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(w, req)

	body := make([]byte, 20000)
	n, _ := w.Result().Body.Read(body)
	bodyStr := string(body[:n])

	expectedMetrics := []string{
		"xray_exporter_config_reload_total",
		"xray_exporter_config_reload_errors_total",
		"xray_exporter_tunnels_configured",
		"xray_exporter_uptime_seconds",
		"xray_exporter_build_info",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(bodyStr, metric) {
			t.Errorf("metrics output should contain %s", metric)
		}
	}
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
