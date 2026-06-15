package tunnel

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeChecker is a test HealthChecker whose result is configurable per tunnel
// name. If a name is not in the map, it defaults to Up=true.
type fakeChecker struct {
	downTunnels map[string]bool
}

func (fc fakeChecker) Check(ti *TunnelInstance) CheckResult {
	if fc.downTunnels[ti.Name] {
		return CheckResult{Up: false, Err: errFakeDown}
	}
	return CheckResult{Up: true, HTTPStatus: 200, Latency: 5 * time.Millisecond}
}

var _ HealthChecker = fakeChecker{}

// errFakeDown is a sentinel error used by fakeChecker for down tunnels.
var errFakeDown = errFake("tunnel is down")

type errFake string

func (e errFake) Error() string { return string(e) }

// writeTestConfig writes a YAML config file and an Xray JSON config to a temp
// dir, returning the config file path. The config has numTunnels tunnels all
// referencing the same xray_config_file.
func writeTestConfig(t *testing.T, numTunnels int) string {
	t.Helper()
	tmpDir := t.TempDir()

	xrayConfigPath := filepath.Join(tmpDir, "xray.json")
	xrayJSON := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"test-uuid","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`
	if err := os.WriteFile(xrayConfigPath, []byte(xrayJSON), 0644); err != nil {
		t.Fatalf("failed to write xray config: %v", err)
	}

	var sb strings.Builder
	sb.WriteString("defaults:\n  check_url: \"https://example.com\"\n  check_interval: \"30s\"\n  check_timeout: \"10s\"\ntunnels:\n")
	for i := 0; i < numTunnels; i++ {
		// Alternate names to make assertions clear.
		sb.WriteString("  - name: tunnel-")
		sb.WriteString(string(rune('a' + i)))
		sb.WriteString("\n    xray_config_file: ")
		sb.WriteString(xrayConfigPath)
		sb.WriteString("\n    socks_port: 0\n")
	}

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(sb.String()), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return configPath
}

func TestRunOnce_AllUp(t *testing.T) {
	configFile := writeTestConfig(t, 2)

	var buf bytes.Buffer
	allUp, err := RunOnce(
		context.Background(),
		configFile,
		fakeChecker{downTunnels: nil},
		NewPrometheusMetrics(),
		&buf,
	)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if !allUp {
		t.Error("expected allUp=true when all tunnels are up")
	}

	output := buf.String()
	if !strings.Contains(output, "xray_tunnel_up") {
		t.Errorf("expected metrics output to contain 'xray_tunnel_up', got:\n%s", output)
	}
}

func TestRunOnce_OneDown(t *testing.T) {
	configFile := writeTestConfig(t, 2)

	var buf bytes.Buffer
	allUp, err := RunOnce(
		context.Background(),
		configFile,
		fakeChecker{downTunnels: map[string]bool{"tunnel-b": true}},
		NewPrometheusMetrics(),
		&buf,
	)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if allUp {
		t.Error("expected allUp=false when one tunnel is down")
	}

	output := buf.String()
	if !strings.Contains(output, "xray_tunnel_up") {
		t.Errorf("expected metrics output to contain 'xray_tunnel_up', got:\n%s", output)
	}
}

func TestRunOnce_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nonexistent.yaml")

	_, err := RunOnce(
		context.Background(),
		configPath,
		fakeChecker{},
		NewPrometheusMetrics(),
		&bytes.Buffer{},
	)
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

func TestRunOnce_NoTunnels(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("defaults:\n  check_url: \"https://example.com\"\n"), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := RunOnce(
		context.Background(),
		configPath,
		fakeChecker{},
		NewPrometheusMetrics(),
		&bytes.Buffer{},
	)
	if err == nil {
		t.Error("expected error for config with no tunnels")
	}
}

func TestEncodeMetrics(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeMetrics(&buf); err != nil {
		t.Fatalf("encodeMetrics() error = %v", err)
	}
	// The default registry always has at least the exporter-level metrics.
	output := buf.String()
	if !strings.Contains(output, "xray_exporter_") {
		t.Errorf("expected output to contain exporter metrics, got:\n%s", output)
	}
}
