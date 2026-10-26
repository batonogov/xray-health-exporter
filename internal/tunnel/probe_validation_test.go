package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batonogov/xray-health-exporter/internal/config"
)

func TestInitTunnelRejectsUnsafeDurationsBeforeStartingCore(t *testing.T) {
	for _, field := range []string{"check_interval", "check_timeout", "download_timeout", "max_backoff"} {
		for _, value := range []string{"0s", "-1s"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				tunnel := config.Tunnel{URL: "vless://id@example.com:443"}
				config.ApplyTunnelDefaults(&tunnel, config.Defaults{})
				switch field {
				case "check_interval":
					tunnel.CheckInterval = value
				case "check_timeout":
					tunnel.CheckTimeout = value
				case "download_timeout":
					tunnel.DownloadTimeout = value
				case "max_backoff":
					tunnel.MaxBackoff = value
				}
				instance, err := InitTunnel(&tunnel, 1080)
				if err == nil || instance != nil || !strings.Contains(err.Error(), field) {
					t.Fatalf("unsafe %s started core: %v", field, err)
				}
			})
		}
	}
}

func TestReloadRejectsUnsafeProbeSettingsAndKeepsInstance(t *testing.T) {
	dir := t.TempDir()
	native := filepath.Join(dir, "native.json")
	if err := os.WriteFile(native, []byte(`{"outbounds":[{"protocol":"freedom"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	write := func(interval string) {
		t.Helper()
		body := fmt.Sprintf("tunnels:\n  - name: stable\n    xray_config_file: %q\n    check_interval: %q\n", native, interval)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("1h")
	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	if err := tm.reloadConfig(path); err != nil {
		t.Fatal(err)
	}
	defer func() { StopTunnels(tm.instances) }()
	original := tm.instances[0]
	write("0s")
	if err := tm.reloadConfig(path); err == nil {
		t.Fatal("unsafe reload accepted")
	}
	if len(tm.instances) != 1 || tm.instances[0] != original {
		t.Fatal("rejected reload replaced running instance")
	}
}
