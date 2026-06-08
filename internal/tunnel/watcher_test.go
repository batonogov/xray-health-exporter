package tunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
)

type watchMockChecker struct{}

func (watchMockChecker) Check(ti *TunnelInstance) CheckResult {
	return CheckResult{Up: true, Latency: 10 * time.Millisecond, HTTPStatus: 200}
}

func TestWatchConfigFile(t *testing.T) {
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

	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile); err != nil {
			watcherErr <- err
		}
	}()

	time.Sleep(100 * time.Millisecond)

	updatedConfig := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1-modified"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("failed to update config: %v", err)
	}

	select {
	case <-done:
	case err := <-watcherErr:
		t.Fatalf("watcher error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not exit after timeout")
	}
}

func TestWatchConfigFile_FileRemoval(t *testing.T) {
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

	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile); err != nil {
			watcherErr <- err
		}
	}()

	time.Sleep(200 * time.Millisecond)

	if err := os.Remove(configFile); err != nil {
		t.Fatalf("failed to remove config: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if err := os.WriteFile(configFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to recreate config: %v", err)
	}

	select {
	case <-done:
	case err := <-watcherErr:
		t.Fatalf("watcher error: %v", err)
	case <-time.After(4 * time.Second):
		t.Fatal("watcher did not exit after timeout")
	}
}

func TestWatchConfigFile_FileRename(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	renamedFile := filepath.Join(tmpDir, "config.yaml.old")

	initialConfig := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile); err != nil {
			watcherErr <- err
		}
	}()

	time.Sleep(200 * time.Millisecond)

	if err := os.Rename(configFile, renamedFile); err != nil {
		t.Fatalf("failed to rename config: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if err := os.WriteFile(configFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to recreate config: %v", err)
	}

	select {
	case <-done:
	case err := <-watcherErr:
		t.Fatalf("watcher error: %v", err)
	case <-time.After(4 * time.Second):
		t.Fatal("watcher did not exit after timeout")
	}
}

func TestWatchConfigFile_ContextCancel(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	cfg := `tunnels:
  - name: "t1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile); err != nil {
			t.Errorf("WatchConfigFile error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WatchConfigFile did not exit on context cancel")
	}
}

func TestWatchConfigFile_CreateEvent(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile); err != nil {
			watcherErr <- err
		}
	}()

	time.Sleep(200 * time.Millisecond)

	cfg := `tunnels:
  - name: "t1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`
	if err := os.WriteFile(configFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	select {
	case <-done:
	case err := <-watcherErr:
		t.Fatalf("watcher error: %v", err)
	case <-time.After(4 * time.Second):
		t.Fatal("watcher did not exit after timeout")
	}
}

func TestWatchConfigFile_ChmodEvent(t *testing.T) {
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

	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile); err != nil {
			watcherErr <- err
		}
	}()

	time.Sleep(200 * time.Millisecond)

	if err := os.Chmod(configFile, 0600); err != nil {
		t.Fatalf("failed to chmod config: %v", err)
	}

	select {
	case <-done:
	case err := <-watcherErr:
		t.Fatalf("watcher error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not exit after timeout")
	}
}

func TestWatchSubscriptions_NoSubscriptions(t *testing.T) {
	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())
	tm.config = &config.Config{}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		WatchSubscriptions(ctx, tm, "/nonexistent")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("WatchSubscriptions should return immediately when no subscriptions")
	}
}

func TestWatchSubscriptions_NilConfig(t *testing.T) {
	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		WatchSubscriptions(ctx, tm, "/nonexistent")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("WatchSubscriptions should return immediately when config is nil")
	}
}

func TestWatchSubscriptions_WithTicker(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	cfg := `tunnels:
  - name: "manual"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    check_url: "https://example.com"
    check_interval: "30s"
    check_timeout: "10s"
subscriptions:
  - url: "http://127.0.0.1:1/unreachable"
    update_interval: "500ms"`

	if err := os.WriteFile(configFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	loadedCfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("config.LoadConfig() error = %v", err)
	}

	existingInstance := &TunnelInstance{
		Name: "manual",
		MetricLabels: MetricLabels{
			Server:   "example.com:443",
			Security: "tls",
			SNI:      "test.com",
		},
		SocksPort:     1080,
		CheckURL:      "https://example.com",
		CheckTimeout:  10 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{existingInstance}
	tm.NextSocksPort = 1081
	tm.config = loadedCfg

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		WatchSubscriptions(ctx, tm, configFile)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("WatchSubscriptions did not exit")
	}
}

func TestWatchSubscriptions_ReloadCallback(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := "vless://uuid@host.com:443?type=tcp&security=tls&sni=host.com&fp=chrome#Sub1"
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(content))))
	}))
	defer ts.Close()

	cfg := fmt.Sprintf(`tunnels:
  - name: "manual"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    check_url: "https://example.com"
    check_interval: "30s"
    check_timeout: "10s"
subscriptions:
  - url: %q
    update_interval: "500ms"`, ts.URL)

	if err := os.WriteFile(configFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	loadedCfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("config.LoadConfig() error = %v", err)
	}

	existingInstance := &TunnelInstance{
		Name: "manual",
		MetricLabels: MetricLabels{
			Server:   "example.com:443",
			Security: "tls",
			SNI:      "test.com",
		},
		SocksPort:     1080,
		CheckURL:      "https://example.com",
		CheckTimeout:  10 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())
	tm.instances = []*TunnelInstance{existingInstance}
	tm.NextSocksPort = 1082
	tm.config = loadedCfg

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		WatchSubscriptions(ctx, tm, configFile)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("WatchSubscriptions did not exit")
	}
}
