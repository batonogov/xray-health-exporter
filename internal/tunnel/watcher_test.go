package tunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
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
		t.Fatal("WatchSubscriptions should exit when canceled without subscriptions")
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
		t.Fatal("WatchSubscriptions should exit when canceled with nil config")
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

func TestSubscriptionScheduleUsesPerSourceIntervals(t *testing.T) {
	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())
	now := time.Now()
	slow := config.Subscription{URL: "https://slow.example", UpdateInterval: "24h"}
	fast := config.Subscription{URL: "https://fast.example", UpdateInterval: "2h"}
	tm.config = &config.Config{Subscriptions: []config.Subscription{slow, fast}}
	tm.sources[subscriptionKey(slow)] = subscriptionState{lastAttempt: now}
	tm.sources[subscriptionKey(fast)] = subscriptionState{lastAttempt: now}
	if got := tm.nextSubscriptionDelay(now); got != 2*time.Hour {
		t.Fatalf("delay = %v, want 2h", got)
	}
	tm.config.Subscriptions[1].UpdateInterval = "30m"
	if got := tm.nextSubscriptionDelay(now); got != 30*time.Minute {
		t.Fatalf("changed delay = %v, want 30m", got)
	}
}

func TestSubscriptionWatcherStartsRefreshingFirstHotAddedSource(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"remarks":"added","outbounds":[{"protocol":"freedom"}]}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	native := filepath.Join(dir, "xray.json")
	os.WriteFile(native, []byte(`{"outbounds":[{"protocol":"freedom"}]}`), 0600)
	path := filepath.Join(dir, "config.yaml")
	initial := fmt.Sprintf("tunnels:\n  - name: static\n    xray_config_file: %q\n", native)
	os.WriteFile(path, []byte(initial), 0600)
	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tm.reloadConfigContext(ctx, path, false); err != nil {
		t.Fatal(err)
	}
	defer func() { StopTunnels(tm.instances) }()
	done := make(chan struct{})
	go func() { defer close(done); WatchSubscriptions(ctx, tm, path) }()
	defer func() { cancel(); <-done }()
	os.WriteFile(path, []byte(initial+fmt.Sprintf("subscriptions:\n  - url: %q\n    update_interval: 20ms\n", server.URL)), 0600)
	if err := tm.reloadConfigContext(ctx, path, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for requests.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("hot-added subscription did not refresh")
		case <-ticker.C:
		}
	}
}

func TestSubscriptionWatcherRetriesFailedFirstHotAddedSource(t *testing.T) {
	var healthy atomic.Bool
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !healthy.Load() {
			http.Error(w, "temporary outage", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"remarks":"recovered","outbounds":[{"protocol":"freedom"}]}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	native := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(native, []byte(`{"outbounds":[{"protocol":"freedom"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf("tunnels:\n  - name: static\n    xray_config_file: %q\n", native)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	tm := NewTunnelManager(watchMockChecker{}, NewPrometheusMetrics())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tm.reloadConfigContext(ctx, path, false); err != nil {
		t.Fatal(err)
	}
	defer func() { StopTunnels(tm.instances) }()
	original := tm.instances[0]
	done := make(chan struct{})
	go func() { defer close(done); WatchSubscriptions(ctx, tm, path) }()
	defer func() { cancel(); <-done }()
	body += fmt.Sprintf("subscriptions:\n  - url: %q\n    update_interval: 100ms\n", server.URL)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tm.reloadConfigContext(ctx, path, false); err == nil {
		t.Fatal("expected initial fetch failure")
	}
	// A scheduler tick before this source's own deadline must not refetch it.
	if err := tm.reloadConfigContext(ctx, path, true); err == nil {
		t.Fatal("uncached source was silently accepted")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("source fetched before due: %d requests", got)
	}
	healthy.Store(true)
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		tm.mu.RLock()
		count := len(tm.instances)
		retained := count > 0 && tm.instances[0] == original
		tm.mu.RUnlock()
		if !retained {
			t.Fatal("retry replaced original static tunnel")
		}
		if count == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("first hot-added source did not recover without another file edit")
		case <-ticker.C:
		}
	}
	if requests.Load() < 2 {
		t.Fatal("source was not retried")
	}
}
