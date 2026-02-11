package tunnel

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	noopChecker := func(ctx context.Context, ti *TunnelInstance, m *metrics.Metrics, logger *slog.Logger) {
		<-ctx.Done()
	}
	tm := NewManager(m, logger, noopChecker)

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile, logger); err != nil {
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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	noopChecker := func(ctx context.Context, ti *TunnelInstance, m *metrics.Metrics, logger *slog.Logger) {
		<-ctx.Done()
	}
	tm := NewManager(m, logger, noopChecker)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile, logger); err != nil {
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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	noopChecker := func(ctx context.Context, ti *TunnelInstance, m *metrics.Metrics, logger *slog.Logger) {
		<-ctx.Done()
	}
	tm := NewManager(m, logger, noopChecker)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile, logger); err != nil {
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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	noopChecker := func(ctx context.Context, ti *TunnelInstance, m *metrics.Metrics, logger *slog.Logger) {
		<-ctx.Done()
	}
	tm := NewManager(m, logger, noopChecker)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	watcherErr := make(chan error, 1)

	go func() {
		defer close(done)
		if err := WatchConfigFile(ctx, tm, configFile, logger); err != nil {
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
