package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func newTestManager(t *testing.T) (*TunnelManager, *metrics.Metrics) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	noopChecker := func(ctx context.Context, ti *TunnelInstance, m *metrics.Metrics, logger *slog.Logger) {
		<-ctx.Done()
	}
	tm := NewManager(m, logger, noopChecker)
	return tm, m
}

func TestInitialize_EmptyConfig(t *testing.T) {
	tm, _ := newTestManager(t)

	cfg := &config.Config{
		Tunnels:       []config.Tunnel{},
		SocksBasePort: 1080,
	}

	err := tm.Initialize(cfg)
	if err == nil {
		t.Error("expected error for empty tunnels")
	}
}

func TestInitialize_InvalidTunnelURL(t *testing.T) {
	tm, _ := newTestManager(t)

	cfg := &config.Config{
		Tunnels: []config.Tunnel{
			{
				Name:          "invalid",
				URL:           "invalid-url",
				CheckURL:      "https://example.com",
				CheckInterval: "30s",
				CheckTimeout:  "10s",
			},
		},
		SocksBasePort: 1080,
	}

	err := tm.Initialize(cfg)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestStopTunnels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	ti := &TunnelInstance{
		Name:       "test-tunnel",
		CancelFunc: cancel,
		VLESSConfig: &VLESSConfig{
			Address:  "test.com",
			Port:     443,
			Security: "tls",
		},
		SocksPort: 1080,
	}

	instances := []*TunnelInstance{ti}
	stopTunnels(instances)

	select {
	case <-ctx.Done():
	case <-time.After(1 * time.Second):
		t.Error("context was not cancelled")
	}
}

func TestStopAll(t *testing.T) {
	tm, _ := newTestManager(t)

	ctx, cancel := context.WithCancel(context.Background())

	ti := &TunnelInstance{
		Name:       "test-tunnel",
		CancelFunc: cancel,
		VLESSConfig: &VLESSConfig{
			Address:  "test.com",
			Port:     443,
			Security: "tls",
		},
		SocksPort: 1080,
	}

	tm.mu.Lock()
	tm.instances = []*TunnelInstance{ti}
	tm.mu.Unlock()

	tm.StopAll()

	select {
	case <-ctx.Done():
	case <-time.After(1 * time.Second):
		t.Error("context was not cancelled by StopAll")
	}

	tm.mu.RLock()
	remaining := tm.instances
	tm.mu.RUnlock()
	if remaining != nil {
		t.Error("expected instances to be nil after StopAll")
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
		var port int
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
		var port int
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

func TestReloadConfig(t *testing.T) {
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

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.Tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(cfg.Tunnels))
	}

	newConfigYAML := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
  - name: "tunnel2"
    url: "vless://uuid2@example2.com:443?type=tcp&security=tls&sni=test2.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(newConfigYAML), 0644); err != nil {
		t.Fatalf("failed to update config: %v", err)
	}

	cfg2, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg2.Tunnels) != 2 {
		t.Errorf("expected 2 tunnels, got %d", len(cfg2.Tunnels))
	}
}

func TestHealthHandler(t *testing.T) {
	t.Run("no tunnels configured", func(t *testing.T) {
		tm, _ := newTestManager(t)

		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		tm.HealthHandler(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("expected status 503, got %v", resp.StatusCode)
		}
	})

	t.Run("all tunnels down", func(t *testing.T) {
		tm, _ := newTestManager(t)

		ti := &TunnelInstance{
			Name: "test",
			VLESSConfig: &VLESSConfig{
				Address:  "test.com",
				Port:     443,
				Security: "tls",
			},
		}
		// Up is false by default (atomic.Bool zero value)

		tm.mu.Lock()
		tm.instances = []*TunnelInstance{ti}
		tm.mu.Unlock()

		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		tm.HealthHandler(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("expected status 503, got %v", resp.StatusCode)
		}
	})

	t.Run("at least one tunnel up", func(t *testing.T) {
		tm, _ := newTestManager(t)

		ti1 := &TunnelInstance{
			Name: "down",
			VLESSConfig: &VLESSConfig{
				Address:  "test.com",
				Port:     443,
				Security: "tls",
			},
		}
		ti2 := &TunnelInstance{
			Name: "up",
			VLESSConfig: &VLESSConfig{
				Address:  "test2.com",
				Port:     443,
				Security: "tls",
			},
		}
		ti2.Up.Store(true)

		tm.mu.Lock()
		tm.instances = []*TunnelInstance{ti1, ti2}
		tm.mu.Unlock()

		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		tm.HealthHandler(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %v", resp.StatusCode)
		}

		body := make([]byte, 2)
		resp.Body.Read(body)
		if string(body) != "OK" {
			t.Errorf("expected body 'OK', got '%s'", string(body))
		}
	})
}
