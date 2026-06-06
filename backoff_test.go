package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackoffDuration(t *testing.T) {
	tests := []struct {
		name       string
		base       time.Duration
		multiplier float64
		maxBackoff time.Duration
		failures   int
		want       time.Duration
	}{
		{
			name:       "single failure doubles interval",
			base:       30 * time.Second,
			multiplier: 2.0,
			maxBackoff: 5 * time.Minute,
			failures:   1,
			want:       1 * time.Minute,
		},
		{
			name:       "two failures quadruples interval",
			base:       30 * time.Second,
			multiplier: 2.0,
			maxBackoff: 5 * time.Minute,
			failures:   2,
			want:       2 * time.Minute,
		},
		{
			name:       "three failures",
			base:       30 * time.Second,
			multiplier: 2.0,
			maxBackoff: 5 * time.Minute,
			failures:   3,
			want:       4 * time.Minute,
		},
		{
			name:       "four failures capped at max_backoff",
			base:       30 * time.Second,
			multiplier: 2.0,
			maxBackoff: 5 * time.Minute,
			failures:   4,
			want:       5 * time.Minute,
		},
		{
			name:       "many failures still capped",
			base:       30 * time.Second,
			multiplier: 2.0,
			maxBackoff: 5 * time.Minute,
			failures:   20,
			want:       5 * time.Minute,
		},
		{
			name:       "multiplier 1.5",
			base:       10 * time.Second,
			multiplier: 1.5,
			maxBackoff: 5 * time.Minute,
			failures:   1,
			want:       15 * time.Second,
		},
		{
			name:       "zero failures returns base",
			base:       30 * time.Second,
			multiplier: 2.0,
			maxBackoff: 5 * time.Minute,
			failures:   0,
			want:       30 * time.Second,
		},
		{
			name:       "max_backoff smaller than base",
			base:       30 * time.Second,
			multiplier: 2.0,
			maxBackoff: 10 * time.Second,
			failures:   1,
			want:       10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backoffDuration(tt.base, tt.multiplier, tt.maxBackoff, tt.failures)
			if got != tt.want {
				t.Errorf("backoffDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunTunnelChecker_BackoffOnFailures(t *testing.T) {
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksListener.Addr().String())
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &TunnelInstance{
		Name: "backoff-test",
		MetricLabels: MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:         socksPort,
		CheckURL:          "http://test.example.com",
		CheckTimeout:      1 * time.Second,
		CheckInterval:     200 * time.Millisecond,
		MaxBackoff:        2 * time.Second,
		BackoffMultiplier: 2.0,
	}

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		runTunnelChecker(ctx, ti, defaultChecker{}, prometheusMetrics{})
	}()

	time.Sleep(3500 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runTunnelChecker did not stop after context cancellation")
	}
}

func TestRunTunnelChecker_BackoffResetsOnSuccess(t *testing.T) {
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	var checkCount int32

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				atomic.AddInt32(&checkCount, 1)

				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksListener.Addr().String())
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &TunnelInstance{
		Name: "backoff-reset-test",
		MetricLabels: MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:         socksPort,
		CheckURL:          "http://test.example.com",
		CheckTimeout:      1 * time.Second,
		CheckInterval:     200 * time.Millisecond,
		MaxBackoff:        10 * time.Second,
		BackoffMultiplier: 2.0,
	}

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		runTunnelChecker(ctx, ti, defaultChecker{}, prometheusMetrics{})
	}()

	time.Sleep(1200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runTunnelChecker did not stop after context cancellation")
	}

	count := atomic.LoadInt32(&checkCount)
	if count < 4 {
		t.Errorf("expected at least 4 checks with fast interval, got %d", count)
	}
}

func TestApplyTunnelDefaults_BackoffFields(t *testing.T) {
	t.Run("backoff defaults applied from empty", func(t *testing.T) {
		tunnel := &Tunnel{}
		applyTunnelDefaults(tunnel, Defaults{})

		if tunnel.MaxBackoff != defaultMaxBackoff.String() {
			t.Errorf("MaxBackoff = %v, want %v", tunnel.MaxBackoff, defaultMaxBackoff.String())
		}
		if tunnel.BackoffMultiplier == nil || *tunnel.BackoffMultiplier != defaultBackoffMult {
			t.Errorf("BackoffMultiplier = %v, want %v", tunnel.BackoffMultiplier, defaultBackoffMult)
		}
	})

	t.Run("backoff defaults from config defaults", func(t *testing.T) {
		customMult := 3.0
		tunnel := &Tunnel{}
		applyTunnelDefaults(tunnel, Defaults{
			MaxBackoff:        "10m",
			BackoffMultiplier: &customMult,
		})

		if tunnel.MaxBackoff != "10m" {
			t.Errorf("MaxBackoff = %v, want 10m", tunnel.MaxBackoff)
		}
		if tunnel.BackoffMultiplier == nil || *tunnel.BackoffMultiplier != 3.0 {
			t.Errorf("BackoffMultiplier = %v, want 3.0", tunnel.BackoffMultiplier)
		}
	})

	t.Run("tunnel backoff values not overwritten", func(t *testing.T) {
		customMult := 1.5
		tunnel := &Tunnel{
			MaxBackoff:        "2m",
			BackoffMultiplier: &customMult,
		}
		defaultMult := 2.0
		applyTunnelDefaults(tunnel, Defaults{
			MaxBackoff:        "10m",
			BackoffMultiplier: &defaultMult,
		})

		if tunnel.MaxBackoff != "2m" {
			t.Errorf("MaxBackoff = %v, want 2m", tunnel.MaxBackoff)
		}
		if tunnel.BackoffMultiplier == nil || *tunnel.BackoffMultiplier != 1.5 {
			t.Errorf("BackoffMultiplier = %v, want 1.5", tunnel.BackoffMultiplier)
		}
	})
}

func TestLoadConfig_BackoffFields(t *testing.T) {
	t.Run("defaults with backoff config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `defaults:
  check_url: "https://example.com"
  max_backoff: "3m"
  backoff_multiplier: 1.5
tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := loadConfig(configFile)
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if config.Defaults.MaxBackoff != "3m" {
			t.Errorf("MaxBackoff = %v, want 3m", config.Defaults.MaxBackoff)
		}
		if config.Defaults.BackoffMultiplier == nil || *config.Defaults.BackoffMultiplier != 1.5 {
			t.Errorf("BackoffMultiplier = %v, want 1.5", config.Defaults.BackoffMultiplier)
		}

		if config.Tunnels[0].MaxBackoff != "3m" {
			t.Errorf("tunnel MaxBackoff = %v, want 3m", config.Tunnels[0].MaxBackoff)
		}
		if config.Tunnels[0].BackoffMultiplier == nil || *config.Tunnels[0].BackoffMultiplier != 1.5 {
			t.Errorf("tunnel BackoffMultiplier = %v, want 1.5", config.Tunnels[0].BackoffMultiplier)
		}
	})

	t.Run("tunnel overrides defaults backoff", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `defaults:
  check_url: "https://example.com"
  max_backoff: "3m"
tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    max_backoff: "1m"
    backoff_multiplier: 2.5`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := loadConfig(configFile)
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if config.Tunnels[0].MaxBackoff != "1m" {
			t.Errorf("tunnel MaxBackoff = %v, want 1m", config.Tunnels[0].MaxBackoff)
		}
		if config.Tunnels[0].BackoffMultiplier == nil || *config.Tunnels[0].BackoffMultiplier != 2.5 {
			t.Errorf("tunnel BackoffMultiplier = %v, want 2.5", config.Tunnels[0].BackoffMultiplier)
		}
	})

	t.Run("default backoff when not specified", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := loadConfig(configFile)
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if config.Tunnels[0].MaxBackoff != defaultMaxBackoff.String() {
			t.Errorf("tunnel MaxBackoff = %v, want %v", config.Tunnels[0].MaxBackoff, defaultMaxBackoff.String())
		}
		if config.Tunnels[0].BackoffMultiplier == nil || *config.Tunnels[0].BackoffMultiplier != defaultBackoffMult {
			t.Errorf("tunnel BackoffMultiplier = %v, want %v", config.Tunnels[0].BackoffMultiplier, defaultBackoffMult)
		}
	})
}

func TestInitTunnel_InvalidBackoffMultiplier(t *testing.T) {
	mult := 0.5
	tunnel := &Tunnel{
		Name:              "bad-mult",
		URL:               "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
		CheckURL:          "https://example.com",
		CheckInterval:     "30s",
		CheckTimeout:      "10s",
		BackoffMultiplier: &mult,
	}

	_, err := initTunnel(tunnel, 1080)
	if err == nil {
		t.Fatal("expected error for backoff_multiplier < 1.0")
	}
	if !strings.Contains(err.Error(), "backoff_multiplier must be >= 1.0") {
		t.Errorf("expected backoff_multiplier error, got: %v", err)
	}
}

func TestInitTunnel_InvalidMaxBackoff(t *testing.T) {
	tunnel := &Tunnel{
		Name:          "bad-backoff",
		URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
		CheckURL:      "https://example.com",
		CheckInterval: "30s",
		CheckTimeout:  "10s",
		MaxBackoff:    "not-a-duration",
	}

	_, err := initTunnel(tunnel, 1080)
	if err == nil {
		t.Fatal("expected error for invalid max_backoff")
	}
	if !strings.Contains(err.Error(), "invalid max_backoff") {
		t.Errorf("expected max_backoff error, got: %v", err)
	}
}
