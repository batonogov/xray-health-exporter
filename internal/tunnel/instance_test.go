package tunnel

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestInitInstance_InvalidDurations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	t.Run("invalid check_interval", func(t *testing.T) {
		tunnel := &config.Tunnel{
			Name:          "test",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "https://example.com",
			CheckInterval: "invalid-duration",
			CheckTimeout:  "10s",
		}

		_, err := InitInstance(tunnel, 1080, logger, m)
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

		_, err := InitInstance(tunnel, 1080, logger, m)
		if err == nil {
			t.Error("expected error for invalid check_timeout")
		}
		if !strings.Contains(err.Error(), "invalid check_timeout") {
			t.Errorf("expected error message about check_timeout, got: %v", err)
		}
	})

	t.Run("invalid VLESS URL", func(t *testing.T) {
		tunnel := &config.Tunnel{
			Name:          "test",
			URL:           "invalid-url",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
		}

		_, err := InitInstance(tunnel, 1080, logger, m)
		if err == nil {
			t.Error("expected error for invalid URL")
		}
		if !strings.Contains(err.Error(), "failed to parse VLESS URL") {
			t.Errorf("expected error about VLESS URL, got: %v", err)
		}
	})
}

func TestTunnelInstanceLabelSet(t *testing.T) {
	ti := &TunnelInstance{
		Name: "test-tunnel",
		VLESSConfig: &VLESSConfig{
			Address:  "example.com",
			Port:     443,
			Security: "tls",
			SNI:      "example.com",
		},
	}

	ls := ti.LabelSet()

	if ls.Name != "test-tunnel" {
		t.Errorf("Name = %v, want test-tunnel", ls.Name)
	}
	if ls.Server != "example.com:443" {
		t.Errorf("Server = %v, want example.com:443", ls.Server)
	}
	if ls.Security != "tls" {
		t.Errorf("Security = %v, want tls", ls.Security)
	}
	if ls.SNI != "example.com" {
		t.Errorf("SNI = %v, want example.com", ls.SNI)
	}
}
