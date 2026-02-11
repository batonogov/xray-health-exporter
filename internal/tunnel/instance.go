package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/socks"
	"github.com/xtls/xray-core/core"
)

// TunnelInstance represents a running tunnel with its check configuration.
type TunnelInstance struct {
	Name          string
	VLESSConfig   *VLESSConfig
	XrayInstance  *core.Instance
	SocksPort     int
	CheckURL      string
	CheckInterval time.Duration
	CheckTimeout  time.Duration
	HTTPClient    *http.Client
	CancelFunc    context.CancelFunc
	Up            atomic.Bool
}

// InitInstance creates a new TunnelInstance from configuration.
func InitInstance(tunnel *config.Tunnel, socksPort int, logger *slog.Logger, m *metrics.Metrics) (*TunnelInstance, error) {
	vlessConfig, err := ParseVLESSURL(tunnel.URL)
	if err != nil {
		if m != nil {
			m.TunnelInitErrors.Inc()
		}
		return nil, fmt.Errorf("failed to parse VLESS URL: %w", err)
	}

	checkInterval, err := time.ParseDuration(tunnel.CheckInterval)
	if err != nil {
		if m != nil {
			m.TunnelInitErrors.Inc()
		}
		return nil, fmt.Errorf("invalid check_interval: %w", err)
	}

	checkTimeout, err := time.ParseDuration(tunnel.CheckTimeout)
	if err != nil {
		if m != nil {
			m.TunnelInitErrors.Inc()
		}
		return nil, fmt.Errorf("invalid check_timeout: %w", err)
	}

	xrayConfigJSON, err := CreateXrayConfig(vlessConfig, socksPort)
	if err != nil {
		if m != nil {
			m.TunnelInitErrors.Inc()
		}
		return nil, fmt.Errorf("failed to create Xray config: %w", err)
	}

	logger.Debug("Xray config generated", "tunnel", tunnel.Name, "config", string(xrayConfigJSON))

	xrayInstance, err := StartXray(xrayConfigJSON)
	if err != nil {
		if m != nil {
			m.TunnelInitErrors.Inc()
		}
		return nil, fmt.Errorf("failed to start Xray: %w", err)
	}

	name := tunnel.Name
	if name == "" {
		name = fmt.Sprintf("%s:%d", vlessConfig.Address, vlessConfig.Port)
	}

	socksProxy := fmt.Sprintf("127.0.0.1:%d", socksPort)
	dialer := socks.NewDialer(socksProxy, checkTimeout)

	httpClient := &http.Client{
		Timeout: checkTimeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			},
			DisableKeepAlives: true,
		},
	}

	return &TunnelInstance{
		Name:          name,
		VLESSConfig:   vlessConfig,
		XrayInstance:  xrayInstance,
		SocksPort:     socksPort,
		CheckURL:      tunnel.CheckURL,
		CheckInterval: checkInterval,
		CheckTimeout:  checkTimeout,
		HTTPClient:    httpClient,
	}, nil
}

// LabelSet returns the metrics label set for this tunnel instance.
func (ti *TunnelInstance) LabelSet() metrics.LabelSet {
	return metrics.LabelSet{
		Name:     ti.Name,
		Server:   fmt.Sprintf("%s:%d", ti.VLESSConfig.Address, ti.VLESSConfig.Port),
		Security: ti.VLESSConfig.Security,
		SNI:      ti.VLESSConfig.SNI,
	}
}
