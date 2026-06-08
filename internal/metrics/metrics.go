// Package metrics declares all Prometheus metrics for xray-health-exporter
// and provides helpers for recording build info, config reloads, and tunnel
// health-check results.
package metrics

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Default configuration values.
const (
	DefaultCheckURL      = "https://www.google.com"
	DefaultTimeout       = 30 * time.Second
	DefaultSocksPort     = 1080
	DefaultCheckInterval = 30 * time.Second
	DefaultMaxBackoff    = 5 * time.Minute
	DefaultBackoffMult   = 2.0
	SocksDialTimeout     = 5 * time.Second
	SocksStartupTimeout  = 10 * time.Second
)

var (
	// TunnelUp is 1 if tunnel is working, 0 otherwise.
	TunnelUp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_tunnel_up",
			Help: "1 if tunnel is working, 0 otherwise",
		},
		[]string{"name", "server", "security", "sni"},
	)

	// TunnelLatency is the latency of the tunnel check in seconds.
	TunnelLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_tunnel_latency_seconds",
			Help: "Latency of the tunnel check in seconds",
		},
		[]string{"name", "server", "security", "sni"},
	)

	// TunnelLatencyHistogram is a histogram of tunnel check latencies.
	TunnelLatencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "xray_tunnel_latency_histogram_seconds",
			Help:    "Latency of the tunnel check in seconds (histogram for percentile queries via histogram_quantile)",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"name", "server", "security", "sni"},
	)

	// TunnelCheckTotal counts the total number of tunnel checks by result.
	TunnelCheckTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xray_tunnel_check_total",
			Help: "Total number of tunnel checks by result",
		},
		[]string{"name", "server", "security", "sni", "result"},
	)

	// TunnelLastSuccess is the timestamp of the last successful tunnel check.
	TunnelLastSuccess = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_tunnel_last_success_timestamp",
			Help: "Timestamp of last successful tunnel check",
		},
		[]string{"name", "server", "security", "sni"},
	)

	// TunnelHTTPStatus is the HTTP status code from the tunnel check.
	TunnelHTTPStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_tunnel_http_status",
			Help: "HTTP status code from tunnel check",
		},
		[]string{"name", "server", "security", "sni"},
	)

	// TunnelErrorTotal counts tunnel errors categorized by reason.
	TunnelErrorTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xray_tunnel_error_total",
			Help: "Total number of tunnel errors categorized by reason",
		},
		[]string{"name", "server", "security", "sni", "reason"},
	)

	// ExporterLeader is 1 if this instance is actively probing tunnels.
	ExporterLeader = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "xray_exporter_leader",
			Help: "1 if this exporter instance is actively probing tunnels (leader, or leader election disabled), 0 otherwise",
		},
	)

	// ExporterConfigReloadTotal counts configuration reload attempts.
	ExporterConfigReloadTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "xray_exporter_config_reload_total",
			Help: "Total number of configuration reload attempts",
		},
	)

	// ExporterConfigReloadErrorsTotal counts configuration reload errors.
	ExporterConfigReloadErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "xray_exporter_config_reload_errors_total",
			Help: "Total number of configuration reload errors",
		},
	)

	// ExporterTunnelsConfigured is the current number of configured tunnels.
	ExporterTunnelsConfigured = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "xray_exporter_tunnels_configured",
			Help: "Current number of configured tunnels",
		},
	)

	// ExporterBuildInfo holds build information with version, go_version,
	// and commit labels. Value is always 1.
	ExporterBuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_exporter_build_info",
			Help: "Build information with version, go_version, and commit labels. Value is always 1.",
		},
		[]string{"version", "go_version", "commit"},
	)

	// startTime records when the process started; set once via InitStartTime.
	startTime time.Time

	exporterUptimeSeconds = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "xray_exporter_uptime_seconds",
			Help: "Time since the exporter process started, in seconds",
		},
		func() float64 {
			return time.Since(startTime).Seconds()
		},
	)
)

func init() {
	prometheus.MustRegister(TunnelUp)
	prometheus.MustRegister(TunnelLatency)
	prometheus.MustRegister(TunnelLatencyHistogram)
	prometheus.MustRegister(TunnelCheckTotal)
	prometheus.MustRegister(TunnelLastSuccess)
	prometheus.MustRegister(TunnelHTTPStatus)
	prometheus.MustRegister(TunnelErrorTotal)
	prometheus.MustRegister(ExporterLeader)
	prometheus.MustRegister(ExporterConfigReloadTotal)
	prometheus.MustRegister(ExporterConfigReloadErrorsTotal)
	prometheus.MustRegister(ExporterTunnelsConfigured)
	prometheus.MustRegister(exporterUptimeSeconds)
	prometheus.MustRegister(ExporterBuildInfo)
}

// InitStartTime sets the exporter start time. Call once from main.
func InitStartTime() { startTime = time.Now() }

// SetBuildInfo sets the build info metric with version, Go version, and commit.
func SetBuildInfo(version, goVersion, commit string) {
	ExporterBuildInfo.WithLabelValues(version, goVersion, commit).Set(1)
}

// SetLeader sets the leader gauge to 1 or 0.
func SetLeader(isLeader bool) {
	if isLeader {
		ExporterLeader.Set(1)
	} else {
		ExporterLeader.Set(0)
	}
}

// IncConfigReloadTotal increments the config reload counter.
func IncConfigReloadTotal() { ExporterConfigReloadTotal.Inc() }

// IncConfigReloadErrorsTotal increments the config reload errors counter.
func IncConfigReloadErrorsTotal() { ExporterConfigReloadErrorsTotal.Inc() }

// SetTunnelsConfigured sets the number of currently configured tunnels.
func SetTunnelsConfigured(count int) { ExporterTunnelsConfigured.Set(float64(count)) }

// ErrorReasons lists all known error reason categories used in
// xray_tunnel_error_total. Keep in sync with ClassifyError.
var ErrorReasons = []string{
	"timeout",
	"dns",
	"tls",
	"connection_refused",
	"connection_reset",
	"bad_status",
	"socks_error",
	"unknown",
}

// ClassifyError determines the category of an error for the
// xray_tunnel_error_total metric.
func ClassifyError(err error) string {
	if err == nil {
		return "unknown"
	}

	msg := err.Error()

	// Timeout errors
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "context deadline") ||
		strings.Contains(msg, "i/o timeout") {
		return "timeout"
	}
	if strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "request canceled") {
		return "timeout"
	}

	// TLS errors
	if strings.Contains(msg, "tls:") || strings.Contains(msg, "TLS:") ||
		strings.Contains(msg, "certificate") || strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "handshake failure") {
		return "tls"
	}

	// DNS errors
	if strings.Contains(msg, "lookup ") || strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "dns:") || strings.Contains(msg, "name resolution") ||
		strings.Contains(msg, "Name or service not known") {
		return "dns"
	}

	// Connection refused
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "Connection refused") {
		return "connection_refused"
	}

	// Connection reset
	if strings.Contains(msg, "connection reset by peer") || strings.Contains(msg, "broken pipe") {
		return "connection_reset"
	}

	// SOCKS5 proxy errors
	if strings.Contains(msg, "SOCKS5") || strings.Contains(msg, "socks5") ||
		strings.Contains(msg, "SOCKS") {
		return "socks_error"
	}

	return "unknown"
}
