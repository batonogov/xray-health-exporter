package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		reason string
	}{
		{"nil error", nil, "unknown"},

		// timeout
		{"context deadline exceeded", context.DeadlineExceeded, "timeout"},
		{"deadline exceeded in message", fmt.Errorf("something deadline exceeded something"), "timeout"},
		{"context deadline in message", fmt.Errorf("context deadline reached"), "timeout"},
		{"Client.Timeout in message", fmt.Errorf("net/http: request canceled (Client.Timeout exceeded while awaiting headers)"), "timeout"},
		{"request canceled in message", fmt.Errorf("net/http: request canceled while waiting for connection"), "timeout"},

		// tls
		{"tls handshake error", fmt.Errorf("tls: handshake failure"), "tls"},
		{"TLS uppercase", fmt.Errorf("TLS: certificate verify failed"), "tls"},
		{"certificate error", fmt.Errorf("x509: certificate signed by unknown authority"), "tls"},
		{"x509 error", fmt.Errorf("x509: cannot validate certificate for 127.0.0.1"), "tls"},
		{"handshake failure", fmt.Errorf("remote error: tls: handshake failure"), "tls"},

		// dns
		{"lookup error", fmt.Errorf("lookup nonexistent.invalid: no such host"), "dns"},
		{"no such host", fmt.Errorf("dial tcp: lookup example.com: no such host"), "dns"},
		{"dns error", fmt.Errorf("dns: resolution failed"), "dns"},
		{"name resolution", fmt.Errorf("name resolution failed"), "dns"},
		{"Name or service not known", fmt.Errorf("dial tcp: lookup host.invalid: Name or service not known"), "dns"},

		// connection_refused
		{"connection refused", fmt.Errorf("dial tcp 127.0.0.1:9999: connection refused"), "connection_refused"},
		{"Connection refused capitalized", fmt.Errorf("Connection refused"), "connection_refused"},

		// connection_reset
		{"connection reset by peer", fmt.Errorf("read tcp 10.0.0.1:12345->10.0.0.2:443: connection reset by peer"), "connection_reset"},
		{"broken pipe", fmt.Errorf("write tcp 10.0.0.1:12345->10.0.0.2:443: broken pipe"), "connection_reset"},

		// socks_error
		{"SOCKS5 handshake failed", fmt.Errorf("SOCKS5 handshake failed"), "socks_error"},
		{"SOCKS5 connect failed", fmt.Errorf("SOCKS5 connect failed: 5"), "socks_error"},
		{"SOCKS connect failed lowercase", fmt.Errorf("socks5 proxy error"), "socks_error"},
		{"SOCKS generic", fmt.Errorf("SOCKS protocol error"), "socks_error"},

		// unknown
		{"generic error", fmt.Errorf("some random error"), "unknown"},
		{"empty error", fmt.Errorf(""), "unknown"},
		{"EOF", fmt.Errorf("unexpected EOF"), "unknown"},
		{"i/o timeout", fmt.Errorf("read tcp: i/o timeout"), "timeout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyError(tt.err)
			if got != tt.reason {
				t.Errorf("ClassifyError(%v) = %q, want %q", tt.err, got, tt.reason)
			}
		})
	}
}

func TestClassifyError_NetError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		reason string
	}{
		{"net.OpError with timeout", &netOpError{msg: "read tcp timeout", timeout: true}, "timeout"},
		{"net.OpError without timeout", &netOpError{msg: "read tcp: connection reset by peer", timeout: false}, "connection_reset"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyError(tt.err)
			if got != tt.reason {
				t.Errorf("ClassifyError(%v) = %q, want %q", tt.err, got, tt.reason)
			}
		})
	}
}

// netOpError implements net.Error for testing
type netOpError struct {
	msg     string
	timeout bool
}

func (e *netOpError) Error() string   { return e.msg }
func (e *netOpError) Timeout() bool   { return e.timeout }
func (e *netOpError) Temporary() bool { return false }
func (e *netOpError) Unwrap() error   { return nil }

func TestMetricsUpdate(t *testing.T) {
	labels := prometheus.Labels{
		"name":     "metrics-test",
		"server":   "test.example.com:443",
		"security": "tls",
		"sni":      "test.example.com",
	}

	t.Run("success metrics", func(t *testing.T) {
		TunnelUp.With(labels).Set(1)
		TunnelLatency.With(labels).Set(0.5)
		TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
		TunnelHTTPStatus.With(labels).Set(200)
		TunnelCheckTotal.With(prometheus.Labels{
			"name":     "metrics-test",
			"server":   "test.example.com:443",
			"security": "tls",
			"sni":      "test.example.com",
			"result":   "success",
		}).Inc()
	})

	t.Run("failure metrics", func(t *testing.T) {
		TunnelUp.With(labels).Set(0)
		TunnelCheckTotal.With(prometheus.Labels{
			"name":     "metrics-test",
			"server":   "test.example.com:443",
			"security": "tls",
			"sni":      "test.example.com",
			"result":   "failure",
		}).Inc()
	})
}

func TestMetricsLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels prometheus.Labels
	}{
		{
			name: "reality tunnel",
			labels: prometheus.Labels{
				"name":     "Reality Server",
				"server":   "reality.example.com:8443",
				"security": "reality",
				"sni":      "google.com",
			},
		},
		{
			name: "tls tunnel",
			labels: prometheus.Labels{
				"name":     "TLS Server",
				"server":   "tls.example.com:443",
				"security": "tls",
				"sni":      "example.com",
			},
		},
		{
			name: "tunnel with special characters in name",
			labels: prometheus.Labels{
				"name":     "Server-123_test",
				"server":   "192.168.1.1:8080",
				"security": "tls",
				"sni":      "test.local",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			TunnelUp.With(tt.labels).Set(1)
			TunnelLatency.With(tt.labels).Set(0.1)
			TunnelHTTPStatus.With(tt.labels).Set(200)
		})
	}
}

func TestMetricsReset(t *testing.T) {
	oldLabels := prometheus.Labels{
		"name":     "old-tunnel",
		"server":   "old.example.com:443",
		"security": "tls",
		"sni":      "old.example.com",
	}

	TunnelUp.With(oldLabels).Set(1)
	TunnelLatency.With(oldLabels).Set(0.5)

	newLabels := prometheus.Labels{
		"name":     "new-tunnel",
		"server":   "new.example.com:443",
		"security": "reality",
		"sni":      "google.com",
	}

	TunnelUp.With(newLabels).Set(1)
	TunnelLatency.With(newLabels).Set(0.3)
}

func TestMetricsEndpoint(t *testing.T) {
	labels := prometheus.Labels{
		"name":     "test-tunnel",
		"server":   "example.com:443",
		"security": "reality",
		"sni":      "google.com",
	}

	TunnelUp.With(labels).Set(1)
	TunnelLatency.With(labels).Set(0.123)
	TunnelHTTPStatus.With(labels).Set(200)
	TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))

	checkLabels := prometheus.Labels{
		"name":     labels["name"],
		"server":   labels["server"],
		"security": labels["security"],
		"sni":      labels["sni"],
		"result":   "success",
	}
	TunnelCheckTotal.With(checkLabels).Inc()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	promhttp.Handler().ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.StatusCode)
	}

	body := make([]byte, 20000)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	expectedMetrics := []string{
		"xray_tunnel_up",
		"xray_tunnel_latency_seconds",
		"xray_tunnel_check_total",
		"xray_tunnel_last_success_timestamp",
		"xray_tunnel_http_status",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(bodyStr, metric) {
			t.Errorf("metrics output should contain %s", metric)
		}
	}

	if !strings.Contains(bodyStr, "# HELP") {
		t.Error("metrics should contain HELP comments")
	}
	if !strings.Contains(bodyStr, "# TYPE") {
		t.Error("metrics should contain TYPE comments")
	}
}

func TestLatencyHistogramMetric(t *testing.T) {
	resetMetrics := func() {
		TunnelLatency.Reset()
		TunnelLatencyHistogram.Reset()
	}
	resetMetrics()
	defer resetMetrics()

	labels := prometheus.Labels{
		"name":     "histogram-test",
		"server":   "histogram.example.com:443",
		"security": "tls",
		"sni":      "histogram.example.com",
	}

	for _, v := range []float64{0.05, 0.1, 0.15, 0.2, 0.3, 0.5} {
		TunnelLatencyHistogram.With(labels).Observe(v)
	}

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "xray_tunnel_latency_histogram_seconds" {
			found = true
			for _, m := range mf.GetMetric() {
				if metricLabelsMatch(m, labels) {
					h := m.GetHistogram()
					if h.GetSampleCount() != 6 {
						t.Errorf("expected 6 samples, got %d", h.GetSampleCount())
					}
					if h.GetSampleSum() < 1.29 || h.GetSampleSum() > 1.31 {
						t.Errorf("expected sum ~1.3, got %f", h.GetSampleSum())
					}
					if len(h.GetBucket()) == 0 {
						t.Error("expected non-empty buckets")
					}
				}
			}
			break
		}
	}
	if !found {
		t.Error("xray_tunnel_latency_histogram_seconds metric not found")
	}
}

func TestLatencyHistogramBuckets(t *testing.T) {
	resetMetrics := func() {
		TunnelLatency.Reset()
		TunnelLatencyHistogram.Reset()
	}
	resetMetrics()
	defer resetMetrics()

	labels := prometheus.Labels{
		"name":     "bucket-test",
		"server":   "bucket.example.com:443",
		"security": "tls",
		"sni":      "bucket.example.com",
	}

	TunnelLatencyHistogram.With(labels).Observe(0.07)

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() != "xray_tunnel_latency_histogram_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			if !metricLabelsMatch(m, labels) {
				continue
			}
			h := m.GetHistogram()
			bounds := []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
			if len(h.GetBucket()) != len(bounds) {
				t.Errorf("expected %d buckets, got %d", len(bounds), len(h.GetBucket()))
			}
			for i, b := range h.GetBucket() {
				switch {
				case i < 3:
					if b.GetCumulativeCount() != 0 {
						t.Errorf("bucket[%d] (le=%v) expected 0, got %d", i, bounds[i], b.GetCumulativeCount())
					}
				default:
					if b.GetCumulativeCount() != 1 {
						t.Errorf("bucket[%d] (le=%v) expected 1, got %d", i, bounds[i], b.GetCumulativeCount())
					}
				}
			}
		}
	}
}

func TestMetricsEndpoint_IncludesHistogram(t *testing.T) {
	TunnelLatencyHistogram.With(prometheus.Labels{
		"name": "hist-test", "server": "s:443", "security": "tls", "sni": "s",
	}).Observe(0.1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)

	if !strings.Contains(string(body), "# TYPE xray_tunnel_latency_histogram_seconds histogram") {
		t.Error("expected xray_tunnel_latency_histogram_seconds histogram TYPE declaration")
	}
}

func TestExporterInternalMetrics_BuildInfo(t *testing.T) {
	ExporterBuildInfo.WithLabelValues("test-version", "go1.26", "abc123").Set(1)

	if !metricExistsWithLabels(t, "xray_exporter_build_info", prometheus.Labels{
		"version":    "test-version",
		"go_version": "go1.26",
		"commit":     "abc123",
	}) {
		t.Error("expected build_info metric with correct labels")
	}
}

func TestExporterInternalMetrics_Uptime(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "xray_exporter_uptime_seconds" {
			found = true
			for _, m := range mf.GetMetric() {
				val := m.GetGauge().GetValue()
				if val < 0 {
					t.Errorf("uptime should be non-negative, got %v", val)
				}
			}
		}
	}
	if !found {
		t.Error("expected xray_exporter_uptime_seconds metric to be registered")
	}
}

func TestExporterInternalMetrics_InMetricsOutput(t *testing.T) {
	ExporterBuildInfo.WithLabelValues("1.0.0", "go1.26", "").Set(1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(w, req)

	body := make([]byte, 20000)
	n, _ := w.Result().Body.Read(body)
	bodyStr := string(body[:n])

	expectedMetrics := []string{
		"xray_exporter_config_reload_total",
		"xray_exporter_config_reload_errors_total",
		"xray_exporter_tunnels_configured",
		"xray_exporter_uptime_seconds",
		"xray_exporter_build_info",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(bodyStr, metric) {
			t.Errorf("metrics output should contain %s", metric)
		}
	}
}

// Helper functions

func metricExistsWithLabels(t *testing.T, metricName string, labels prometheus.Labels) bool {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}

		for _, metric := range mf.GetMetric() {
			if metricLabelsMatch(metric, labels) {
				return true
			}
		}
	}

	return false
}

func metricLabelsMatch(metric *dto.Metric, labels prometheus.Labels) bool {
	if len(metric.GetLabel()) != len(labels) {
		return false
	}

	for _, lp := range metric.GetLabel() {
		val, ok := labels[lp.GetName()]
		if !ok || val != lp.GetValue() {
			return false
		}
	}

	return true
}
