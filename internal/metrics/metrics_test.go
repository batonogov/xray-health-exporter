package metrics

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"net/http/httptest"

	dto "github.com/prometheus/client_model/go"
)

func TestBaseLabels(t *testing.T) {
	labels := BaseLabels("my-tunnel", "example.com:443", "tls", "example.com")

	if labels["name"] != "my-tunnel" {
		t.Errorf("name = %v, want my-tunnel", labels["name"])
	}
	if labels["server"] != "example.com:443" {
		t.Errorf("server = %v, want example.com:443", labels["server"])
	}
	if labels["security"] != "tls" {
		t.Errorf("security = %v, want tls", labels["security"])
	}
	if labels["sni"] != "example.com" {
		t.Errorf("sni = %v, want example.com", labels["sni"])
	}
}

func TestCheckLabels(t *testing.T) {
	labels := CheckLabels("my-tunnel", "example.com:443", "tls", "example.com", "success")

	if labels["result"] != "success" {
		t.Errorf("result = %v, want success", labels["result"])
	}
	if len(labels) != 5 {
		t.Errorf("expected 5 labels, got %d", len(labels))
	}
}

func TestCleanupRemoved(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	removed := LabelSet{Name: "removed", Server: "removed.example.com:1443", Security: "reality", SNI: "google.com"}
	kept := LabelSet{Name: "kept", Server: "kept.example.com:2443", Security: "tls", SNI: "kept.example.com"}
	newLS := LabelSet{Name: "new", Server: "new.example.com:3443", Security: "tls", SNI: "new.example.com"}

	populateMetrics := func(ls LabelSet) {
		labels := BaseLabels(ls.Name, ls.Server, ls.Security, ls.SNI)
		m.TunnelUp.With(labels).Set(1)
		m.TunnelLatency.With(labels).Set(0.2)
		m.TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
		m.TunnelHTTPStatus.With(labels).Set(200)
		m.TunnelCheckTotal.With(CheckLabels(ls.Name, ls.Server, ls.Security, ls.SNI, "success")).Inc()
		m.TunnelCheckTotal.With(CheckLabels(ls.Name, ls.Server, ls.Security, ls.SNI, "failure")).Inc()
	}

	populateMetrics(removed)
	populateMetrics(kept)
	populateMetrics(newLS)

	m.CleanupRemoved([]LabelSet{removed, kept}, []LabelSet{kept, newLS})

	if metricExistsWithLabels(t, reg, "xray_tunnel_up", prometheus.Labels{
		"name": "removed", "server": "removed.example.com:1443", "security": "reality", "sni": "google.com",
	}) {
		t.Errorf("expected metrics for removed tunnel to be deleted")
	}

	if !metricExistsWithLabels(t, reg, "xray_tunnel_up", prometheus.Labels{
		"name": "kept", "server": "kept.example.com:2443", "security": "tls", "sni": "kept.example.com",
	}) {
		t.Errorf("expected metrics for kept tunnel to remain")
	}

	for _, result := range []string{"success", "failure"} {
		if metricExistsWithLabels(t, reg, "xray_tunnel_check_total", prometheus.Labels{
			"name": "removed", "server": "removed.example.com:1443", "security": "reality", "sni": "google.com", "result": result,
		}) {
			t.Errorf("expected counter metric (%s) for removed tunnel to be deleted", result)
		}
	}

	if !metricExistsWithLabels(t, reg, "xray_tunnel_check_total", prometheus.Labels{
		"name": "kept", "server": "kept.example.com:2443", "security": "tls", "sni": "kept.example.com", "result": "success",
	}) {
		t.Errorf("expected counter metric for kept tunnel to remain")
	}
}

func TestMetricsUpdate(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	labels := BaseLabels("metrics-test", "test.example.com:443", "tls", "test.example.com")

	t.Run("success metrics", func(t *testing.T) {
		m.TunnelUp.With(labels).Set(1)
		m.TunnelLatency.With(labels).Set(0.5)
		m.TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
		m.TunnelHTTPStatus.With(labels).Set(200)
		m.TunnelCheckTotal.With(CheckLabels("metrics-test", "test.example.com:443", "tls", "test.example.com", "success")).Inc()
	})

	t.Run("failure metrics", func(t *testing.T) {
		m.TunnelUp.With(labels).Set(0)
		m.TunnelCheckTotal.With(CheckLabels("metrics-test", "test.example.com:443", "tls", "test.example.com", "failure")).Inc()
	})
}

func TestMetricsLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	tests := []struct {
		name   string
		labels prometheus.Labels
	}{
		{
			name:   "reality tunnel",
			labels: BaseLabels("Reality Server", "reality.example.com:8443", "reality", "google.com"),
		},
		{
			name:   "tls tunnel",
			labels: BaseLabels("TLS Server", "tls.example.com:443", "tls", "example.com"),
		},
		{
			name:   "tunnel with special characters in name",
			labels: BaseLabels("Server-123_test", "192.168.1.1:8080", "tls", "test.local"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.TunnelUp.With(tt.labels).Set(1)
			m.TunnelLatency.With(tt.labels).Set(0.1)
			m.TunnelHTTPStatus.With(tt.labels).Set(200)
		})
	}
}

func TestMetricsReset(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	oldLabels := BaseLabels("old-tunnel", "old.example.com:443", "tls", "old.example.com")
	m.TunnelUp.With(oldLabels).Set(1)
	m.TunnelLatency.With(oldLabels).Set(0.5)

	newLabels := BaseLabels("new-tunnel", "new.example.com:443", "reality", "google.com")
	m.TunnelUp.With(newLabels).Set(1)
	m.TunnelLatency.With(newLabels).Set(0.3)
}

func TestMetricsEndpoint(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	labels := BaseLabels("test-tunnel", "example.com:443", "reality", "google.com")
	m.TunnelUp.With(labels).Set(1)
	m.TunnelLatency.With(labels).Set(0.123)
	m.TunnelHTTPStatus.With(labels).Set(200)
	m.TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
	m.TunnelCheckTotal.With(CheckLabels("test-tunnel", "example.com:443", "reality", "google.com", "success")).Inc()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected status OK, got %v", resp.StatusCode)
	}

	body := make([]byte, 10000)
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

func metricExistsWithLabels(t *testing.T, reg prometheus.Gatherer, metricName string, labels prometheus.Labels) bool {
	t.Helper()

	mfs, err := reg.Gather()
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

func TestTunnelInitErrorsMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.TunnelInitErrors.Inc()
	m.TunnelInitErrors.Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range mfs {
		if mf.GetName() == "xray_tunnel_init_errors_total" {
			found = true
			metrics := mf.GetMetric()
			if len(metrics) != 1 {
				t.Fatalf("expected 1 metric, got %d", len(metrics))
			}
			if metrics[0].GetCounter().GetValue() != 2 {
				t.Errorf("expected counter value 2, got %v", metrics[0].GetCounter().GetValue())
			}
		}
	}

	if !found {
		t.Error("xray_tunnel_init_errors_total metric not found")
	}
}

func TestLabelSetKey(t *testing.T) {
	ls := LabelSet{Name: "test", Server: "example.com:443", Security: "tls", SNI: "example.com"}
	expected := fmt.Sprintf("%s|%s|%s|%s", ls.Name, ls.Server, ls.Security, ls.SNI)
	if ls.key() != expected {
		t.Errorf("key() = %v, want %v", ls.key(), expected)
	}
}
