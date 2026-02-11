package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metric collectors.
type Metrics struct {
	TunnelUp          *prometheus.GaugeVec
	TunnelLatency     *prometheus.GaugeVec
	TunnelCheckTotal  *prometheus.CounterVec
	TunnelLastSuccess *prometheus.GaugeVec
	TunnelHTTPStatus  *prometheus.GaugeVec
	TunnelInitErrors  prometheus.Counter
}

// New creates and registers all metrics on the given registry.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		TunnelUp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "xray_tunnel_up",
				Help: "1 if tunnel is working, 0 otherwise",
			},
			[]string{"name", "server", "security", "sni"},
		),
		TunnelLatency: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "xray_tunnel_latency_seconds",
				Help: "Latency of the tunnel check in seconds",
			},
			[]string{"name", "server", "security", "sni"},
		),
		TunnelCheckTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "xray_tunnel_check_total",
				Help: "Total number of tunnel checks by result",
			},
			[]string{"name", "server", "security", "sni", "result"},
		),
		TunnelLastSuccess: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "xray_tunnel_last_success_timestamp",
				Help: "Timestamp of last successful tunnel check",
			},
			[]string{"name", "server", "security", "sni"},
		),
		TunnelHTTPStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "xray_tunnel_http_status",
				Help: "HTTP status code from tunnel check",
			},
			[]string{"name", "server", "security", "sni"},
		),
		TunnelInitErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "xray_tunnel_init_errors_total",
				Help: "Total number of tunnel initialization errors",
			},
		),
	}

	reg.MustRegister(
		m.TunnelUp,
		m.TunnelLatency,
		m.TunnelCheckTotal,
		m.TunnelLastSuccess,
		m.TunnelHTTPStatus,
		m.TunnelInitErrors,
	)

	return m
}

// BaseLabels returns the standard 4-label set for a tunnel.
func BaseLabels(name, server, security, sni string) prometheus.Labels {
	return prometheus.Labels{
		"name":     name,
		"server":   server,
		"security": security,
		"sni":      sni,
	}
}

// CheckLabels returns the 5-label set (with result) for check counters.
func CheckLabels(name, server, security, sni, result string) prometheus.Labels {
	return prometheus.Labels{
		"name":     name,
		"server":   server,
		"security": security,
		"sni":      sni,
		"result":   result,
	}
}

// LabelSet represents a unique set of tunnel labels.
type LabelSet struct {
	Name     string
	Server   string
	Security string
	SNI      string
}

func (ls LabelSet) key() string {
	return fmt.Sprintf("%s|%s|%s|%s", ls.Name, ls.Server, ls.Security, ls.SNI)
}

// CleanupRemoved deletes metrics for tunnels present in old but not in new.
func (m *Metrics) CleanupRemoved(old, new []LabelSet) {
	if len(old) == 0 {
		return
	}

	newKeys := make(map[string]struct{}, len(new))
	for _, ls := range new {
		newKeys[ls.key()] = struct{}{}
	}

	for _, ls := range old {
		if _, exists := newKeys[ls.key()]; exists {
			continue
		}

		labels := []string{ls.Name, ls.Server, ls.Security, ls.SNI}
		m.TunnelUp.DeleteLabelValues(labels...)
		m.TunnelLatency.DeleteLabelValues(labels...)
		m.TunnelLastSuccess.DeleteLabelValues(labels...)
		m.TunnelHTTPStatus.DeleteLabelValues(labels...)
		m.TunnelCheckTotal.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], "success")
		m.TunnelCheckTotal.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], "failure")
	}
}
