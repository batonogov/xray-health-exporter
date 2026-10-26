package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	SubscriptionUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xray_subscription_up", Help: "Whether the last subscription refresh succeeded",
	}, []string{"name"})
	SubscriptionLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xray_subscription_last_success_timestamp", Help: "Unix fetch timestamp of the latest accepted subscription response",
	}, []string{"name"})
	SubscriptionServers = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xray_subscription_servers", Help: "Server count in the accepted subscription configuration",
	}, []string{"name"})
	SubscriptionRefreshErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "xray_subscription_refresh_errors_total", Help: "Failed subscription refresh attempts",
	}, []string{"name"})
	subscriptionMu    sync.Mutex
	subscriptionNames = make(map[string]struct{})
)

func init() {
	prometheus.MustRegister(SubscriptionUp, SubscriptionLastSuccess, SubscriptionServers, SubscriptionRefreshErrors)
}

// UpdateSubscriptionStatus publishes source state without creating a refresh
// event. lastSuccess is the original fetch time of the latest accepted response;
// applying cached data must never manufacture a new successful fetch.
func UpdateSubscriptionStatus(name string, up bool, lastSuccess time.Time, acceptedServers int) {
	subscriptionMu.Lock()
	defer subscriptionMu.Unlock()
	subscriptionNames[name] = struct{}{}
	SubscriptionRefreshErrors.WithLabelValues(name).Add(0)
	value := float64(0)
	if up {
		value = 1
	}
	SubscriptionUp.WithLabelValues(name).Set(value)
	stamp := float64(0)
	if !lastSuccess.IsZero() {
		stamp = float64(lastSuccess.Unix())
	}
	SubscriptionLastSuccess.WithLabelValues(name).Set(stamp)
	SubscriptionServers.WithLabelValues(name).Set(float64(acceptedServers))
}

// IncSubscriptionRefreshErrors records one failed request or newly rejected
// candidate response. Republishing cached state does not increment this counter.
func IncSubscriptionRefreshErrors(name string) {
	subscriptionMu.Lock()
	defer subscriptionMu.Unlock()
	subscriptionNames[name] = struct{}{}
	SubscriptionRefreshErrors.WithLabelValues(name).Inc()
}

// CleanupSubscriptionMetrics removes series for sources removed from config.
func CleanupSubscriptionMetrics(activeNames []string) {
	subscriptionMu.Lock()
	defer subscriptionMu.Unlock()
	active := make(map[string]bool, len(activeNames))
	for _, name := range activeNames {
		active[name] = true
	}
	for name := range subscriptionNames {
		if active[name] {
			continue
		}
		SubscriptionUp.DeleteLabelValues(name)
		SubscriptionLastSuccess.DeleteLabelValues(name)
		SubscriptionServers.DeleteLabelValues(name)
		SubscriptionRefreshErrors.DeleteLabelValues(name)
		delete(subscriptionNames, name)
	}
}
