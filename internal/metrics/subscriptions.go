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
		Name: "xray_subscription_last_success_timestamp", Help: "Unix timestamp of the last successful subscription refresh",
	}, []string{"name"})
	SubscriptionServers = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xray_subscription_servers", Help: "Server count from the last successful subscription refresh",
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

// RecordSubscriptionRefresh records source health without discarding the last
// successful server count on failure. Names must not contain subscription URLs.
func RecordSubscriptionRefresh(name string, count int, err error) {
	subscriptionMu.Lock()
	defer subscriptionMu.Unlock()
	subscriptionNames[name] = struct{}{}
	SubscriptionRefreshErrors.WithLabelValues(name).Add(0)
	if err != nil {
		SubscriptionUp.WithLabelValues(name).Set(0)
		SubscriptionRefreshErrors.WithLabelValues(name).Inc()
		return
	}
	SubscriptionUp.WithLabelValues(name).Set(1)
	SubscriptionLastSuccess.WithLabelValues(name).Set(float64(time.Now().Unix()))
	SubscriptionServers.WithLabelValues(name).Set(float64(count))
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
