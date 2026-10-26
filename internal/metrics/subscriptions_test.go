package metrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSubscriptionFailurePreservesLastSuccess(t *testing.T) {
	CleanupSubscriptionMetrics(nil)
	t.Cleanup(func() { CleanupSubscriptionMetrics(nil) })
	RecordSubscriptionRefresh("primary", 3, nil)
	stamp := testutil.ToFloat64(SubscriptionLastSuccess.WithLabelValues("primary"))
	RecordSubscriptionRefresh("primary", 0, errors.New("unavailable"))
	if testutil.ToFloat64(SubscriptionUp.WithLabelValues("primary")) != 0 ||
		testutil.ToFloat64(SubscriptionServers.WithLabelValues("primary")) != 3 ||
		testutil.ToFloat64(SubscriptionLastSuccess.WithLabelValues("primary")) != stamp || stamp == 0 ||
		testutil.ToFloat64(SubscriptionRefreshErrors.WithLabelValues("primary")) != 1 {
		t.Fatal("failed refresh must mark source down and retain last successful count and timestamp")
	}
	RecordSubscriptionRefresh("secondary", 2, nil)
	CleanupSubscriptionMetrics([]string{"secondary"})
	if testutil.CollectAndCount(SubscriptionUp) != 1 || testutil.CollectAndCount(SubscriptionServers) != 1 ||
		testutil.CollectAndCount(SubscriptionLastSuccess) != 1 || testutil.CollectAndCount(SubscriptionRefreshErrors) != 1 {
		t.Fatal("removed source left stale metrics")
	}
	RecordSubscriptionRefresh("secondary", 4, nil)
	if testutil.ToFloat64(SubscriptionUp.WithLabelValues("secondary")) != 1 || testutil.ToFloat64(SubscriptionServers.WithLabelValues("secondary")) != 4 {
		t.Fatal("successful refresh did not update source metrics")
	}
}
