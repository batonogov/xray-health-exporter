package metrics

import (
	"github.com/prometheus/client_golang/prometheus/testutil"
	"testing"
	"time"
)

func TestSubscriptionStatePublicationPreservesFetchHistory(t *testing.T) {
	CleanupSubscriptionMetrics(nil)
	t.Cleanup(func() { CleanupSubscriptionMetrics(nil) })
	fetchedAt := time.Unix(1234567890, 0)
	UpdateSubscriptionStatus("primary", true, fetchedAt, 3)
	IncSubscriptionRefreshErrors("primary")
	UpdateSubscriptionStatus("primary", false, fetchedAt, 3)
	// A cached response may become accepted while the most recent fetch failed.
	UpdateSubscriptionStatus("primary", false, fetchedAt, 4)
	if testutil.ToFloat64(SubscriptionUp.WithLabelValues("primary")) != 0 ||
		testutil.ToFloat64(SubscriptionServers.WithLabelValues("primary")) != 4 ||
		testutil.ToFloat64(SubscriptionLastSuccess.WithLabelValues("primary")) != float64(fetchedAt.Unix()) ||
		testutil.ToFloat64(SubscriptionRefreshErrors.WithLabelValues("primary")) != 1 {
		t.Fatal("publishing accepted data changed fetch history or error count")
	}
	UpdateSubscriptionStatus("secondary", false, time.Time{}, 0)
	if testutil.ToFloat64(SubscriptionLastSuccess.WithLabelValues("secondary")) != 0 {
		t.Fatal("unaccepted source has a success timestamp")
	}
	CleanupSubscriptionMetrics([]string{"secondary"})
	if testutil.CollectAndCount(SubscriptionUp) != 1 || testutil.CollectAndCount(SubscriptionServers) != 1 ||
		testutil.CollectAndCount(SubscriptionLastSuccess) != 1 || testutil.CollectAndCount(SubscriptionRefreshErrors) != 1 {
		t.Fatal("removed source left stale metrics")
	}
}
