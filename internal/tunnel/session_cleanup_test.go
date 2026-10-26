package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func assertNoSubscriptionSeries(t *testing.T) {
	t.Helper()
	for _, collector := range []prometheus.Collector{metrics.SubscriptionUp, metrics.SubscriptionServers, metrics.SubscriptionLastSuccess, metrics.SubscriptionRefreshErrors} {
		if testutil.CollectAndCount(collector) != 0 {
			t.Fatal("subscription series survived probing session")
		}
	}
}

func TestRunProbingCleansFailedStartupSubscriptionMetrics(t *testing.T) {
	metrics.CleanupSubscriptionMetrics(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "outage", 503) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("subscriptions:\n  - name: failed\n    url: %q\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RunProbing(context.Background(), path, mockChecker{}, NewPrometheusMetrics()); err == nil {
		t.Fatal("expected startup failure")
	}
	assertNoSubscriptionSeries(t)
}

func TestRunProbingCleanupDoesNotClobberActiveSession(t *testing.T) {
	metrics.CleanupSubscriptionMetrics(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"outbounds":[{"protocol":"freedom"}]}`) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("subscriptions:\n  - name: active\n    url: %q\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunProbing(ctx, path, mockChecker{}, NewPrometheusMetrics()) }()
	deadline := time.After(time.Second)
	for testutil.CollectAndCount(metrics.SubscriptionUp) == 0 {
		select {
		case err := <-done:
			t.Fatalf("session exited: %v", err)
		case <-deadline:
			t.Fatal("session did not start")
		case <-time.After(time.Millisecond):
		}
	}
	if err := RunProbing(context.Background(), path, mockChecker{}, NewPrometheusMetrics()); err == nil {
		t.Fatal("concurrent session was accepted")
	}
	if testutil.ToFloat64(metrics.SubscriptionUp.WithLabelValues("active")) != 1 {
		t.Fatal("rejected second session removed active source metrics")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("session did not stop")
	}
	assertNoSubscriptionSeries(t)
}
