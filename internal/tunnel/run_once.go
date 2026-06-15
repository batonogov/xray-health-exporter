package tunnel

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// RunOnce loads the configuration, initializes all tunnels, performs exactly
// one health-check per tunnel (concurrently), updates Prometheus metrics, and
// writes all metrics in Prometheus text-exposition format to w.
//
// It returns allUp=true only if every tunnel check returned Up==true.
//
// Checks are individually bounded by each tunnel's CheckTimeout, so no
// external context is required for cancellation.
//
// Unlike RunProbing, this function:
//   - Does NOT start the HTTP server, config watcher, or subscription watcher.
//   - Does NOT use RunTunnelChecker (which loops forever).
//   - Performs a single PerformCheck per tunnel instead.
//   - Ignores leader election — run-once is a single-shot local action intended
//     for CI, scripts, and debugging. It always runs regardless of leader
//     election configuration.
func RunOnce(configFile string, checker HealthChecker, mu MetricsUpdater, w io.Writer) (bool, error) {
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return false, fmt.Errorf("failed to load config: %w", err)
	}

	subTunnels := config.ResolveSubscriptions(cfg)
	cfg.Tunnels = append(cfg.Tunnels, subTunnels...)

	if len(cfg.Tunnels) == 0 {
		return false, fmt.Errorf("no tunnels to initialize (including subscriptions)")
	}

	if err := config.ValidateTunnels(cfg); err != nil {
		return false, fmt.Errorf("config validation failed: %w", err)
	}

	instances, _, err := createTunnelInstances(cfg, metrics.DefaultSocksPort)
	if err != nil {
		return false, fmt.Errorf("failed to initialize tunnels: %w", err)
	}
	defer StopTunnels(instances)

	metrics.SetTunnelsConfigured(len(instances))

	// Perform exactly one check per tunnel, concurrently.
	var allUp atomic.Bool
	allUp.Store(true)

	var wg sync.WaitGroup
	for _, ti := range instances {
		wg.Add(1)
		go func(ti *TunnelInstance) {
			defer wg.Done()

			result := checker.Check(ti)

			if !result.Up {
				allUp.Store(false)
			}

			if !result.Up && result.Err != nil {
				mu.RecordError(ti.Name, ti.MetricLabels, result.Err)
			}

			if result.Up {
				slog.Info("tunnel UP", "tunnel", ti.Name, "latency", result.Latency.Round(time.Millisecond))
			} else if result.Err != nil {
				slog.Error("tunnel DOWN", "tunnel", ti.Name, "error", result.Err)
			} else {
				slog.Error("tunnel DOWN", "tunnel", ti.Name)
			}

			mu.Update(ti.Name, ti.MetricLabels, result)
		}(ti)
	}
	wg.Wait()

	// Encode all metrics from the default registry in Prometheus text format.
	if err := encodeMetrics(w); err != nil {
		return allUp.Load(), fmt.Errorf("failed to encode metrics: %w", err)
	}

	return allUp.Load(), nil
}

// encodeMetrics gathers all registered metric families from the default
// Prometheus registry and encodes them in text-exposition format to w.
func encodeMetrics(w io.Writer) error {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return fmt.Errorf("gather metrics: %w", err)
	}

	enc := expfmt.NewEncoder(w, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return fmt.Errorf("encode metric family %q: %w", mf.GetName(), err)
		}
	}
	return nil
}
