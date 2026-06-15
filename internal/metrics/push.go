package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

// PushJobName is the job name used when pushing to Pushgateway.
const PushJobName = "xray-health-exporter"

// DefaultPushInterval is used when METRICS_PUSH_INTERVAL is empty and the
// minimum check interval across tunnels cannot be determined.
const DefaultPushInterval = 30 * time.Second

// PushConfig holds the configuration for pushing metrics to a Pushgateway.
type PushConfig struct {
	// URL is the base Pushgateway URL without credentials and without a path
	// (the prometheus/push package appends /metrics/job/<job> itself).
	URL string
	// Username for HTTP Basic Auth (empty when no credentials are embedded).
	Username string
	// Password for HTTP Basic Auth (empty when no credentials are embedded).
	Password string
	// Instance is the value of the "instance" grouping label (empty to omit).
	Instance string
	// Interval between consecutive pushes.
	Interval time.Duration
}

// ParsePushURL parses a Pushgateway URL that may contain embedded user:pass
// credentials (e.g. "https://user:pass@pushgateway.example.com:9091/metrics/job/xray").
// It extracts the credentials for Basic Auth, strips them from the returned
// URL, and validates that the scheme is http or https.
//
// The path and query are removed because the prometheus/push package constructs
// the full /metrics/job/<job> path itself — passing a path through would result
// in a doubled path component.
func ParsePushURL(rawURL string) (cleanURL, username, password string, err error) {
	u, parseErr := url.Parse(strings.TrimSpace(rawURL))
	if parseErr != nil {
		return "", "", "", fmt.Errorf("invalid push URL: %w", parseErr)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", "", fmt.Errorf("push URL must use http or https scheme, got %q", u.Scheme)
	}

	if u.Host == "" {
		return "", "", "", fmt.Errorf("push URL must contain a host")
	}

	// Extract credentials for Basic Auth.
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	// Strip credentials, path, query, and fragment so the push package can build
	// its own /metrics/job/<job>[/<label>/<value>] path.
	u.User = nil
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""

	return u.String(), username, password, nil
}

// amLeader reports whether this instance is currently the leader by reading
// the xray_exporter_leader gauge from the default Prometheus registry. When
// leader election is disabled, SetLeader(true) is called at startup so this
// returns true.
//
// amLeader fails CLOSED: on a registry Gather error or when the leader gauge
// is not found, it returns false. In an HA setup (leader election + push),
// a follower must never become a second producer — dropping a single push on
// a transient error is far less harmful than pushing duplicate or stale
// series to the Pushgateway.
func amLeader() bool {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		slog.Warn("leader gauge check failed; skipping push", "error", err)
		return false
	}
	for _, mf := range mfs {
		if mf.GetName() != "xray_exporter_leader" {
			continue
		}
		for _, m := range mf.GetMetric() {
			if g := m.GetGauge(); g != nil {
				return g.GetValue() == 1
			}
		}
	}
	// Metric not found — fail closed.
	return false
}

// PushMetrics pushes all metrics from gatherer to the Pushgateway described by
// cfg. It uses HTTP Basic Auth when Username is non-empty, and adds an
// "instance" grouping label when Instance is non-empty.
//
// PushMetrics is safe to call concurrently with scrapes of /metrics.
func PushMetrics(cfg PushConfig, gatherer prometheus.Gatherer) error {
	p := push.New(cfg.URL, PushJobName).Gatherer(gatherer)

	if cfg.Username != "" {
		p = p.BasicAuth(cfg.Username, cfg.Password)
	}

	if cfg.Instance != "" {
		p = p.Grouping("instance", cfg.Instance)
	}

	return p.Push()
}

// PushLoop periodically pushes metrics from the default registry to the
// Pushgateway described by cfg. It blocks until ctx is canceled.
//
// A push is only performed when this instance is the leader (checked via the
// xray_exporter_leader gauge). When leader election is disabled,
// SetLeader(true) is called at startup so pushes always occur.
//
// Push errors are logged via slog.Warn but do not stop the loop.
func PushLoop(ctx context.Context, cfg PushConfig) {
	slog.Info("starting push gateway loop",
		"url", cfg.URL,
		"interval", cfg.Interval,
		"instance", cfg.Instance)

	// Push once immediately so metrics appear without waiting for the first tick.
	if amLeader() {
		if err := PushMetrics(cfg, prometheus.DefaultGatherer); err != nil {
			slog.Warn("failed to push metrics to pushgateway", "error", err)
		}
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("push gateway loop stopped")
			return
		case <-ticker.C:
			if !amLeader() {
				continue
			}
			if err := PushMetrics(cfg, prometheus.DefaultGatherer); err != nil {
				slog.Warn("failed to push metrics to pushgateway", "error", err)
			}
		}
	}
}

// ReadPushConfig reads METRICS_PUSH_URL, METRICS_PUSH_INTERVAL, and
// METRICS_INSTANCE environment variables and returns a *PushConfig.
//
// Returns (nil, nil) when METRICS_PUSH_URL is empty (push disabled — the
// default behavior is unchanged).
//
// When METRICS_PUSH_INTERVAL is empty and minCheckInterval is positive, the
// push interval defaults to minCheckInterval; otherwise DefaultPushInterval is
// used. When METRICS_INSTANCE is empty, the value defaults to os.Hostname().
func ReadPushConfig(minCheckInterval time.Duration) (*PushConfig, error) {
	rawURL := strings.TrimSpace(os.Getenv("METRICS_PUSH_URL"))
	if rawURL == "" {
		return nil, nil
	}

	cleanURL, username, password, err := ParsePushURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid METRICS_PUSH_URL: %w", err)
	}

	interval := DefaultPushInterval
	if intervalStr := os.Getenv("METRICS_PUSH_INTERVAL"); intervalStr != "" {
		interval, err = time.ParseDuration(intervalStr)
		if err != nil {
			return nil, fmt.Errorf("invalid METRICS_PUSH_INTERVAL: %w", err)
		}
		if interval <= 0 {
			return nil, fmt.Errorf("METRICS_PUSH_INTERVAL must be positive, got %v", interval)
		}
	} else if minCheckInterval > 0 {
		interval = minCheckInterval
	}

	instance := os.Getenv("METRICS_INSTANCE")
	if instance == "" {
		if hostname, err := os.Hostname(); err != nil {
			slog.Warn("failed to determine hostname for push instance label", "error", err)
		} else {
			instance = hostname
		}
	}

	return &PushConfig{
		URL:      cleanURL,
		Username: username,
		Password: password,
		Instance: instance,
		Interval: interval,
	}, nil
}
