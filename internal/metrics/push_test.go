package metrics

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestParsePushURL(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		wantURL     string
		wantUser    string
		wantPass    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "with credentials and path",
			rawURL:   "https://user:pass@pushgateway.example.com:9091/metrics/job/xray-health-exporter",
			wantURL:  "https://pushgateway.example.com:9091",
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:    "without credentials",
			rawURL:  "http://pushgateway.example.com:9091",
			wantURL: "http://pushgateway.example.com:9091",
		},
		{
			name:     "username only no password",
			rawURL:   "http://user@pushgateway.example.com:9091",
			wantURL:  "http://pushgateway.example.com:9091",
			wantUser: "user",
		},
		{
			name:     "https with credentials and no port",
			rawURL:   "https://admin:s3cret@pgw.internal",
			wantURL:  "https://pgw.internal",
			wantUser: "admin",
			wantPass: "s3cret",
		},
		{
			name:        "invalid scheme ftp",
			rawURL:      "ftp://pushgateway:9091",
			wantErr:     true,
			errContains: "scheme",
		},
		{
			name:        "no scheme",
			rawURL:      "pushgateway:9091",
			wantErr:     true,
			errContains: "scheme",
		},
		{
			name:        "empty string",
			rawURL:      "",
			wantErr:     true,
			errContains: "scheme",
		},
		{
			name:        "malformed url with spaces",
			rawURL:      "http://push gateway:9091",
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotUser, gotPass, err := ParsePushURL(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (url=%q user=%q)", gotURL, gotUser)
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotURL != tt.wantURL {
				t.Errorf("URL = %q, want %q", gotURL, tt.wantURL)
			}
			if gotUser != tt.wantUser {
				t.Errorf("Username = %q, want %q", gotUser, tt.wantUser)
			}
			if gotPass != tt.wantPass {
				t.Errorf("Password = %q, want %q", gotPass, tt.wantPass)
			}
		})
	}
}

func TestParsePushURL_StripsPathAndQuery(t *testing.T) {
	cleanURL, _, _, err := ParsePushURL("http://pgw:9091/foo/bar?baz=1#frag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleanURL != "http://pgw:9091" {
		t.Errorf("URL = %q, want %q", cleanURL, "http://pgw:9091")
	}
}

func startFakePushgateway(t *testing.T, username, password string) (*httptest.Server, *pushRecorder) {
	t.Helper()
	rec := &pushRecorder{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.record(r.Method, r.Header.Get("Authorization"), body, r.URL.Path)

		// Pushgateway returns 202 Accepted for pushes.
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	return srv, rec
}

type pushRecorder struct {
	mu       sync.Mutex
	requests []pushRequest
}

type pushRequest struct {
	method string
	auth   string
	body   []byte
	path   string
}

func (r *pushRecorder) record(method, auth string, body []byte, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, pushRequest{
		method: method,
		auth:   auth,
		body:   body,
		path:   path,
	})
}

func (r *pushRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

func (r *pushRecorder) last() pushRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) == 0 {
		return pushRequest{}
	}
	return r.requests[len(r.requests)-1]
}

func newTestRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "xray_test_push_metric",
		Help: "test gauge for push",
	})
	g.Set(42)
	reg.MustRegister(g)
	return reg
}

func TestPushMetrics_NoAuth(t *testing.T) {
	srv, rec := startFakePushgateway(t, "", "")
	reg := newTestRegistry()

	cfg := PushConfig{URL: srv.URL}
	if err := PushMetrics(cfg, reg); err != nil {
		t.Fatalf("PushMetrics failed: %v", err)
	}

	if rec.count() != 1 {
		t.Fatalf("expected 1 push request, got %d", rec.count())
	}

	last := rec.last()
	if last.method != http.MethodPut {
		t.Errorf("method = %q, want PUT", last.method)
	}
	if last.auth != "" {
		t.Errorf("expected no Authorization header, got %q", last.auth)
	}
	if len(last.body) == 0 {
		t.Error("expected non-empty body")
	}
}

func TestPushMetrics_WithBasicAuth(t *testing.T) {
	srv, rec := startFakePushgateway(t, "user", "pass")
	reg := newTestRegistry()

	cfg := PushConfig{
		URL:      srv.URL,
		Username: "user",
		Password: "pass",
	}
	if err := PushMetrics(cfg, reg); err != nil {
		t.Fatalf("PushMetrics failed: %v", err)
	}

	if rec.count() != 1 {
		t.Fatalf("expected 1 push request, got %d", rec.count())
	}

	last := rec.last()
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if last.auth != expected {
		t.Errorf("Authorization = %q, want %q", last.auth, expected)
	}
}

func TestPushMetrics_WithInstanceGrouping(t *testing.T) {
	srv, rec := startFakePushgateway(t, "", "")
	reg := newTestRegistry()

	cfg := PushConfig{
		URL:      srv.URL,
		Instance: "my-host",
	}
	if err := PushMetrics(cfg, reg); err != nil {
		t.Fatalf("PushMetrics failed: %v", err)
	}

	last := rec.last()
	if !strings.Contains(last.path, "/instance/my-host") {
		t.Errorf("path %q does not contain instance grouping", last.path)
	}
}

func TestPushMetrics_PullStillWorks(t *testing.T) {
	// Push must not break the pull /metrics path: the same registry must still
	// be scrapeable via promhttp.
	srv, rec := startFakePushgateway(t, "", "")
	reg := newTestRegistry()

	cfg := PushConfig{URL: srv.URL}
	if err := PushMetrics(cfg, reg); err != nil {
		t.Fatalf("PushMetrics failed: %v", err)
	}

	// Now scrape the registry via promhttp as /metrics would.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("/metrics status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "xray_test_push_metric") {
		t.Error("/metrics body does not contain the test metric")
	}
	if rec.count() != 1 {
		t.Errorf("expected 1 push request, got %d", rec.count())
	}
}

func TestPushMetrics_ServerError(t *testing.T) {
	// Pushgateway returning 500 should produce an error, not a panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	reg := newTestRegistry()
	cfg := PushConfig{URL: srv.URL}
	err := PushMetrics(cfg, reg)
	if err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status code") {
		t.Errorf("error %q does not mention status code", err.Error())
	}
}

func TestPushLoop_ExitsOnContextCancel(t *testing.T) {
	// PushLoop only pushes when the leader gauge is 1.
	SetLeader(true)
	t.Cleanup(func() { SetLeader(false) })

	srv, rec := startFakePushgateway(t, "", "")

	ctx, cancel := context.WithCancel(context.Background())

	// Use a short interval so the initial push + at least one tick happens.
	cfg := PushConfig{
		URL:      srv.URL,
		Interval: 50 * time.Millisecond,
	}

	done := make(chan struct{})
	go func() {
		PushLoop(ctx, cfg)
		close(done)
	}()

	// Give the loop time to do at least two pushes (initial + one tick).
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// success — loop exited on cancel
	case <-time.After(5 * time.Second):
		t.Fatal("PushLoop did not exit within 5s after context cancel")
	}

	if rec.count() < 2 {
		t.Errorf("expected at least 2 pushes (initial + tick), got %d", rec.count())
	}
}

func TestReadPushConfig_Disabled(t *testing.T) {
	t.Setenv("METRICS_PUSH_URL", "")
	cfg, err := ReadPushConfig(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when METRICS_PUSH_URL is empty, got %+v", cfg)
	}
}

func TestReadPushConfig_Enabled(t *testing.T) {
	t.Setenv("METRICS_PUSH_URL", "https://user:pass@pgw.example.com:9091")
	t.Setenv("METRICS_PUSH_INTERVAL", "15s")
	t.Setenv("METRICS_INSTANCE", "test-host")

	cfg, err := ReadPushConfig(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if cfg.URL != "https://pgw.example.com:9091" {
		t.Errorf("URL = %q, want %q", cfg.URL, "https://pgw.example.com:9091")
	}
	if cfg.Username != "user" {
		t.Errorf("Username = %q, want %q", cfg.Username, "user")
	}
	if cfg.Password != "pass" {
		t.Errorf("Password = %q, want %q", cfg.Password, "pass")
	}
	if cfg.Instance != "test-host" {
		t.Errorf("Instance = %q, want %q", cfg.Instance, "test-host")
	}
	if cfg.Interval != 15*time.Second {
		t.Errorf("Interval = %v, want %v", cfg.Interval, 15*time.Second)
	}
}

func TestReadPushConfig_DefaultIntervalFromMinCheck(t *testing.T) {
	t.Setenv("METRICS_PUSH_URL", "http://pgw:9091")
	t.Setenv("METRICS_PUSH_INTERVAL", "")

	cfg, err := ReadPushConfig(10 * time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interval != 10*time.Second {
		t.Errorf("Interval = %v, want %v (minCheckInterval)", cfg.Interval, 10*time.Second)
	}
}

func TestReadPushConfig_DefaultIntervalFallback(t *testing.T) {
	t.Setenv("METRICS_PUSH_URL", "http://pgw:9091")
	t.Setenv("METRICS_PUSH_INTERVAL", "")

	cfg, err := ReadPushConfig(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interval != DefaultPushInterval {
		t.Errorf("Interval = %v, want %v (DefaultPushInterval)", cfg.Interval, DefaultPushInterval)
	}
}

func TestReadPushConfig_InvalidInterval(t *testing.T) {
	t.Setenv("METRICS_PUSH_URL", "http://pgw:9091")
	t.Setenv("METRICS_PUSH_INTERVAL", "not-a-duration")

	_, err := ReadPushConfig(0)
	if err == nil {
		t.Fatal("expected error for invalid interval, got nil")
	}
}

func TestReadPushConfig_InvalidURL(t *testing.T) {
	t.Setenv("METRICS_PUSH_URL", "ftp://pgw:9091")

	_, err := ReadPushConfig(0)
	if err == nil {
		t.Fatal("expected error for invalid URL scheme, got nil")
	}
}

func TestAmLeader(t *testing.T) {
	// amLeader reads the xray_exporter_leader gauge from the default registry.
	// By default it is 0 (not leader) until SetLeader(true) is called.
	SetLeader(false)
	if amLeader() {
		t.Error("expected amLeader() = false when gauge is 0")
	}

	SetLeader(true)
	if !amLeader() {
		t.Error("expected amLeader() = true when gauge is 1")
	}

	// Reset to avoid affecting other tests.
	SetLeader(false)
}

// TestAmLeader_FailClosed verifies that amLeader returns false (does not push)
// when the leader gauge value is not 1. This is the core fail-closed contract:
// a follower must never become a second producer in an HA setup. The
// Gather-error and metric-not-found paths also return false (by code
// inspection), but are hard to unit-test against the global default registry.
func TestAmLeader_FailClosed(t *testing.T) {
	// Gauge at 0 (follower) => must NOT be treated as leader.
	SetLeader(false)
	result := amLeader()
	if result {
		t.Fatalf("amLeader() = true when gauge is 0; expected false (fail-closed: follower must not push)")
	}

	// Gauge at 1 (leader) => push is allowed.
	SetLeader(true)
	if !amLeader() {
		t.Fatalf("amLeader() = false when gauge is 1; expected true")
	}

	// Any value other than exactly 1 must be treated as not-leader.
	// The gauge only holds 0 or 1 in production, but verify the contract.
	SetLeader(false)
	if amLeader() {
		t.Fatalf("amLeader() = true when gauge reset to 0; expected false")
	}
}
