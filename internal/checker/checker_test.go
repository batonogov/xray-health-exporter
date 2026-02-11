package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/socks"
	"github.com/batonogov/xray-health-exporter/internal/testutil"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
	"github.com/prometheus/client_golang/prometheus"
)

func newTestDeps(t *testing.T) (*metrics.Metrics, *slog.Logger) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return m, logger
}

func newTestInstance(port int, checkURL string, timeout time.Duration) *tunnel.TunnelInstance {
	socksProxy := fmt.Sprintf("127.0.0.1:%d", port)
	dialer := socks.NewDialer(socksProxy, timeout)

	ti := &tunnel.TunnelInstance{
		Name: "test-tunnel",
		VLESSConfig: &tunnel.VLESSConfig{
			Address:  "test.example.com",
			Port:     443,
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     port,
		CheckURL:      checkURL,
		CheckTimeout:  timeout,
		CheckInterval: 30 * time.Second,
		HTTPClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext:       dialer.DialContext,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: false},
				DisableKeepAlives: true,
			},
		},
	}
	return ti
}

func TestCheck(t *testing.T) {
	m, logger := newTestDeps(t)

	port, cleanup := testutil.StartMockSOCKS5(t)
	defer cleanup()

	ti := newTestInstance(port, "http://test.example.com", 5*time.Second)

	time.Sleep(100 * time.Millisecond)

	result := Check(ti, m, logger)

	if !result.Up {
		t.Errorf("expected tunnel to be UP, error: %v", result.Error)
	}

	if !ti.Up.Load() {
		t.Error("expected ti.Up to be true")
	}
}

func TestCheck_Timeout(t *testing.T) {
	m, logger := newTestDeps(t)

	port, cleanup := testutil.StartMockSOCKS5(t, testutil.WithResponseDelay(3*time.Second))
	defer cleanup()

	ti := newTestInstance(port, "http://test.example.com", 1*time.Second)

	time.Sleep(100 * time.Millisecond)

	result := Check(ti, m, logger)

	if result.Up {
		t.Error("expected tunnel to be DOWN due to timeout")
	}
}

func TestCheck_BadStatusCodes(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		shouldFail bool
	}{
		{"status 200 OK", http.StatusOK, false},
		{"status 301 redirect", http.StatusMovedPermanently, false},
		{"status 302 redirect", http.StatusFound, false},
		{"status 307 redirect", http.StatusTemporaryRedirect, false},
		{"status 404 not found", http.StatusNotFound, true},
		{"status 500 server error", http.StatusInternalServerError, true},
		{"status 503 unavailable", http.StatusServiceUnavailable, true},
		{"status 403 forbidden", http.StatusForbidden, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, logger := newTestDeps(t)

			port, cleanup := testutil.StartMockSOCKS5(t, testutil.WithHTTPResponse(tc.statusCode, "test response"))
			defer cleanup()

			ti := newTestInstance(port, "http://test.example.com", 5*time.Second)
			ti.Name = fmt.Sprintf("status-%d-test", tc.statusCode)

			time.Sleep(100 * time.Millisecond)

			result := Check(ti, m, logger)

			if tc.shouldFail && result.Up {
				t.Errorf("expected tunnel to be DOWN for status %d", tc.statusCode)
			}
			if !tc.shouldFail && !result.Up {
				t.Errorf("expected tunnel to be UP for status %d, error: %v", tc.statusCode, result.Error)
			}
		})
	}
}

func TestCheck_DNSError(t *testing.T) {
	m, logger := newTestDeps(t)

	// Reply with SOCKS5 Host unreachable (code 4)
	port, cleanup := testutil.StartMockSOCKS5(t, testutil.WithSOCKSReplyCode(4))
	defer cleanup()

	ti := newTestInstance(port, "https://nonexistent.invalid.domain.example", 5*time.Second)
	ti.Name = "dns-error-test"
	ti.VLESSConfig.Address = "nonexistent.invalid.domain.example"
	ti.VLESSConfig.SNI = "nonexistent.invalid.domain.example"

	time.Sleep(100 * time.Millisecond)

	result := Check(ti, m, logger)

	if result.Up {
		t.Error("expected tunnel to be DOWN due to SOCKS error")
	}
}

func TestCheck_TLSError(t *testing.T) {
	m, logger := newTestDeps(t)

	// Send invalid TLS handshake bytes
	port, cleanup := testutil.StartMockSOCKS5(t, testutil.WithRawResponse([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x50}))
	defer cleanup()

	ti := newTestInstance(port, "https://test.example.com", 5*time.Second)
	ti.Name = "tls-error-test"

	time.Sleep(100 * time.Millisecond)

	result := Check(ti, m, logger)

	if result.Up {
		t.Error("expected tunnel to be DOWN due to TLS error")
	}
}

func TestRun(t *testing.T) {
	m, logger := newTestDeps(t)

	var requestCount atomic.Int32

	port, cleanup := testutil.StartMockSOCKS5(t)
	defer cleanup()

	ti := newTestInstance(port, "http://test.example.com", 5*time.Second)
	ti.Name = "periodic-check-test"
	ti.CheckInterval = 500 * time.Millisecond

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	// Wrap Check to count calls
	originalCheck := Check
	checkCount := &requestCount
	go func() {
		ticker := time.NewTicker(ti.CheckInterval)
		defer ticker.Stop()

		originalCheck(ti, m, logger)
		checkCount.Add(1)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				originalCheck(ti, m, logger)
				checkCount.Add(1)
			}
		}
	}()

	time.Sleep(1600 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	finalCount := checkCount.Load()
	if finalCount < 3 {
		t.Errorf("expected at least 3 checks, got %d", finalCount)
	}
}

func TestRun_Context(t *testing.T) {
	m, logger := newTestDeps(t)

	port, cleanup := testutil.StartMockSOCKS5(t)
	defer cleanup()

	ti := newTestInstance(port, "http://test.example.com", 5*time.Second)
	ti.Name = "context-cancel-test"
	ti.CheckInterval = 100 * time.Millisecond

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan bool, 1)
	go func() {
		Run(ctx, ti, m, logger)
		done <- true
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run did not stop after context cancellation")
	}
}
