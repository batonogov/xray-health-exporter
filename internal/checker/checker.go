// Package checker provides the default health-checker implementation that
// performs real SOCKS5 HTTP health-checks against tunnel instances.
//
// Three check methods are supported (configurable per tunnel via check_method):
//   - "http" (default): GET the check_url and expect a 2xx/3xx status.
//   - "ip": GET an IP-echo service through the proxy and compare the returned
//     IP with the host's real public IP (resolved once at startup). The check
//     passes if the proxy IP differs from the real IP.
//   - "download": download from a URL through the proxy and verify that at
//     least download_min_size bytes are received.
package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/socks"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

// DefaultChecker is the production HealthChecker that performs real SOCKS5
// HTTP health-checks. The real public IP is resolved once at startup via
// ResolveRealIP and stored for ip-method checks.
type DefaultChecker struct {
	realIP string
}

// NewDefaultChecker creates a DefaultChecker with the pre-resolved real public
// IP. Pass an empty string to resolve lazily on first ip-method check.
func NewDefaultChecker(realIP string) DefaultChecker {
	return DefaultChecker{realIP: realIP}
}

// Check dispatches the health-check to the method configured on the tunnel
// instance (http, ip, or download). The default is http for backward
// compatibility.
func (dc DefaultChecker) Check(ti *tunnel.TunnelInstance) tunnel.CheckResult {
	method := ti.CheckMethod
	if method == "" {
		method = metrics.DefaultCheckMethod
	}
	switch method {
	case "ip":
		return dc.checkByIP(ti)
	case "download":
		return checkByDownload(ti)
	default:
		return PerformCheck(ti)
	}
}

// newSOCKSClient builds an HTTP client that routes through the tunnel's
// SOCKS5 proxy. It verifies the SOCKS port is reachable first.
func newSOCKSClient(ti *tunnel.TunnelInstance, timeout time.Duration) (*http.Client, error) {
	socksProxy := fmt.Sprintf("127.0.0.1:%d", ti.SocksPort)

	// Check that the SOCKS5 proxy port is reachable.
	conn, err := net.DialTimeout("tcp", socksProxy, min(metrics.SocksDialTimeout, timeout))
	if err != nil {
		return nil, err
	}
	conn.Close()

	dialer := socks.NewSOCKS5Dialer(socksProxy, timeout)

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DisableKeepAlives: true,
		},
	}, nil
}

// ttfbRequest builds a GET request instrumented with httptrace so that the
// time-to-first-byte (TTFB) can be measured. The returned *atomic.Int64 holds
// the TTFB in nanoseconds once GotFirstResponseByte fires.
func ttfbRequest(ctx context.Context, start time.Time, url string) (*http.Request, *atomic.Int64, error) {
	var ttfbNanos atomic.Int64
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			ttfbNanos.Store(time.Since(start).Nanoseconds())
		},
	}
	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		http.MethodGet, url, nil,
	)
	return req, &ttfbNanos, err
}

// resolveLatency returns the TTFB if the httptrace callback fired, otherwise
// falls back to the total elapsed time so latency stays meaningful even when
// the callback never fires (error before first byte or empty body).
func resolveLatency(ttfbNanos *atomic.Int64, start time.Time) time.Duration {
	if nanos := ttfbNanos.Load(); nanos > 0 {
		return time.Duration(nanos)
	}
	return time.Since(start)
}

// PerformCheck performs a single HTTP health-check on a tunnel instance and
// returns a CheckResult. This is the "http" method — the default check
// behaviour. It does NOT update Prometheus metrics or log results — that is
// the caller's responsibility.
//
// The CheckResult contract:
//   - Up==true  => tunnel is reachable with an acceptable HTTP status.
//     Err may be non-nil when the body could not be fully read (partial success).
//   - Up==false => tunnel is down; Err describes the reason.
func PerformCheck(ti *tunnel.TunnelInstance) tunnel.CheckResult {
	start := time.Now()

	client, err := newSOCKSClient(ti, ti.CheckTimeout)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}

	req, ttfbNanos, err := ttfbRequest(context.Background(), start, ti.CheckURL)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusTemporaryRedirect {
		return tunnel.CheckResult{
			Up:         false,
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("bad status code: %d", resp.StatusCode),
		}
	}

	// Read a small portion of the body to verify the connection is fully working.
	// This is excluded from the latency (TTFB) measurement.
	_, bodyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	return tunnel.CheckResult{
		Up:         true,
		Latency:    resolveLatency(ttfbNanos, start),
		HTTPStatus: resp.StatusCode,
		Err:        bodyErr,
	}
}

// checkByIP verifies that traffic is actually routed through the proxy by
// comparing the IP returned via the proxy against the host's real public IP.
// The check succeeds if the proxy IP differs from the real IP. If the real IP
// was not resolved at startup, it is resolved lazily on the first call.
func (dc DefaultChecker) checkByIP(ti *tunnel.TunnelInstance) tunnel.CheckResult {
	realIP := dc.realIP
	if realIP == "" {
		var err error
		realIP, err = ResolveRealIP(context.Background(), ti.IPCheckURL)
		if err != nil {
			return tunnel.CheckResult{Up: false, Err: fmt.Errorf("failed to resolve real IP: %w", err)}
		}
	}

	start := time.Now()

	client, err := newSOCKSClient(ti, ti.CheckTimeout)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}

	req, ttfbNanos, err := ttfbRequest(context.Background(), start, ti.IPCheckURL)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return tunnel.CheckResult{
			Up:         false,
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("ip check returned bad status: %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}

	proxyIP := strings.TrimSpace(string(body))

	if proxyIP == realIP {
		return tunnel.CheckResult{
			Up:         false,
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("proxy IP (%s) matches real IP — traffic is not routed through the proxy", proxyIP),
		}
	}

	return tunnel.CheckResult{
		Up:         true,
		Latency:    resolveLatency(ttfbNanos, start),
		HTTPStatus: resp.StatusCode,
	}
}

// checkByDownload verifies the tunnel by downloading from a URL through the
// proxy and checking that at least DownloadMinSize bytes are received. It uses
// a separate DownloadTimeout (typically longer than CheckTimeout).
func checkByDownload(ti *tunnel.TunnelInstance) tunnel.CheckResult {
	start := time.Now()

	client, err := newSOCKSClient(ti, ti.DownloadTimeout)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}

	req, ttfbNanos, err := ttfbRequest(context.Background(), start, ti.DownloadURL)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return tunnel.CheckResult{
			Up:         false,
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("download returned bad status: %d", resp.StatusCode),
		}
	}

	// Read until we have DownloadMinSize bytes or EOF.
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, ti.DownloadMinSize))
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}

	if n < ti.DownloadMinSize {
		return tunnel.CheckResult{
			Up:         false,
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("downloaded %d bytes, need at least %d", n, ti.DownloadMinSize),
		}
	}

	return tunnel.CheckResult{
		Up:         true,
		Latency:    resolveLatency(ttfbNanos, start),
		HTTPStatus: resp.StatusCode,
	}
}

// ResolveRealIP determines the host's real public IP by making a direct
// (non-proxy) GET request to an IP-echo service. Call once at startup; the
// result is stored in DefaultChecker for ip-method checks.
func ResolveRealIP(ctx context.Context, ipCheckURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipCheckURL, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ip check returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}
