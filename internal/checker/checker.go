// Package checker provides the default health-checker implementation that
// performs real SOCKS5 HTTP health-checks against tunnel instances.
//
// Three check methods are supported (configurable per tunnel via check_method):
//   - "http" (default): GET the check_url and expect status 200, 301, 302,
//     or 307.
//   - "ip": GET an IP-echo service through the proxy and compare the returned
//     IP with the host's public IP obtained directly from the same endpoint.
//     Direct results are cached per endpoint for five minutes. The check
//     passes only when both responses are valid, different IP addresses.
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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/socks"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

// DefaultChecker performs SOCKS5 HTTP health checks and caches direct IP
// lookups per endpoint. Its zero value is ready to use; do not copy it after use.
type DefaultChecker struct {
	mu        sync.Mutex
	ips       map[string]*cachedIP
	now       func() time.Time
	resolveIP func(context.Context, string) (netip.Addr, error)
}

// NewDefaultChecker creates a checker. A legacy pre-resolved address, when
// provided, seeds only the built-in IP endpoint for one cache TTL. Pass an empty
// string for lazy resolution using each tunnel's effective ip_check_url.
func NewDefaultChecker(realIP string) *DefaultChecker {
	dc := &DefaultChecker{}
	if ip, err := parseIP(realIP); err == nil {
		dc.ips = map[string]*cachedIP{metrics.DefaultIPCheckURL: {ip: ip, expires: time.Now().Add(realIPCacheTTL)}}
	}
	return dc
}

// Check dispatches the health-check to the method configured on the tunnel
// instance (http, ip, or download). The default is http for backward
// compatibility.
func (dc *DefaultChecker) Check(ti *tunnel.TunnelInstance) tunnel.CheckResult {
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

// checkByIP validates and compares canonical direct/proxied IP addresses. The
// complete check, including a direct cache miss, shares one timeout budget.
func (dc *DefaultChecker) checkByIP(ti *tunnel.TunnelInstance) tunnel.CheckResult {
	timeout := ti.CheckTimeout
	if timeout <= 0 {
		timeout = metrics.DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	endpoint := ti.IPCheckURL
	if endpoint == "" {
		endpoint = metrics.DefaultIPCheckURL
	}
	realIP, err := dc.hostIP(ctx, endpoint)
	if err != nil {
		return tunnel.CheckResult{Err: fmt.Errorf("failed to resolve real IP: %w", err)}
	}
	if err := ctx.Err(); err != nil {
		return tunnel.CheckResult{Err: err}
	}
	start := time.Now()
	deadline, _ := ctx.Deadline()
	client, err := newSOCKSClient(ti, time.Until(deadline))
	if err != nil {
		return tunnel.CheckResult{Err: err}
	}
	req, ttfbNanos, err := ttfbRequest(ctx, start, endpoint)
	if err != nil {
		return tunnel.CheckResult{Err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return tunnel.CheckResult{Err: err}
	}
	defer resp.Body.Close()
	result := tunnel.CheckResult{HTTPStatus: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		result.Err = fmt.Errorf("ip check returned bad status: %d", resp.StatusCode)
		return result
	}
	proxyIP, err := readIPResponse(resp.Body)
	if err != nil {
		result.Err = fmt.Errorf("invalid proxy IP response: %w", err)
		return result
	}
	if proxyIP == realIP {
		result.Err = fmt.Errorf("proxy IP (%s) matches real IP — traffic may share the host's egress", proxyIP)
		return result
	}
	result.Up = true
	result.Latency = resolveLatency(ttfbNanos, start)
	return result
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
