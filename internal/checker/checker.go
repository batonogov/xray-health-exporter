// Package checker provides the default health-checker implementation that
// performs real SOCKS5 HTTP health-checks against tunnel instances.
package checker

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/socks"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

// DefaultChecker is the production HealthChecker that performs real SOCKS5
// HTTP health-checks.
type DefaultChecker struct{}

// Check performs a single health-check on a tunnel instance and returns a
// tunnel.CheckResult.
func (DefaultChecker) Check(ti *tunnel.TunnelInstance) tunnel.CheckResult {
	return PerformCheck(ti)
}

// PerformCheck performs a single health-check on a tunnel instance and returns
// a CheckResult. It does NOT update Prometheus metrics or log results — that
// is the caller's responsibility.
//
// The CheckResult contract:
//   - Up==true  => tunnel is reachable with an acceptable HTTP status.
//     Err may be non-nil when the body could not be fully read (partial success).
//   - Up==false => tunnel is down; Err describes the reason.
func PerformCheck(ti *tunnel.TunnelInstance) tunnel.CheckResult {
	start := time.Now()

	socksProxy := fmt.Sprintf("127.0.0.1:%d", ti.SocksPort)

	// Check that the SOCKS5 proxy port is reachable
	conn, err := net.DialTimeout("tcp", socksProxy, min(metrics.SocksDialTimeout, ti.CheckTimeout))
	if err != nil {
		return tunnel.CheckResult{Up: false, Err: err}
	}
	conn.Close()

	dialer := socks.NewSOCKS5Dialer(socksProxy, ti.CheckTimeout)

	client := &http.Client{
		Timeout: ti.CheckTimeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get(ti.CheckURL)
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
	_, bodyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	duration := time.Since(start)
	return tunnel.CheckResult{
		Up:         true,
		Latency:    duration,
		HTTPStatus: resp.StatusCode,
		Err:        bodyErr,
	}
}
