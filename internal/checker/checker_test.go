package checker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

func TestCheckTunnel(t *testing.T) {
	ts := httptest.NewServer(httptestHandler())
	defer ts.Close()

	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
		c.Write([]byte(httpResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "test-tunnel",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      ts.URL,
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	result := PerformCheck(ti)
	if !result.Up {
		t.Errorf("expected tunnel to be up, got error: %v", result.Err)
	}
	if result.HTTPStatus != 200 {
		t.Errorf("expected HTTP 200, got %d", result.HTTPStatus)
	}
}

func TestCheckTunnel_Timeout(t *testing.T) {
	ts := httptest.NewServer(httptestHandlerSlow(3 * time.Second))
	defer ts.Close()

	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		time.Sleep(3 * time.Second)
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "timeout-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      ts.URL,
		CheckTimeout:  1 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)
	result := PerformCheck(ti)
	if result.Up {
		t.Error("expected tunnel to be down due to timeout")
	}
}

func TestCheckTunnel_BadStatusCodes(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		shouldFail bool
	}{
		{"status 200 OK", 200, false},
		{"status 301 redirect", 301, false},
		{"status 302 redirect", 302, false},
		{"status 307 redirect", 307, false},
		{"status 404 not found", 404, true},
		{"status 500 server error", 500, true},
		{"status 503 unavailable", 503, true},
		{"status 403 forbidden", 403, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(httptestHandlerStatus(tc.statusCode))
			defer ts.Close()

			socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				buf := make([]byte, 4096)
				c.Read(buf)
				httpResponse := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 13\r\n\r\ntest response",
					tc.statusCode, http.StatusText(tc.statusCode))
				c.Write([]byte(httpResponse))
			})
			defer socksListener.Close()

			ti := &tunnel.TunnelInstance{
				Name: fmt.Sprintf("status-%d-test", tc.statusCode),
				MetricLabels: tunnel.MetricLabels{
					Server:   "test.example.com:443",
					Security: "tls",
					SNI:      "test.example.com",
				},
				SocksPort:     socksPort,
				CheckURL:      ts.URL,
				CheckTimeout:  5 * time.Second,
				CheckInterval: 30 * time.Second,
			}

			time.Sleep(100 * time.Millisecond)
			result := PerformCheck(ti)

			if tc.shouldFail && result.Up {
				t.Errorf("expected failure for status %d", tc.statusCode)
			}
			if !tc.shouldFail && !result.Up {
				t.Errorf("expected success for status %d, got error: %v", tc.statusCode, result.Err)
			}
		})
	}
}

func TestCheckTunnel_DNSError(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "dns-error-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "nonexistent.invalid.domain.example:443",
			Security: "tls",
			SNI:      "nonexistent.invalid.domain.example",
		},
		SocksPort:     socksPort,
		CheckURL:      "https://nonexistent.invalid.domain.example",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)
	result := PerformCheck(ti)
	if result.Up {
		t.Error("expected tunnel to be down due to DNS error")
	}
}

func TestCheckTunnel_TLSError(t *testing.T) {
	ts := httptest.NewServer(httptestHandlerStatus(200))
	defer ts.Close()

	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		c.Write([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x50})
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "tls-error-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      "https://test.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)
	result := PerformCheck(ti)
	if result.Up {
		t.Error("expected tunnel to be down due to TLS error")
	}
}

func TestCheckTunnel_SOCKSNotReachable(t *testing.T) {
	ti := &tunnel.TunnelInstance{
		Name: "socks-unreachable",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.com:443",
			Security: "tls",
			SNI:      "test.com",
		},
		SocksPort:     59998,
		CheckURL:      "https://example.com",
		CheckTimeout:  1 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	result := PerformCheck(ti)
	if result.Up {
		t.Error("expected tunnel to be down")
	}
}

func TestCheckTunnel_BodyReadError(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\nsmall"
		c.Write([]byte(httpResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "body-read-error",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      "http://test.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)
	result := PerformCheck(ti)
	// Body read error but tunnel is still up (partial success)
	if !result.Up {
		t.Errorf("expected tunnel to be up (partial success), got error: %v", result.Err)
	}
}

func TestCheckTunnel_BodyReadSuccess(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
		c.Write([]byte(httpResponse))
		time.Sleep(200 * time.Millisecond)
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "body-read-ok",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      "http://test.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)
	result := PerformCheck(ti)
	if !result.Up {
		t.Errorf("expected tunnel to be up, got error: %v", result.Err)
	}
	if result.Err != nil {
		t.Errorf("expected no body read error, got: %v", result.Err)
	}
}

func TestRunTunnelChecker_BackoffOnFailures(t *testing.T) {
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksListener.Addr().String())
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &tunnel.TunnelInstance{
		Name: "backoff-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:         socksPort,
		CheckURL:          "http://test.example.com",
		CheckTimeout:      1 * time.Second,
		CheckInterval:     200 * time.Millisecond,
		MaxBackoff:        2 * time.Second,
		BackoffMultiplier: 2.0,
	}

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		tunnel.RunTunnelChecker(ctx, ti, DefaultChecker{}, tunnel.NewPrometheusMetrics())
	}()

	time.Sleep(3500 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunTunnelChecker did not stop after context cancellation")
	}
}

func TestRunTunnelChecker_BackoffResetsOnSuccess(t *testing.T) {
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	var checkCount int32

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				atomic.AddInt32(&checkCount, 1)

				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksListener.Addr().String())
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &tunnel.TunnelInstance{
		Name: "backoff-reset-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:         socksPort,
		CheckURL:          "http://test.example.com",
		CheckTimeout:      1 * time.Second,
		CheckInterval:     200 * time.Millisecond,
		MaxBackoff:        10 * time.Second,
		BackoffMultiplier: 2.0,
	}

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		tunnel.RunTunnelChecker(ctx, ti, DefaultChecker{}, tunnel.NewPrometheusMetrics())
	}()

	time.Sleep(1200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunTunnelChecker did not stop after context cancellation")
	}

	count := atomic.LoadInt32(&checkCount)
	if count < 4 {
		t.Errorf("expected at least 4 checks with fast interval, got %d", count)
	}
}

func TestRunTunnelChecker(t *testing.T) {
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	var requestCount int32

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				atomic.AddInt32(&requestCount, 1)

				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksListener.Addr().String())
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &tunnel.TunnelInstance{
		Name: "periodic-check-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      "http://test.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 500 * time.Millisecond,
	}

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	go tunnel.RunTunnelChecker(ctx, ti, DefaultChecker{}, tunnel.NewPrometheusMetrics())

	time.Sleep(1600 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	finalCount := atomic.LoadInt32(&requestCount)
	if finalCount < 3 {
		t.Errorf("expected at least 3 checks, got %d", finalCount)
	}
}

func TestRunTunnelChecker_Context(t *testing.T) {
	ts := httptest.NewServer(httptestHandler())
	defer ts.Close()

	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksListener.Addr().String())
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &tunnel.TunnelInstance{
		Name: "context-cancel-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      ts.URL,
		CheckTimeout:  5 * time.Second,
		CheckInterval: 100 * time.Millisecond,
	}

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)

	go func() {
		tunnel.RunTunnelChecker(ctx, ti, DefaultChecker{}, tunnel.NewPrometheusMetrics())
		done <- true
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("RunTunnelChecker did not stop after context cancellation")
	}
}

func TestRunTunnelChecker_ImmediateCancel(t *testing.T) {
	ti := &tunnel.TunnelInstance{
		Name: "cancel-before-check",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.com:443",
			Security: "tls",
			SNI:      "test.com",
		},
		SocksPort:     59997,
		CheckURL:      "http://test.com",
		CheckTimeout:  1 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		tunnel.RunTunnelChecker(ctx, ti, DefaultChecker{}, tunnel.NewPrometheusMetrics())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunTunnelChecker should exit immediately on cancelled context")
	}
}

func TestConcurrentCheckTunnel(t *testing.T) {
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)
				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksListener.Addr().String())
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &tunnel.TunnelInstance{
		Name: "concurrent-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.com:443",
			Security: "tls",
			SNI:      "test.com",
		},
		SocksPort:     socksPort,
		CheckURL:      "http://test.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			PerformCheck(ti)
		}()
	}
	wg.Wait()
}

func TestPerformCheck_TTFBLatency(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
		c.Write([]byte(httpResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "ttfb-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      "http://test.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	result := PerformCheck(ti)
	if !result.Up {
		t.Fatalf("expected tunnel to be up, got error: %v", result.Err)
	}
	if result.HTTPStatus != 200 {
		t.Errorf("expected HTTP 200, got %d", result.HTTPStatus)
	}
	// Latency is now measured as TTFB; it must be captured and positive.
	if result.Latency <= 0 {
		t.Errorf("expected positive TTFB latency, got %v", result.Latency)
	}
}

// Benchmarks

func BenchmarkCheckTunnel(b *testing.B) {
	b.ReportAllocs()

	ts := httptest.NewServer(httptestHandler())
	defer ts.Close()

	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)
				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksListener.Addr().String())
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &tunnel.TunnelInstance{
		Name: "bench-tunnel",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      ts.URL,
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PerformCheck(ti)
	}
}

// Helper functions

func httptestHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}
}

func httptestHandlerSlow(delay time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}
}

func httptestHandlerStatus(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte("test response"))
	}
}

func startMockSOCKS(t *testing.T, afterConnect func(net.Conn)) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				afterConnect(c)
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	return listener, port
}

// --- Tests for check_method: ip (issue #114) ---

func TestCheckByIP_Success(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		// Proxy returns a DIFFERENT IP than the real IP.
		ipResponse := "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n203.0.113.5\n"
		c.Write([]byte(ipResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "ip-test-ok",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckMethod:   "ip",
		IPCheckURL:    "http://ip.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	checker := NewDefaultChecker("192.168.1.1")
	result := checker.Check(ti)
	if !result.Up {
		t.Errorf("expected tunnel up (different IP), got error: %v", result.Err)
	}
	if result.HTTPStatus != 200 {
		t.Errorf("expected HTTP 200, got %d", result.HTTPStatus)
	}
}

func TestCheckByIP_SameIP(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		// Proxy returns the SAME IP as the real IP.
		ipResponse := "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n192.168.1.1\n"
		c.Write([]byte(ipResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "ip-test-same",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckMethod:   "ip",
		IPCheckURL:    "http://ip.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	checker := NewDefaultChecker("192.168.1.1")
	result := checker.Check(ti)
	if result.Up {
		t.Error("expected tunnel down (proxy IP matches real IP)")
	}
}

func TestCheckByIP_BadStatus(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		ipResponse := "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
		c.Write([]byte(ipResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "ip-test-bad-status",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckMethod:   "ip",
		IPCheckURL:    "http://ip.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	checker := NewDefaultChecker("192.168.1.1")
	result := checker.Check(ti)
	if result.Up {
		t.Error("expected tunnel down due to bad status")
	}
}

// --- Tests for check_method: download (issue #114) ---

func TestCheckByDownload_Success(t *testing.T) {
	data := strings.Repeat("A", 60000)
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		httpResponse := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(data), data)
		c.Write([]byte(httpResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "download-test-ok",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:       socksPort,
		CheckMethod:     "download",
		DownloadURL:     "http://download.example.com",
		DownloadTimeout: 10 * time.Second,
		DownloadMinSize: 51200,
		CheckTimeout:    5 * time.Second,
		CheckInterval:   30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	checker := NewDefaultChecker("")
	result := checker.Check(ti)
	if !result.Up {
		t.Errorf("expected tunnel up (enough bytes), got error: %v", result.Err)
	}
}

func TestCheckByDownload_TooFewBytes(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nshort"
		c.Write([]byte(httpResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "download-test-few",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:       socksPort,
		CheckMethod:     "download",
		DownloadURL:     "http://download.example.com",
		DownloadTimeout: 10 * time.Second,
		DownloadMinSize: 51200,
		CheckTimeout:    5 * time.Second,
		CheckInterval:   30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	checker := NewDefaultChecker("")
	result := checker.Check(ti)
	if result.Up {
		t.Error("expected tunnel down (too few bytes)")
	}
}

func TestCheckByDownload_BadStatus(t *testing.T) {
	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		httpResponse := "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
		c.Write([]byte(httpResponse))
	})
	defer socksListener.Close()

	ti := &tunnel.TunnelInstance{
		Name: "download-test-bad-status",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:       socksPort,
		CheckMethod:     "download",
		DownloadURL:     "http://download.example.com",
		DownloadTimeout: 10 * time.Second,
		DownloadMinSize: 51200,
		CheckTimeout:    5 * time.Second,
		CheckInterval:   30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	checker := NewDefaultChecker("")
	result := checker.Check(ti)
	if result.Up {
		t.Error("expected tunnel down due to bad status")
	}
}

// --- Tests for ResolveRealIP ---

func TestResolveRealIP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("203.0.113.42\n"))
	}))
	defer ts.Close()

	ip, err := ResolveRealIP(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("ResolveRealIP error: %v", err)
	}
	if ip != "203.0.113.42" {
		t.Errorf("got IP %q, want 203.0.113.42", ip)
	}
}

func TestResolveRealIP_BadStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, err := ResolveRealIP(context.Background(), ts.URL)
	if err == nil {
		t.Error("expected error for bad status")
	}
}

func TestResolveRealIP_Unreachable(t *testing.T) {
	_, err := ResolveRealIP(context.Background(), "http://127.0.0.1:0/nope")
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

// --- Test for Check routing (default = http) ---

func TestCheck_DefaultMethodIsHTTP(t *testing.T) {
	ts := httptest.NewServer(httptestHandler())
	defer ts.Close()

	socksListener, socksPort := startMockSOCKS(t, func(c net.Conn) {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 4096)
		c.Read(buf)
		httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
		c.Write([]byte(httpResponse))
	})
	defer socksListener.Close()

	// CheckMethod is empty — should default to http.
	ti := &tunnel.TunnelInstance{
		Name: "default-method-test",
		MetricLabels: tunnel.MetricLabels{
			Server:   "test.example.com:443",
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      ts.URL,
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	checker := NewDefaultChecker("")
	result := checker.Check(ti)
	if !result.Up {
		t.Errorf("expected tunnel up via default http method, got error: %v", result.Err)
	}
}
