package checker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

func ipResponseSOCKS(t *testing.T, respond func(net.Conn, *http.Request)) int {
	t.Helper()
	listener, port := startMockSOCKS(t, func(c net.Conn) {
		if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		} // The initial SOCKS reachability probe sends no request.
		defer req.Body.Close()
		respond(c, req)
	})
	t.Cleanup(func() { _ = listener.Close() })
	return port
}

func TestIPCheckCanonicalComparisonAndInvalidProxyResponses(t *testing.T) {
	for _, tc := range []struct {
		name, direct, proxy string
		up                  bool
		truncated           bool
	}{
		{"different-ipv4", "192.0.2.1", "198.51.100.2", true, false},
		{"same-ipv4", "192.0.2.1", "192.0.2.1", false, false},
		{"mapped-proxy", "192.0.2.1", "::ffff:192.0.2.1", false, false},
		{"mapped-direct", "::ffff:c000:201", "192.0.2.1", false, false},
		{"same-ipv6", "2001:db8::a", "2001:0DB8:0000:0000:0000:0000:0000:000A", false, false},
		{"different-ipv6", "2001:db8::a", "2001:db8::b", true, false},
		{"whitespace", " 192.0.2.1\n", "\t198.51.100.2\r\n", true, false},
		{"empty", "192.0.2.1", "", false, false},
		{"whitespace-only", "192.0.2.1", " \r\n", false, false},
		{"html", "192.0.2.1", "<html>198.51.100.2</html>", false, false},
		{"json", "192.0.2.1", `{"ip":"198.51.100.2"}`, false, false},
		{"invalid", "192.0.2.1", "999.0.0.1", false, false},
		{"multiple", "192.0.2.1", "198.51.100.2\n198.51.100.3", false, false},
		{"zone", "192.0.2.1", "fe80::1%en0", false, false},
		{"oversized", "192.0.2.1", "198.51.100.2" + strings.Repeat(" ", 256), false, false},
		{"truncated-valid-prefix", "192.0.2.1", "198.51.100.2", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.direct) }))
			defer direct.Close()
			port := ipResponseSOCKS(t, func(c net.Conn, r *http.Request) {
				length := len(tc.proxy)
				if tc.truncated {
					length++
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", length, tc.proxy)
			})
			result := NewDefaultChecker("").Check(&tunnel.TunnelInstance{SocksPort: port, CheckMethod: "ip", IPCheckURL: direct.URL, CheckTimeout: time.Second})
			if result.Up != tc.up || (result.Err == nil) != tc.up {
				t.Fatalf("result=%+v, want up=%v", result, tc.up)
			}
			if result.HTTPStatus != 200 {
				t.Fatalf("lost HTTP status: %+v", result)
			}
		})
	}
}

func TestResolveRealIPValidatesEntireResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		truncated        bool
	}{
		{"ipv4", "192.0.2.1\n", "192.0.2.1", false},
		{"ipv6", "2001:0DB8:0:0:0:0:0:1", "2001:db8::1", false},
		{"mapped", "::ffff:c000:201", "192.0.2.1", false},
		{"empty", "", "", false}, {"html", "<html>blocked</html>", "", false},
		{"json", `{"ip":"192.0.2.1"}`, "", false},
		{"zone", "fe80::1%eth0", "", false},
		{"multiple", "192.0.2.1 198.51.100.1", "", false},
		{"oversized", "192.0.2.1" + strings.Repeat(" ", 256), "", false},
		{"truncated", "192.0.2.1", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				size := len(tc.body)
				if tc.truncated {
					size++
				}
				w.Header().Set("Content-Length", fmt.Sprint(size))
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			got, err := ResolveRealIP(context.Background(), server.URL)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("accepted invalid response %q as %q", tc.body, got)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestIPCheckUsesEffectiveYAMLEndpoint(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(fmt.Sprintf("tunnel-override-%v", override), func(t *testing.T) {
			var directCalls atomic.Int32
			direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				directCalls.Add(1)
				if r.URL.Path != "/configured" || r.URL.RawQuery != "format=text" {
					t.Errorf("wrong direct endpoint: %s", r.URL)
				}
				fmt.Fprintln(w, "192.0.2.1")
			}))
			defer direct.Close()
			endpoint := direct.URL + "/configured?format=text"
			defaultEndpoint := endpoint
			if override {
				defaultEndpoint = "http://127.0.0.1:1/wrong-yaml-default"
			}
			text := fmt.Sprintf("defaults:\n  check_method: ip\n  ip_check_url: %s\ntunnels:\n  - name: test\n    url: vless://id@example.com:443\n", defaultEndpoint)
			if override {
				text += fmt.Sprintf("    ip_check_url: %s\n", endpoint)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("IP_CHECK_URL", "http://127.0.0.1:1/wrong-env-default")
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			port := ipResponseSOCKS(t, func(c net.Conn, r *http.Request) {
				if r.URL.Path != "/configured" || r.URL.RawQuery != "format=text" {
					t.Errorf("wrong proxied endpoint: %s", r.URL)
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n198.51.100.2")
			})
			dc := NewDefaultChecker("")
			result := dc.Check(&tunnel.TunnelInstance{SocksPort: port, CheckMethod: cfg.Tunnels[0].CheckMethod, IPCheckURL: cfg.Tunnels[0].IPCheckURL, CheckTimeout: time.Second})
			if !result.Up || directCalls.Load() != 1 {
				t.Fatalf("result=%+v calls=%d", result, directCalls.Load())
			}
		})
	}
}

func TestHostIPCacheTTLAndFailure(t *testing.T) {
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	var calls atomic.Int32
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := calls.Add(1)
		if fail.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		fmt.Fprintf(w, "192.0.2.%d", count)
	}))
	defer server.Close()
	dc := &DefaultChecker{now: func() time.Time { return time.Unix(0, now.Load()) }}
	get := func(want string) {
		t.Helper()
		got, err := dc.hostIP(context.Background(), server.URL)
		if err != nil || got.String() != want {
			t.Fatalf("got %v, %v; want %s", got, err, want)
		}
	}
	get("192.0.2.1")
	get("192.0.2.1")
	now.Add(int64(realIPCacheTTL - time.Nanosecond))
	get("192.0.2.1")
	now.Add(1)
	get("192.0.2.2")
	fail.Store(true)
	now.Add(int64(realIPCacheTTL))
	if ip, err := dc.hostIP(context.Background(), server.URL); err == nil || ip.IsValid() {
		t.Fatalf("stale cache served after failure: %v, %v", ip, err)
	}
	fail.Store(false)
	get("192.0.2.4")
	if calls.Load() != 4 {
		t.Fatalf("unexpected lookups: %d", calls.Load())
	}
}

func TestHostIPConcurrentLookupsAndIndependentEndpoints(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	dc := &DefaultChecker{resolveIP: func(ctx context.Context, endpoint string) (netip.Addr, error) {
		calls.Add(1)
		if endpoint == "slow" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return netip.Addr{}, ctx.Err()
			}
		}
		return netip.MustParseAddr("192.0.2.1"), nil
	}}
	var wg sync.WaitGroup
	const workers = 24
	errs := make(chan error, workers)
	wg.Add(1)
	go func() { defer wg.Done(); _, err := dc.hostIP(context.Background(), "slow"); errs <- err }()
	<-entered
	for range workers - 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := dc.hostIP(context.Background(), "slow")
			if err == nil && ip.String() != "192.0.2.1" {
				err = fmt.Errorf("wrong IP %v", ip)
			}
			errs <- err
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := dc.hostIP(ctx, "other"); err != nil {
		t.Fatalf("unrelated endpoint blocked: %v", err)
	}
	canceled, cancelWait := context.WithCancel(context.Background())
	cancelWait()
	if _, err := dc.hostIP(canceled, "slow"); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter cancellation: %v", err)
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("got %d direct lookups, want one per endpoint", calls.Load())
	}
}

func TestHostIPWaitingCallerDeadline(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	dc := &DefaultChecker{resolveIP: func(ctx context.Context, endpoint string) (netip.Addr, error) {
		close(entered)
		<-release
		return netip.MustParseAddr("192.0.2.1"), nil
	}}
	ownerDone := make(chan struct{})
	go func() { defer close(ownerDone); _, _ = dc.hostIP(context.Background(), "endpoint") }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := dc.hostIP(ctx, "endpoint")
	close(release)
	<-ownerDone
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting caller ignored own deadline: %v", err)
	}
}

func TestIPCheckTimeoutCoversDirectAndProxy(t *testing.T) {
	for _, phase := range []string{"direct-headers", "direct-body", "proxy-headers", "proxy-body"} {
		t.Run(phase, func(t *testing.T) {
			direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(phase, "direct") {
					if phase == "direct-body" {
						w.Header().Set("Content-Length", "100")
						fmt.Fprint(w, "192.0.2.1")
						w.(http.Flusher).Flush()
					}
					<-r.Context().Done()
					return
				}
				fmt.Fprint(w, "192.0.2.1")
			}))
			defer direct.Close()
			port := ipResponseSOCKS(t, func(c net.Conn, r *http.Request) {
				if phase == "proxy-body" {
					fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n198.51.100.2")
				}
				_, _ = io.Copy(io.Discard, c) // Exit when the check's deadline closes the client.
			})
			start := time.Now()
			result := NewDefaultChecker("").Check(&tunnel.TunnelInstance{SocksPort: port, CheckMethod: "ip", IPCheckURL: direct.URL, CheckTimeout: 80 * time.Millisecond})
			if result.Up || result.Err == nil {
				t.Fatalf("timeout accepted: %+v", result)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("check ignored timeout: %s", elapsed)
			}
			if metrics.ClassifyError(result.Err) != "timeout" {
				t.Fatalf("wrong error classification: %v", result.Err)
			}
		})
	}
}

func TestNonIPChecksDoNotResolveHostIP(t *testing.T) {
	dc := &DefaultChecker{resolveIP: func(context.Context, string) (netip.Addr, error) {
		t.Error("unexpected direct IP lookup")
		return netip.Addr{}, errors.New("unexpected lookup")
	}}
	port := ipResponseSOCKS(t, func(c net.Conn, r *http.Request) { fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK") })
	for _, method := range []string{"http", "download"} {
		result := dc.Check(&tunnel.TunnelInstance{SocksPort: port, CheckMethod: method, CheckURL: "http://example.com/", DownloadURL: "http://example.com/", CheckTimeout: time.Second, DownloadTimeout: time.Second, DownloadMinSize: 2})
		if !result.Up {
			t.Fatalf("%s check failed: %+v", method, result)
		}
	}
}

func TestLegacySeedIsLimitedToDefaultEndpoint(t *testing.T) {
	dc := NewDefaultChecker("::ffff:192.0.2.1")
	dc.resolveIP = func(context.Context, string) (netip.Addr, error) { return netip.MustParseAddr("198.51.100.1"), nil }
	got, err := dc.hostIP(context.Background(), metrics.DefaultIPCheckURL)
	if err != nil || got.String() != "192.0.2.1" {
		t.Fatalf("legacy seed: %v, %v", got, err)
	}
	got, err = dc.hostIP(context.Background(), "http://other.example/")
	if err != nil || got.String() != "198.51.100.1" {
		t.Fatalf("seed leaked across endpoints: %v, %v", got, err)
	}
	dc.now = func() time.Time { return time.Now().Add(realIPCacheTTL) }
	got, err = dc.hostIP(context.Background(), metrics.DefaultIPCheckURL)
	if err != nil || got.String() != "198.51.100.1" {
		t.Fatalf("seed did not expire: %v, %v", got, err)
	}
}

func TestIPCheckSharesTimeoutAcrossBothRequests(t *testing.T) {
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(200 * time.Millisecond):
			fmt.Fprint(w, "192.0.2.1")
		case <-r.Context().Done():
		}
	}))
	defer direct.Close()
	port := ipResponseSOCKS(t, func(c net.Conn, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n198.51.100.2")
	})
	result := NewDefaultChecker("").Check(&tunnel.TunnelInstance{SocksPort: port, CheckMethod: "ip", IPCheckURL: direct.URL, CheckTimeout: 300 * time.Millisecond})
	if result.Up || result.Err == nil || metrics.ClassifyError(result.Err) != "timeout" {
		t.Fatalf("requests received separate timeout budgets: %+v", result)
	}
}

func TestInvalidDirectIPStopsProxyCheck(t *testing.T) {
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"ip":"192.0.2.1"}`) }))
	defer direct.Close()
	var proxyCalls atomic.Int32
	port := ipResponseSOCKS(t, func(c net.Conn, r *http.Request) { proxyCalls.Add(1) })
	result := NewDefaultChecker("").Check(&tunnel.TunnelInstance{SocksPort: port, CheckMethod: "ip", IPCheckURL: direct.URL, CheckTimeout: time.Second})
	if result.Up || result.Err == nil || proxyCalls.Load() != 0 {
		t.Fatalf("invalid direct response allowed proxy comparison: %+v, calls=%d", result, proxyCalls.Load())
	}
}
