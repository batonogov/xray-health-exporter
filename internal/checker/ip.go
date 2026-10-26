package checker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	realIPCacheTTL     = 5 * time.Minute
	maxIPResponseBytes = 256
)

type cachedIP struct {
	ip      netip.Addr
	expires time.Time
	done    chan struct{}
	err     error
}

func (dc *DefaultChecker) clock() time.Time {
	if dc.now != nil {
		return dc.now()
	}
	return time.Now()
}

// hostIP coalesces concurrent lookups for one endpoint without blocking other
// endpoints. Expired and failed lookups never provide a stale fallback.
func (dc *DefaultChecker) hostIP(ctx context.Context, endpoint string) (netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	dc.mu.Lock()
	if dc.ips == nil {
		dc.ips = make(map[string]*cachedIP)
	}
	if entry := dc.ips[endpoint]; entry != nil {
		if entry.done != nil {
			dc.mu.Unlock()
			select {
			case <-ctx.Done():
				return netip.Addr{}, ctx.Err()
			case <-entry.done:
				return entry.ip, entry.err
			}
		}
		if dc.clock().Before(entry.expires) {
			dc.mu.Unlock()
			return entry.ip, nil
		}
	}
	entry := &cachedIP{done: make(chan struct{})}
	dc.ips[endpoint] = entry
	dc.mu.Unlock()
	resolve := dc.resolveIP
	if resolve == nil {
		resolve = resolveRealIP
	}
	ip, err := resolve(ctx, endpoint)
	// Resolver failures are shared with current waiters but not cached for later checks.
	dc.mu.Lock()
	entry.ip, entry.err = ip, err
	entry.expires = dc.clock().Add(realIPCacheTTL)
	done := entry.done
	if err != nil {
		delete(dc.ips, endpoint)
	} else {
		dc.ips[endpoint] = &cachedIP{ip: ip, expires: entry.expires}
	}
	close(done)
	dc.mu.Unlock()
	return ip, err
}

func parseIP(body string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(body))
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("response must contain one plain-text IP address")
	}
	return ip.Unmap(), nil
}

func readIPResponse(body io.Reader) (netip.Addr, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxIPResponseBytes+1))
	if err != nil {
		return netip.Addr{}, err
	}
	if len(data) > maxIPResponseBytes {
		return netip.Addr{}, fmt.Errorf("IP response exceeds %d bytes", maxIPResponseBytes)
	}
	return parseIP(string(data))
}

// ResolveRealIP retrieves and validates the host's address directly, bypassing
// HTTP_PROXY/HTTPS_PROXY. The caller's deadline and a 30-second cap both apply.
// It does not cache; DefaultChecker caches successful responses per endpoint.
func ResolveRealIP(ctx context.Context, endpoint string) (string, error) {
	ip, err := resolveRealIP(ctx, endpoint)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

func resolveRealIP(ctx context.Context, endpoint string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("ip check returned bad status: %d", resp.StatusCode)
	}
	return readIPResponse(resp.Body)
}
