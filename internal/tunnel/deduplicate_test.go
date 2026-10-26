package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const dedupNative = `{"outbounds":[{"protocol":"freedom"}]}`
const dedupVLESS = "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=ws&path=%2Fone"

func dedupConfig(tunnels ...config.Tunnel) *config.Config {
	cfg := &config.Config{Tunnels: tunnels}
	for i := range cfg.Tunnels {
		config.ApplyTunnelDefaults(&cfg.Tunnels[i], cfg.Defaults)
	}
	return cfg
}

func TestPrepareTunnelConfigDeduplicatesEffectiveSettings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tunnels  []config.Tunnel
		wantName string
		wantPort int
	}{
		{"identical", []config.Tunnel{{Name: "shared", URL: dedupVLESS}, {Name: "shared", URL: dedupVLESS}}, "shared", 0},
		{"query-order", []config.Tunnel{{Name: "shared", URL: dedupVLESS}, {Name: "shared", URL: "vless://00000000-0000-4000-8000-000000000001@example.com:443?path=%2Fone&type=ws&security=tls"}}, "shared", 0},
		{"equivalent-duration", []config.Tunnel{{Name: "shared", URL: dedupVLESS, CheckInterval: "60s"}, {Name: "shared", URL: dedupVLESS, CheckInterval: "1m"}}, "shared", 0},
		{"same-explicit-port", []config.Tunnel{{Name: "shared", URL: dedupVLESS, SocksPort: 12345}, {Name: "shared", URL: dedupVLESS, SocksPort: 12345}}, "shared", 12345},
		{"auto-and-explicit-port", []config.Tunnel{{Name: "shared", URL: dedupVLESS}, {Name: "shared", URL: dedupVLESS, SocksPort: 12345}}, "shared", 12345},
		{"prefer-explicit-name", []config.Tunnel{{Name: "provider-fallback", NameGenerated: true, URL: dedupVLESS}, {Name: "chosen", URL: dedupVLESS}}, "chosen", 0},
		{"retain-explicit-name", []config.Tunnel{{Name: "chosen", URL: dedupVLESS}, {Name: "provider-fallback", NameGenerated: true, URL: dedupVLESS}}, "chosen", 0},
		{"unnamed-static", []config.Tunnel{{URL: dedupVLESS}, {Name: "example.com:443", NameGenerated: true, URL: dedupVLESS}}, "example.com:443", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dedupConfig(tc.tunnels...)
			if err := prepareTunnelConfig(cfg); err != nil {
				t.Fatal(err)
			}
			if len(cfg.Tunnels) != 1 || cfg.Tunnels[0].Name != tc.wantName || cfg.Tunnels[0].SocksPort != tc.wantPort {
				t.Fatalf("unexpected normalized monitors: count=%d", len(cfg.Tunnels))
			}
		})
	}
	cfg := dedupConfig(config.Tunnel{Name: "first", URL: dedupVLESS}, config.Tunnel{Name: "second", URL: dedupVLESS})
	if err := prepareTunnelConfig(cfg); err != nil || len(cfg.Tunnels) != 2 {
		t.Fatalf("distinct explicit names merged: count=%d, error=%v", len(cfg.Tunnels), err)
	}
}

func TestPrepareTunnelConfigCanonicalNativeAndFrozenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native.json")
	if err := os.WriteFile(path, []byte(`{"remarks":"ignored","outbounds":[{"settings":{},"protocol":"freedom"}],"inbounds":[{"port":9999}],"log":{"loglevel":"debug"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := dedupConfig(
		config.Tunnel{Name: "shared", XrayConfigFile: path},
		config.Tunnel{Name: "shared", XrayConfigJSON: json.RawMessage(`{ "outbounds": [ {"protocol":"freedom", "settings":{}} ] }`)},
	)
	if err := prepareTunnelConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tunnels) != 1 || cfg.Tunnels[0].XrayConfigFile != "" || len(cfg.Tunnels[0].XrayConfigJSON) == 0 {
		t.Fatal("native input was not deduplicated and frozen")
	}
	before, err := tunnelFingerprint(cfg.Tunnels[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"outbounds":[{"protocol":"blackhole"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := tunnelFingerprint(cfg.Tunnels[0])
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("file changed between preflight and startup")
	}
	data, _, _, err := buildTunnelConfig(&cfg.Tunnels[0], 12345)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "blackhole") {
		t.Fatal("startup reread the changed file")
	}
	cfg = dedupConfig(config.Tunnel{Name: "xray-oldhash", NameGenerated: true, XrayConfigJSON: json.RawMessage(dedupNative)}, config.Tunnel{Name: "xray-newhash", NameGenerated: true, XrayConfigJSON: json.RawMessage("{\n\"outbounds\": [{\"protocol\": \"freedom\"}]} ")})
	if err := prepareTunnelConfig(cfg); err != nil || len(cfg.Tunnels) != 1 {
		t.Fatalf("equivalent generated JSON monitors not merged: %v", err)
	}
}

func TestPrepareTunnelConfigRejectsConflictsWithoutSecrets(t *testing.T) {
	base := config.Tunnel{Name: "same", URL: dedupVLESS}
	for _, tc := range []struct {
		name  string
		other config.Tunnel
	}{
		{"credentials", config.Tunnel{Name: "same", URL: strings.Replace(dedupVLESS, "00000000-0000-4000-8000-000000000001", "private-credential", 1)}},
		{"transport", config.Tunnel{Name: "same", URL: strings.Replace(dedupVLESS, "%2Fone", "%2Fprivate-route", 1)}},
		{"check-url", config.Tunnel{Name: "same", URL: dedupVLESS, CheckURL: "https://example.com/private-token"}},
		{"check-interval", config.Tunnel{Name: "same", URL: dedupVLESS, CheckInterval: "17s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dedupConfig(base, tc.other)
			err := prepareTunnelConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), "share Prometheus labels") {
				t.Fatalf("expected identity conflict, got %v", err)
			}
			for _, secret := range []string{"private-credential", "private-route", "private-token", "vless://"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error exposes %s", secret)
				}
			}
		})
	}
	for _, pair := range [][]config.Tunnel{
		{{Name: "same", URL: dedupVLESS, SocksPort: 12345}, {Name: "same", URL: dedupVLESS, SocksPort: 12346}},
		{{Name: "first", URL: dedupVLESS, SocksPort: 12345}, {Name: "second", URL: dedupVLESS, SocksPort: 12345}},
	} {
		if err := prepareTunnelConfig(dedupConfig(pair...)); err == nil {
			t.Fatal("conflicting explicit ports accepted")
		}
	}
}

type dedupCountingChecker struct{ count atomic.Int32 }

func (c *dedupCountingChecker) Check(*TunnelInstance) CheckResult {
	c.count.Add(1)
	return CheckResult{Up: true, HTTPStatus: 200}
}

func TestSubscriptionDeduplicationSharesCoreAndPreservesSourceCounts(t *testing.T) {
	metrics.CleanupSubscriptionMetrics(nil)
	defer metrics.CleanupSubscriptionMetrics(nil)
	native := `{"remarks":"shared","outbounds":[{"protocol":"freedom"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "[%s,%s]", native, native) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(two bool) {
		body := fmt.Sprintf("defaults:\n  check_interval: 1ms\nsubscriptions:\n  - name: first\n    url: %q\n", server.URL+"/first")
		if two {
			body += fmt.Sprintf("  - name: second\n    url: %q\n", server.URL+"/second")
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(true)
	checker := &dedupCountingChecker{}
	tm := NewTunnelManager(checker, NewPrometheusMetrics())
	defer func() { StopTunnels(tm.instances); CleanupRemovedTunnelMetrics(tm.instances, nil) }()
	if err := tm.reloadConfig(path); err != nil {
		t.Fatal(err)
	}
	if len(tm.instances) != 1 || tm.instances[0].XrayInstance == nil || tm.instances[0].checkerDone == nil {
		t.Fatal("duplicate cores or missing checker")
	}
	original := tm.instances[0]
	for _, name := range []string{"first", "second"} {
		if testutil.ToFloat64(metrics.SubscriptionServers.WithLabelValues(name)) != 2 {
			t.Fatal("source count was deduplicated")
		}
	}
	if testutil.ToFloat64(metrics.ExporterTunnelsConfigured) != 1 {
		t.Fatal("configured count is not unique")
	}
	write(false)
	if err := tm.reloadConfig(path); err != nil {
		t.Fatal(err)
	}
	if len(tm.instances) != 1 || tm.instances[0] != original {
		t.Fatal("removing duplicate source replaced shared core")
	}
	select {
	case <-original.checkerDone:
		t.Fatal("shared checker was stopped")
	default:
	}
	deadline := time.Now().Add(time.Second)
	for checker.count.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if checker.count.Load() == 0 {
		t.Fatal("shared checker did not run")
	}
}

func TestStaticSubscriptionDeduplicationRunOnceAndDaemon(t *testing.T) {
	native := `{"remarks":"shared","outbounds":[{"protocol":"freedom"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, native) }))
	defer server.Close()
	dir := t.TempDir()
	file := filepath.Join(dir, "native.json")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte(dedupNative), 0600); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("tunnels:\n  - name: shared\n    xray_config_file: %q\nsubscriptions:\n  - url: %q\n", file, server.URL)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	if err := tm.reloadConfig(path); err != nil {
		t.Fatal(err)
	}
	if len(tm.instances) != 1 {
		StopTunnels(tm.instances)
		t.Fatal("static/subscription duplicates not merged")
	}
	StopTunnels(tm.instances)
	CleanupRemovedTunnelMetrics(tm.instances, nil)
	checker := &dedupCountingChecker{}
	var output bytes.Buffer
	up, err := RunOnce(path, checker, NewPrometheusMetrics(), &output)
	if err != nil || !up || checker.count.Load() != 1 {
		t.Fatalf("RUN_ONCE checked %d copies: up=%v error=%v", checker.count.Load(), up, err)
	}
}

func TestConflictingLabelsRejectCandidateAndRunOnce(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "native.json")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte(dedupNative), 0600); err != nil {
		t.Fatal(err)
	}
	originalBody := fmt.Sprintf("tunnels:\n  - name: shared\n    xray_config_file: %q\n", file)
	if err := os.WriteFile(path, []byte(originalBody), 0600); err != nil {
		t.Fatal(err)
	}
	tm := NewTunnelManager(mockChecker{}, NewPrometheusMetrics())
	defer func() { StopTunnels(tm.instances); CleanupRemovedTunnelMetrics(tm.instances, nil) }()
	if err := tm.reloadConfig(path); err != nil {
		t.Fatal(err)
	}
	original := tm.instances[0]
	body := originalBody + fmt.Sprintf("  - name: shared\n    xray_config_file: %q\n    check_url: https://example.com/private-token\n", file)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	err := tm.reloadConfigContext(context.Background(), path, false)
	if err == nil || !strings.Contains(err.Error(), "share Prometheus labels") {
		t.Fatalf("candidate conflict not detected: %v", err)
	}
	if len(tm.instances) != 1 || tm.instances[0] != original {
		t.Fatal("conflict changed active core")
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", original.SocksPort), time.Second)
	if err != nil {
		t.Fatal("old core stopped")
	}
	conn.Close()
	checker := &dedupCountingChecker{}
	up, err := RunOnce(path, checker, NewPrometheusMetrics(), &bytes.Buffer{})
	if err == nil || up || checker.count.Load() != 0 {
		t.Fatal("RUN_ONCE accepted conflicting identities")
	}
	if strings.Contains(err.Error(), "private-token") {
		t.Fatal("conflict error leaked secret")
	}
}
