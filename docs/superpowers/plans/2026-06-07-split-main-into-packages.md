# Split main.go into Packages — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor monolithic main.go (2003 lines) into well-structured Go packages under `internal/` and `cmd/exporter/`.

**Architecture:** Extract code into packages by responsibility: `socks`, `config`, `metrics`, `tunnel`, `checker`, `leaderelection`. The entry point moves to `cmd/exporter/main.go`. Types (`TunnelInstance`, `MetricLabels`, `CheckResult`, `VLESSConfig`) and interfaces (`HealthChecker`, `MetricsUpdater`) live in `tunnel` package. Dependency direction is strictly one-way: `cmd/exporter` → `leaderelection` → `tunnel` → `checker`/`metrics`/`config` → `socks`/`config`. No circular imports.

**Tech Stack:** Go 1.26+, existing dependencies (prometheus, xray-core, fsnotify, k8s client-go)

**Key design decisions:**
- `metrics` package: prometheus variable declarations, init(), `classifyError`, helper functions (`SetLeader`, `IncConfigReloadTotal`, etc.). Does NOT import `tunnel` — avoids circular dependency.
- `tunnel` package: all types + interfaces + manager code + xray config generation + `cleanupRemovedTunnelMetrics`. Imports `metrics`, `config`.
- `prometheusMetrics` implementation of `MetricsUpdater` lives in `cmd/exporter/main.go` (wiring layer), NOT in `metrics` package — avoids `metrics` ↔ `tunnel` cycle.
- `MetricsUpdater` interface adds `RecordError(name, ml, err)` method. `prometheusMetrics` handles `tunnelErrorTotal` incrementing via `metrics.ClassifyError()`. This preserves exact current behavior where error metrics are only tracked through `checkAndRecord`.
- `Cleanup` removed from `MetricsUpdater` interface — `cleanupRemovedTunnelMetrics` called directly from `tunnel` package (same package as TunnelManager).

---

### Task 1: Create branch and directory structure

**Files:**
- Create: `cmd/exporter/`
- Create: `internal/socks/`
- Create: `internal/config/`
- Create: `internal/metrics/`
- Create: `internal/tunnel/`
- Create: `internal/checker/`
- Create: `internal/leaderelection/`

- [ ] **Step 1: Create feature branch**

```bash
git checkout -b refactor/split-main-into-packages
```

- [ ] **Step 2: Create directory structure**

```bash
mkdir -p cmd/exporter internal/socks internal/config internal/metrics internal/tunnel internal/checker internal/leaderelection
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "chore: create package directory structure for #34"
```

---

### Task 2: Create `internal/socks/dialer.go`

**Files:**
- Create: `internal/socks/dialer.go`

This is a leaf package — no internal dependencies.

- [ ] **Step 1: Create `internal/socks/dialer.go`**

Package `socks`. Move from `main.go` lines 922–1019:
- `socks5Dialer` struct (exported: `SOCKS5Dialer`)
- `newSOCKS5Dialer` (exported: `NewSOCKS5Dialer`)
- `DialContext` method

Change `socks5Dialer` → `SOCKS5Dialer` (exported), `newSOCKS5Dialer` → `NewSOCKS5Dialer`.

```go
package socks

import (
    "context"
    "fmt"
    "net"
    "strconv"
    "time"
)

type SOCKS5Dialer struct {
    ProxyAddr string
    Timeout   time.Duration
}

func NewSOCKS5Dialer(proxyAddr string, timeout time.Duration) *SOCKS5Dialer {
    return &SOCKS5Dialer{ProxyAddr: proxyAddr, Timeout: timeout}
}

func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    // ... exact copy of current socks5Dialer.DialContext body ...
    // Replace d.proxyAddr → d.ProxyAddr, d.timeout → d.Timeout
}
```

- [ ] **Step 2: Verify new package compiles**

```bash
go build ./internal/socks/
```

- [ ] **Step 3: Commit**

```bash
git add internal/socks/ && git commit -m "refactor: extract SOCKS5 dialer into internal/socks package"
```

---

### Task 3: Create `internal/metrics/metrics.go`

**Files:**
- Create: `internal/metrics/metrics.go`

This is a leaf package — no internal dependencies. Contains only prometheus declarations, init, and helper functions.

- [ ] **Step 1: Create `internal/metrics/metrics.go`**

Package `metrics`. Move from `main.go`:
- Lines 62–167: All prometheus variable declarations (`tunnelUp`, `tunnelLatency`, `tunnelLatencyHistogram`, `tunnelCheckTotal`, `tunnelLastSuccess`, `tunnelHTTPStatus`, `tunnelErrorTotal`, `exporterLeader`, `exporterConfigReloadTotal`, `exporterConfigReloadErrorsTotal`, `exporterTunnelsConfigured`, `exporterUptimeSeconds`, `exporterBuildInfo`, `exporterStartTime`)
- Lines 169–183: `init()` function (prometheus.MustRegister calls)
- Lines 1021–1089: `errorReasons` slice + `classifyError` function

All variables and constants are exported (capital first letter). Add helper functions for code that currently directly accesses these vars from outside the package:

```go
package metrics

import (
    "errors"
    "net"
    "strings"
    "time"

    "github.com/prometheus/client_golang/prometheus"
)

// All prometheus vars (exported):
var (
    TunnelUp                = prometheus.NewGaugeVec(...)
    TunnelLatency           = prometheus.NewGaugeVec(...)
    TunnelLatencyHistogram  = prometheus.NewHistogramVec(...)
    TunnelCheckTotal        = prometheus.NewCounterVec(...)
    TunnelLastSuccess       = prometheus.NewGaugeVec(...)
    TunnelHTTPStatus        = prometheus.NewGaugeVec(...)
    TunnelErrorTotal        = prometheus.NewCounterVec(...)
    ExporterLeader          = prometheus.NewGauge(...)
    ExporterConfigReloadTotal = prometheus.NewCounter(...)
    ExporterConfigReloadErrorsTotal = prometheus.NewCounter(...)
    ExporterTunnelsConfigured = prometheus.NewGauge(...)
    ExporterBuildInfo       = prometheus.NewGaugeVec(...)
    startTime               time.Time  // unexported, set via InitStartTime
)

// Constants (exported)
const (
    DefaultListenAddr    = ":9273"
    DefaultCheckURL      = "https://www.google.com"
    DefaultTimeout       = 30 * time.Second
    DefaultSocksPort     = 1080
    DefaultCheckInterval = 30 * time.Second
    DefaultConfigFile    = "/app/config.yaml"
    DefaultMaxBackoff    = 5 * time.Minute
    DefaultBackoffMult   = 2.0
    SocksDialTimeout     = 5 * time.Second
    SocksStartupTimeout  = 10 * time.Second
)

// ErrorReasons is exported for use in cleanup
var ErrorReasons = []string{...}

func init() {
    prometheus.MustRegister(TunnelUp, TunnelLatency, ...)
}

// InitStartTime sets the process start time for uptime metric
func InitStartTime() { startTime = time.Now() }

// SetBuildInfo sets version/go_version/commit labels
func SetBuildInfo(version, goVersion, commit string) {
    ExporterBuildInfo.WithLabelValues(version, goVersion, commit).Set(1)
}

// SetLeader sets the exporter leader gauge
func SetLeader(isLeader bool) {
    if isLeader { ExporterLeader.Set(1) } else { ExporterLeader.Set(0) }
}

// IncConfigReloadTotal increments config reload counter
func IncConfigReloadTotal() { ExporterConfigReloadTotal.Inc() }

// IncConfigReloadErrorsTotal increments config reload error counter
func IncConfigReloadErrorsTotal() { ExporterConfigReloadErrorsTotal.Inc() }

// SetTunnelsConfigured sets the tunnels configured gauge
func SetTunnelsConfigured(count int) { ExporterTunnelsConfigured.Set(float64(count)) }

// ClassifyError categorizes an error for xray_tunnel_error_total
func ClassifyError(err error) string { ... }  // exact copy of current classifyError
```

Note: `exporterUptimeSeconds` gauge function references `startTime` — keep as `GaugeFunc` in init:

```go
var exporterUptimeSeconds = prometheus.NewGaugeFunc(
    prometheus.GaugeOpts{
        Name: "xray_exporter_uptime_seconds",
        Help: "...",
    },
    func() float64 { return time.Since(startTime).Seconds() },
)
```

- [ ] **Step 2: Verify new package compiles**

```bash
go build ./internal/metrics/
```

- [ ] **Step 3: Commit**

```bash
git add internal/metrics/ && git commit -m "refactor: extract prometheus metrics into internal/metrics package"
```

---

### Task 4: Create `internal/config/config.go` and `internal/config/watcher.go`

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/watcher.go`

No internal dependencies. Imports only standard library + fsnotify + yaml.

- [ ] **Step 1: Create `internal/config/config.go`**

Package `config`. Move from `main.go`:
- Lines 267–296: `Config`, `Defaults`, `Tunnel`, `Subscription` structs (all exported, already are)
- Lines 361–393: `applyTunnelDefaults` (exported: `ApplyTunnelDefaults`)
- Lines 395–442: `loadConfig` (exported: `LoadConfig`)
- Lines 444–505: `fetchSubscription` (exported: `FetchSubscription`)
- Lines 507–538: `resolveSubscriptions` (exported: `ResolveSubscriptions`)
- Lines 1264–1304: `Tunnel.Validate` method
- Lines 1306–1326: `validateTunnels` (exported: `ValidateTunnels`)

Replace references to local constants with `metrics.` prefixed constants:
- `defaultCheckURL` → `metrics.DefaultCheckURL`
- `defaultCheckInterval` → `metrics.DefaultCheckInterval`
- `defaultTimeout` → `metrics.DefaultTimeout`
- `defaultMaxBackoff` → `metrics.DefaultMaxBackoff`
- `defaultBackoffMult` → `metrics.DefaultBackoffMult`

Import: `"github.com/batonogov/xray-health-exporter/internal/metrics"`

- [ ] **Step 2: Create `internal/config/watcher.go`**

Move from `main.go`:
- Lines 1515–1652: `watchConfigFile` (exported: `WatchConfigFile`)
- Lines 1654–1687: `watchSubscriptions` (exported: `WatchSubscriptions`)

These functions take `*tunnel.TunnelManager` as parameter. Import tunnel package.

```go
package config

import (
    "context"
    // ...
    "github.com/batonogov/xray-health-exporter/internal/tunnel"
)

func WatchConfigFile(ctx context.Context, tm *tunnel.TunnelManager, configFile string) error { ... }
func WatchSubscriptions(ctx context.Context, tm *tunnel.TunnelManager, configFile string) { ... }
```

Wait — this creates a dependency cycle: `config` → `tunnel` and `tunnel` → `config` (for `LoadConfig`, `ResolveSubscriptions`).

**Resolution:** Keep `WatchConfigFile` and `WatchSubscriptions` in `tunnel` package instead. They're orchestration functions that happen to watch the config file. `config` package only has data types and parsing functions.

So: `internal/config/config.go` — only types + parsing + validation (no watcher code).

`watchConfigFile` and `watchSubscriptions` stay in `internal/tunnel/watcher.go`.

- [ ] **Step 3: Verify new package compiles**

```bash
go build ./internal/config/
```

- [ ] **Step 4: Commit**

```bash
git add internal/config/ && git commit -m "refactor: extract config parsing into internal/config package"
```

---

### Task 5: Create `internal/tunnel/` — types, xray, manager, watcher

**Files:**
- Create: `internal/tunnel/types.go`
- Create: `internal/tunnel/xray.go`
- Create: `internal/tunnel/manager.go`
- Create: `internal/tunnel/watcher.go`

This is the core package. Imports `config`, `metrics`, `socks`.

- [ ] **Step 1: Create `internal/tunnel/types.go`**

Move from `main.go`:
- Lines 185–206: `HealthChecker` interface, `CheckResult` struct (already exported)
- Lines 208–213: `MetricsUpdater` interface — modify to add `RecordError` and remove `Cleanup`:

```go
package tunnel

import (
    "time"
    "github.com/batonogov/xray-health-exporter/internal/metrics"
)

// CheckResult holds the outcome of a single health-check.
type CheckResult struct {
    Up         bool
    Latency    time.Duration
    HTTPStatus int
    Err        error
}

// MetricLabels holds protocol-agnostic labels for Prometheus metrics.
type MetricLabels struct {
    Server   string
    Security string
    SNI      string
}

// TunnelInstance represents a running tunnel.
type TunnelInstance struct {
    Name              string
    VLESSConfig       *VLESSConfig
    MetricLabels      MetricLabels
    XrayInstance      interface{ Close() }  // *core.Instance
    SocksPort         int
    CheckURL          string
    CheckInterval     time.Duration
    CheckTimeout      time.Duration
    MaxBackoff        time.Duration
    BackoffMultiplier float64
    CancelFunc        context.CancelFunc
}

// HealthChecker performs a single health-check on a tunnel instance.
type HealthChecker interface {
    Check(ti *TunnelInstance) CheckResult
}

// MetricsUpdater records health-check results as Prometheus metrics.
type MetricsUpdater interface {
    Update(name string, ml MetricLabels, result CheckResult)
    RecordError(name string, ml MetricLabels, err error)
}
```

Note: `TunnelInstance.XrayInstance` uses `interface{ Close() }` instead of `*core.Instance` to avoid importing xray-core in types. The manager file will do a type assertion where needed. Alternatively, import xray-core — it's already a dependency.

Actually, just import `core` — it's a direct dependency and `TunnelInstance` is tightly coupled to it:

```go
import "github.com/xtls/xray-core/core"

type TunnelInstance struct {
    // ...
    XrayInstance *core.Instance
    // ...
    cancelFunc   context.CancelFunc  // keep unexported
}
```

- [ ] **Step 2: Create `internal/tunnel/xray.go`**

Move from `main.go`:
- Lines 298–314: `VLESSConfig` struct (already exported)
- Lines 540–580: `parseVLESSURL` (exported: `ParseVLESSURL`)
- Lines 582–626: `createXrayConfig` (exported: `CreateXrayConfig`)
- Lines 628–705: `createStreamSettings` (exported: `CreateStreamSettings`)
- Lines 707–731: `startXray` (exported: `StartXray`)
- Lines 733–773: `loadXrayConfigFile` (exported: `LoadXrayConfigFile`)
- Lines 775–832: `extractMetricLabelsFromXrayConfig` (exported: `ExtractMetricLabelsFromXrayConfig`)

```go
package tunnel

import (
    "encoding/json"
    "fmt"
    "os"
    "strconv"
    "strings"
    "net/url"

    "github.com/xtls/xray-core/core"
    "github.com/xtls/xray-core/infra/conf"
    _ "github.com/xtls/xray-core/main/distro/all"
)
```

- [ ] **Step 3: Create `internal/tunnel/manager.go`**

Move from `main.go`:
- Lines 325–359: `TunnelManager` struct, `NewTunnelManager`
- Lines 834–919: `initTunnel` (exported: `InitTunnel`)
- Lines 1248–1260: `waitForSOCKSPort` (exported: `WaitForSOCKSPort`)
- Lines 1328–1397: `initializeTunnels` (exported: `InitializeTunnels`)
- Lines 1399–1409: `stopTunnels` (exported: `StopTunnels`)
- Lines 1092–1180: `performCheck` helper functions are in checker, but `checkAndRecord` and `runTunnelChecker` stay here (orchestration)
- Lines 1150–1180: `checkAndRecord`
- Lines 1182–1229: `runTunnelChecker`
- Lines 1231–1245: `backoffDuration` (exported: `BackoffDuration`)
- Lines 1411–1451: `tunnelMetricLabels` (unexported), `cleanupRemovedTunnelMetrics` (exported: `CleanupRemovedTunnelMetrics`)
- Lines 1453–1512: `reloadConfig` method on `TunnelManager`
- Lines 1749–1809: `runProbing` (exported: `RunProbing`)

Key import changes:
```go
import (
    "github.com/batonogov/xray-health-exporter/internal/config"
    "github.com/batonogov/xray-health-exporter/internal/metrics"
    "github.com/batonogov/xray-health-exporter/internal/socks"
)
```

Replace all references:
- `defaultSocksPort` → `metrics.DefaultSocksPort`
- `defaultCheckURL` → `metrics.DefaultCheckURL`
- `defaultMaxBackoff` → `metrics.DefaultMaxBackoff`
- `socksStartupTimeout` → `metrics.SocksStartupTimeout`
- `tunnelUp` → `metrics.TunnelUp`
- `tunnelLatency` → `metrics.TunnelLatency`
- `tunnelCheckTotal` → `metrics.TunnelCheckTotal`
- `tunnelErrorTotal` → `metrics.TunnelErrorTotal`
- `tunnelLatencyHistogram` → `metrics.TunnelLatencyHistogram`
- `tunnelLastSuccess` → `metrics.TunnelLastSuccess`
- `tunnelHTTPStatus` → `metrics.TunnelHTTPStatus`
- `errorReasons` → `metrics.ErrorReasons`
- `exporterConfigReloadTotal` → `metrics.ExporterConfigReloadTotal` (or use `metrics.IncConfigReloadTotal()`)
- `exporterConfigReloadErrorsTotal` → use `metrics.IncConfigReloadErrorsTotal()`
- `exporterTunnelsConfigured` → use `metrics.SetTunnelsConfigured()`
- `loadConfig(` → `config.LoadConfig(`
- `resolveSubscriptions(` → `config.ResolveSubscriptions(`
- `validateTunnels(` → `config.ValidateTunnels(`
- `initTunnel(` → stays in same package (unexported)
- `newSOCKS5Dialer(` → `socks.NewSOCKS5Dialer(`
- `parseVLESSURL(` → stays in same package
- `createXrayConfig(` → stays in same package
- `startXray(` → stays in same package
- `loadXrayConfigFile(` → stays in same package
- `waitForSOCKSPort(` → stays in same package

`checkAndRecord` changes — replace direct `tunnelErrorTotal` access with `metrics.RecordError()` through interface:

```go
func checkAndRecord(ti *TunnelInstance, checker HealthChecker, mu MetricsUpdater) {
    result := checker.Check(ti)
    if !result.Up && result.Err != nil {
        mu.RecordError(ti.Name, ti.MetricLabels, result.Err)
    }
    // logging (unchanged)
    mu.Update(ti.Name, ti.MetricLabels, result)
}
```

`runTunnelChecker` loop body — replace `metrics.Update` call with `mu.Update` (through interface), and `checker.Check` through interface:

```go
func runTunnelChecker(ctx context.Context, ti *TunnelInstance, checker HealthChecker, mu MetricsUpdater) {
    // ... jitter + first checkAndRecord ...
    for {
        select {
        case <-ctx.Done(): return
        case <-ticker.C:
            // backoff logic (unchanged)
            result := checker.Check(ti)
            // logging (unchanged)
            mu.Update(ti.Name, ti.MetricLabels, result)
        }
    }
}
```

`cleanupRemovedTunnelMetrics` uses metrics package vars directly:

```go
func CleanupRemovedTunnelMetrics(oldInstances, newInstances []*TunnelInstance) {
    // ... newKeys map (unchanged) ...
    for _, ti := range oldInstances {
        // ...
        metrics.TunnelUp.DeleteLabelValues(labels...)
        metrics.TunnelLatency.DeleteLabelValues(labels...)
        metrics.TunnelLatencyHistogram.DeleteLabelValues(labels...)
        metrics.TunnelLastSuccess.DeleteLabelValues(labels...)
        metrics.TunnelHTTPStatus.DeleteLabelValues(labels...)
        metrics.TunnelCheckTotal.DeleteLabelValues(...)
        for _, reason := range metrics.ErrorReasons {
            metrics.TunnelErrorTotal.DeleteLabelValues(...)
        }
    }
}
```

- [ ] **Step 4: Create `internal/tunnel/watcher.go`**

Move from `main.go`:
- Lines 1515–1652: `watchConfigFile` → `WatchConfigFile`
- Lines 1654–1687: `watchSubscriptions` → `WatchSubscriptions`

```go
package tunnel

import (
    "context"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/fsnotify/fsnotify"
    "github.com/batonogov/xray-health-exporter/internal/config"
    "github.com/batonogov/xray-health-exporter/internal/metrics"
    "log/slog"
)
```

- [ ] **Step 5: Verify package compiles**

```bash
go build ./internal/tunnel/
```

- [ ] **Step 6: Commit**

```bash
git add internal/tunnel/ && git commit -m "refactor: extract tunnel management into internal/tunnel package"
```

---

### Task 6: Create `internal/checker/checker.go`

**Files:**
- Create: `internal/checker/checker.go`

Imports `tunnel` (for types) and `socks`.

- [ ] **Step 1: Create `internal/checker/checker.go`**

Move from `main.go`:
- Lines 258–264: `defaultChecker` struct (exported: `DefaultChecker`)
- Lines 1092–1148: `performCheck` (exported: `PerformCheck`)

```go
package checker

import (
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "net/http"
    "time"

    "github.com/batonogov/xray-health-exporter/internal/socks"
    "github.com/batonogov/xray-health-exporter/internal/tunnel"
    "github.com/batonogov/xray-health-exporter/internal/metrics"
)

type DefaultChecker struct{}

func (DefaultChecker) Check(ti *tunnel.TunnelInstance) tunnel.CheckResult {
    return PerformCheck(ti)
}

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
            TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
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
            Up: false, HTTPStatus: resp.StatusCode,
            Err: fmt.Errorf("bad status code: %d", resp.StatusCode),
        }
    }

    _, bodyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
    duration := time.Since(start)
    return tunnel.CheckResult{
        Up: true, Latency: duration, HTTPStatus: resp.StatusCode, Err: bodyErr,
    }
}
```

- [ ] **Step 2: Verify package compiles**

```bash
go build ./internal/checker/
```

- [ ] **Step 3: Commit**

```bash
git add internal/checker/ && git commit -m "refactor: extract health checker into internal/checker package"
```

---

### Task 7: Create `internal/leaderelection/leaderelection.go`

**Files:**
- Create: `internal/leaderelection/leaderelection.go`

Imports `tunnel` and `metrics`.

- [ ] **Step 1: Create `internal/leaderelection/leaderelection.go`**

Move from `main.go`:
- Lines 1689–1698: `leaderElectionConfig` (exported: `LeaderElectionConfig`)
- Line 1701: `serviceAccountNamespacePath` (exported: `ServiceAccountNamespacePath`)
- Lines 1703–1745: `readLeaderElectionConfig` (exported: `ReadLeaderElectionConfig`)
- Lines 1811–1871: `runWithLeaderElection` (exported: `RunWithLeaderElection`)

```go
package leaderelection

import (
    "context"
    "fmt"
    "os"
    "strings"
    "time"

    "log/slog"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/tools/leaderelection"
    "k8s.io/client-go/tools/leaderelection/resourcelock"

    "github.com/batonogov/xray-health-exporter/internal/metrics"
    "github.com/batonogov/xray-health-exporter/internal/tunnel"
)
```

Replace: `exporterLeader.Set(...)` → `metrics.SetLeader(...)`.

- [ ] **Step 2: Verify package compiles**

```bash
go build ./internal/leaderelection/
```

- [ ] **Step 3: Commit**

```bash
git add internal/leaderelection/ && git commit -m "refactor: extract leader election into internal/leaderelection package"
```

---

### Task 8: Create `cmd/exporter/main.go` — wiring layer

**Files:**
- Create: `cmd/exporter/main.go`

This is the new entry point. Imports all internal packages, defines `prometheusMetrics` implementation.

- [ ] **Step 1: Create `cmd/exporter/main.go`**

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "runtime"
    "strings"
    "syscall"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"

    "github.com/batonogov/xray-health-exporter/internal/checker"
    "github.com/batonogov/xray-health-exporter/internal/config"
    "github.com/batonogov/xray-health-exporter/internal/leaderelection"
    "github.com/batonogov/xray-health-exporter/internal/metrics"
    "github.com/batonogov/xray-health-exporter/internal/tunnel"
)

var Version = "dev"
var Commit = ""

// prometheusMetrics implements tunnel.MetricsUpdater using the global prometheus vars
type prometheusMetrics struct{}

func (prometheusMetrics) Update(name string, ml tunnel.MetricLabels, r tunnel.CheckResult) {
    labels := prometheus.Labels{
        "name": name, "server": ml.Server, "security": ml.Security, "sni": ml.SNI,
    }
    resultLabels := func(result string) prometheus.Labels {
        return prometheus.Labels{
            "name": name, "server": ml.Server, "security": ml.Security, "sni": ml.SNI, "result": result,
        }
    }
    if r.Up {
        metrics.TunnelUp.With(labels).Set(1)
        if r.Err == nil {
            metrics.TunnelLatency.With(labels).Set(r.Latency.Seconds())
            metrics.TunnelLatencyHistogram.With(labels).Observe(r.Latency.Seconds())
        }
        metrics.TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
        metrics.TunnelCheckTotal.With(resultLabels("success")).Inc()
    } else {
        metrics.TunnelUp.With(labels).Set(0)
        metrics.TunnelCheckTotal.With(resultLabels("failure")).Inc()
    }
    if r.HTTPStatus > 0 {
        metrics.TunnelHTTPStatus.With(labels).Set(float64(r.HTTPStatus))
    }
}

func (prometheusMetrics) RecordError(name string, ml tunnel.MetricLabels, err error) {
    errorLabels := prometheus.Labels{
        "name": name, "server": ml.Server, "security": ml.Security,
        "sni": ml.SNI, "reason": metrics.ClassifyError(err),
    }
    metrics.TunnelErrorTotal.With(errorLabels).Inc()
}

func setupLogger() {
    // exact copy of current setupLogger from main.go lines 1873-1911
}

func main() {
    setupLogger()
    metrics.InitStartTime()
    metrics.SetBuildInfo(Version, runtime.Version(), Commit)
    slog.Info("xray-health-exporter starting", "version", Version)

    configFile := os.Getenv("CONFIG_FILE")
    if configFile == "" {
        configFile = metrics.DefaultConfigFile
    }
    listenAddr := os.Getenv("LISTEN_ADDR")
    if listenAddr == "" {
        listenAddr = metrics.DefaultListenAddr
    }

    lec, err := leaderelection.ReadLeaderElectionConfig()
    if err != nil {
        slog.Error("invalid leader election config", "error", err)
        os.Exit(1)
    }

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    if lec == nil {
        metrics.SetLeader(true)
    }

    mux := http.NewServeMux()
    mux.Handle("/metrics", promhttp.Handler())
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, "OK")
    })
    server := &http.Server{Addr: listenAddr, Handler: mux}
    slog.Info("metrics server listening", "address", listenAddr)

    serverErr := make(chan error, 1)
    go func() { serverErr <- server.ListenAndServe() }()

    probingDone := make(chan struct{})
    go func() {
        defer close(probingDone)
        if lec != nil {
            if err := leaderelection.RunWithLeaderElection(ctx, lec, configFile); err != nil {
                slog.Info("leader election stopped", "error", err)
            }
            return
        }
        if err := tunnel.RunProbing(ctx, configFile); err != nil {
            slog.Info("probing stopped", "error", err)
        }
    }()

    select {
    case err := <-serverErr:
        if err != nil && !errors.Is(err, http.ErrServerClosed) {
            slog.Error("HTTP server error", "error", err)
        }
    case <-ctx.Done():
    case <-probingDone:
        slog.Warn("probing exited unexpectedly, shutting down")
    }

    slog.Info("shutdown signal received, stopping HTTP server")
    stop()
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
        slog.Error("HTTP server shutdown error", "error", err)
    }
    select {
    case <-probingDone:
    case <-time.After(15 * time.Second):
        slog.Warn("probing did not stop within timeout", "timeout", "15s")
    }
}
```

- [ ] **Step 2: Verify new entry point compiles**

```bash
go build -o /dev/null ./cmd/exporter/
```

- [ ] **Step 3: Commit**

```bash
git add cmd/exporter/ && git commit -m "refactor: create cmd/exporter entry point"
```

---

### Task 9: Delete old root files + move tests to new packages

**Files:**
- Delete: `main.go`, `main_test.go`, `backoff_test.go`, `exporter_metrics_test.go` (root directory)
- Create: test files in each internal package

This is the "switch" — remove old code, activate new structure.

- [ ] **Step 1: Delete old root source files**

```bash
rm main.go
```

- [ ] **Step 2: Create test files in new packages**

Move tests from `main_test.go` and other test files to their corresponding packages. Each test file updates imports and type references.

**`internal/socks/dialer_test.go`:**
Tests: `TestSOCKS5Dialer`, `TestSOCKS5DialContext`, `TestSOCKS5DialContextErrors`, `TestSOCKS5DialContext_HandshakeErrors`, `TestDialContext_WriteErrorDuringConnect`, `TestDialContext_ReadErrorResponseDomain`, `TestDialContext_InvalidPort`, `TestDialContext_ResponseReadError`, `TestDialContext_IPv4ResponseReadError`, `TestDialContext_IPv6ResponseReadError`, `TestDialContext_DomainResponseReadError`, `TestDialContext_DomainLenThenClose`
- Package: `socks`
- Replace: `newSOCKS5Dialer(` → `NewSOCKS5Dialer(`, `socks5Dialer{` → `SOCKS5Dialer{`

**`internal/config/config_test.go`:**
Tests: `TestLoadConfig`, `TestLoadConfig_SocksPort`, `TestValidateTunnels_SocksPort`, `TestApplyTunnelDefaults`, `TestApplyTunnelDefaults_BackoffFields`, `TestLoadConfig_BackoffFields`, `TestTunnelValidate`, `TestTunnelValidate_XrayConfigFile`, `TestValidateTunnels`, `TestLoadConfig_Subscriptions`, `TestFetchSubscription` (all variants), `TestResolveSubscriptions` (all variants), `TestWatchSubscriptions_NoSubscriptions`, `TestWatchSubscriptions_NilConfig`
- Package: `config`
- Replace: `loadConfig(` → `LoadConfig(`, `applyTunnelDefaults(` → `ApplyTunnelDefaults(`, `validateTunnels(` → `ValidateTunnels(`, `fetchSubscription(` → `FetchSubscription(`, `resolveSubscriptions(` → `ResolveSubscriptions(`, `defaultCheckURL` → `metrics.DefaultCheckURL`, `defaultCheckInterval` → `metrics.DefaultCheckInterval`, `defaultMaxBackoff` → `metrics.DefaultMaxBackoff`, `defaultBackoffMult` → `metrics.DefaultBackoffMult`

**`internal/tunnel/xray_test.go`:**
Tests: `TestParseVLESSURL`, `TestCreateStreamSettings`, `TestCreateXrayConfig`, `TestCreateXrayConfig_gRPC`, `TestLoadXrayConfigFile` (all variants), `TestExtractMetricLabelsFromXrayConfig` (all variants), `TestInitTunnel_XrayConfigFile` (all variants), `TestInitTunnel_VLESSURLParseError`, `TestInitTunnel_InvalidDurations`, `TestInitTunnel_InvalidBackoffMultiplier`, `TestInitTunnel_InvalidMaxBackoff`, `TestStartXray_InvalidConfig`, `TestCreateXrayConfig_WithXRAYLogLevel`, `TestLoadXrayConfigFile_WithXRAYLogLevel`, `TestVLESSURL_NoSecurity`
- Package: `tunnel`
- Replace: `parseVLESSURL(` → `ParseVLESSURL(`, `createXrayConfig(` → `CreateXrayConfig(`, `createStreamSettings(` → `CreateStreamSettings(`, `startXray(` → `StartXray(`, `loadXrayConfigFile(` → `LoadXrayConfigFile(`, `extractMetricLabelsFromXrayConfig(` → `ExtractMetricLabelsFromXrayConfig(`, `initTunnel(` → `InitTunnel(`

**`internal/tunnel/manager_test.go`:**
Tests: `TestInitializeTunnels`, `TestInitializeTunnels_SocksPort` (all subtests), `TestInitializeTunnels_CleanupOnError`, `TestStopTunnels`, `TestStopTunnels_NilXrayInstance`, `TestTunnelManagerReloadConfig`, `TestWaitForSOCKSPort`, `TestTunnelMetricLabels`, `TestCleanupRemovedTunnelMetrics`, `TestCleanupRemovedTunnelMetrics_ErrorMetrics`, `TestCleanupRemovedTunnelMetrics_EmptyOld`, `TestReloadConfig_InvalidConfigKeepsOldTunnels`, `TestReloadConfig_LoadError`, `TestReloadConfig_NoTunnelsAfterResolve`, `TestReloadConfig_ValidationError`, `TestRunProbing`, `TestConcurrentTunnelManagerReload`
- Package: `tunnel`
- Replace: `defaultSocksPort` → `metrics.DefaultSocksPort`, `initializeTunnels(` → `InitializeTunnels(`, `stopTunnels(` → `StopTunnels(`, `NewTunnelManager(` → `NewTunnelManager(` (same name, different import path), `cleanupRemovedTunnelMetrics(` → `CleanupRemovedTunnelMetrics(`, `defaultChecker{}` → `checker.DefaultChecker{}`, `prometheusMetrics{}` → import from cmd package — NO. Tests in internal packages cannot import cmd.

**Problem:** Tests in `internal/tunnel` need `prometheusMetrics{}` which is defined in `cmd/exporter/main.go`. Internal packages cannot import `cmd`.

**Solution:** Define a test-only mock `MetricsUpdater` in tunnel tests, OR export `prometheusMetrics` from a shared test helper.

Actually, the simpler solution: the tests in `internal/tunnel/manager_test.go` that use `prometheusMetrics{}` should instead define a local test mock or just use a simple struct that satisfies the interface. Since `prometheusMetrics` just calls prometheus functions which are globally registered, the tests can define their own trivial implementation:

```go
type testMetrics struct{}
func (testMetrics) Update(name string, ml tunnel.MetricLabels, r tunnel.CheckResult) {
    // delegate to prometheus globals directly
    // or just no-op if we don't need to verify metrics in these tests
}
func (testMetrics) RecordError(name string, ml tunnel.MetricLabels, err error) {}
```

But many tests actually verify metrics behavior (e.g., `TestCleanupRemovedTunnelMetrics`). For those, we need the real prometheus behavior. The cleanest approach: create a `testMetrics` that directly calls the `metrics` package prometheus vars (since tests CAN import `internal/metrics`):

```go
// In internal/tunnel/manager_test.go
import "github.com/batonogov/xray-health-exporter/internal/metrics"

type testMetrics struct{}
func (testMetrics) Update(name string, ml tunnel.MetricLabels, r tunnel.CheckResult) {
    labels := prometheus.Labels{"name": name, "server": ml.Server, "security": ml.Security, "sni": ml.SNI}
    if r.Up {
        metrics.TunnelUp.With(labels).Set(1)
        if r.Err == nil {
            metrics.TunnelLatency.With(labels).Set(r.Latency.Seconds())
        }
        metrics.TunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
        metrics.TunnelCheckTotal.With(prometheus.Labels{"name": name, "server": ml.Server, "security": ml.Security, "sni": ml.SNI, "result": "success"}).Inc()
    } else {
        metrics.TunnelUp.With(labels).Set(0)
        metrics.TunnelCheckTotal.With(prometheus.Labels{"name": name, "server": ml.Server, "security": ml.Security, "sni": ml.SNI, "result": "failure"}).Inc()
    }
    if r.HTTPStatus > 0 {
        metrics.TunnelHTTPStatus.With(labels).Set(float64(r.HTTPStatus))
    }
}
func (testMetrics) RecordError(name string, ml tunnel.MetricLabels, err error) {
    errorLabels := prometheus.Labels{"name": name, "server": ml.Server, "security": ml.Security, "sni": ml.SNI, "reason": metrics.ClassifyError(err)}
    metrics.TunnelErrorTotal.With(errorLabels).Inc()
}
```

This duplicates the prometheus logic in tests but keeps it self-contained within the test package.

Similarly, `defaultChecker{}` → `checker.DefaultChecker{}`.

And `tunnelUp` → `metrics.TunnelUp`, etc. in test assertions.

**`internal/tunnel/watcher_test.go`:**
Tests: `TestWatchConfigFile`, `TestWatchConfigFile_FileRemoval`, `TestWatchConfigFile_FileRename`, `TestWatchConfigFile_ChmodEvent`, `TestWatchConfigFile_ContextCancel`, `TestWatchConfigFile_CreateEvent`, `TestWatchSubscriptions_WithTicker`, `TestWatchSubscriptions_ReloadCallback`
- Package: `tunnel`
- Replace: `watchConfigFile(` → `WatchConfigFile(`, `watchSubscriptions(` → `WatchSubscriptions(`, `prometheusMetrics{}` → `testMetrics{}`, `defaultSocksPort` → `metrics.DefaultSocksPort`

**`internal/checker/checker_test.go`:**
Tests: `TestCheckTunnel`, `TestCheckTunnel_Timeout`, `TestCheckTunnel_BadStatusCodes`, `TestCheckTunnel_DNSError`, `TestCheckTunnel_TLSError`, `TestCheckTunnel_SOCKSNotReachable`, `TestCheckTunnel_BodyReadError`, `TestCheckTunnel_BodyReadSuccess`, `TestRunTunnelChecker`, `TestRunTunnelChecker_Context`, `TestRunTunnelChecker_ImmediateCancel`, `TestConcurrentCheckTunnel`, `TestBackoffDuration`, `TestRunTunnelChecker_BackoffOnFailures`, `TestRunTunnelChecker_BackoffResetsOnSuccess`
- Package: `checker`
- Replace: `TunnelInstance{` → `tunnel.TunnelInstance{`, `MetricLabels{` → `tunnel.MetricLabels{`, `VLESSConfig{` → `tunnel.VLESSConfig{`, `CheckResult{` → `tunnel.CheckResult{`, `defaultChecker{}` → `DefaultChecker{}`, `prometheusMetrics{}` → `testMetrics{}`, `performCheck(` → `PerformCheck(`, `backoffDuration(` → need to import from tunnel: `tunnel.BackoffDuration(`, `checkAndRecord(` → `tunnel.CheckAndRecord(` (export it), `runTunnelChecker(` → `tunnel.RunTunnelChecker(` (export it), `newSOCKS5Dialer(` → `socks.NewSOCKS5Dialer(`, `waitForSOCKSPort(` → `tunnel.WaitForSOCKSPort(`

**`internal/metrics/metrics_test.go`:**
Tests: `TestClassifyError`, `TestClassifyError_NetError`, `TestMetricsUpdate`, `TestMetricsLabels`, `TestMetricsReset`, `TestMetricsEndpoint`, `TestCleanupRemovedTunnelMetrics` (note: this test uses TunnelInstance — move to tunnel tests instead), `TestLatencyHistogramMetric`, `TestLatencyHistogramBuckets`, `TestMetricsEndpoint_IncludesHistogram`, `TestExporterInternalMetrics_*` tests
- Package: `metrics`
- Replace: `classifyError(` → `ClassifyError(`, `tunnelUp` → `TunnelUp`, etc.
- Note: `TestCleanupRemovedTunnelMetrics` stays in `tunnel` tests since it needs `TunnelInstance`

**`internal/leaderelection/leaderelection_test.go`:**
Tests: `TestReadLeaderElectionConfig`
- Package: `leaderelection`
- Replace: `readLeaderElectionConfig(` → `ReadLeaderElectionConfig(`, `serviceAccountNamespacePath` → `ServiceAccountNamespacePath`

**`cmd/exporter/main_test.go`:**
Tests: `TestHealthEndpoint`, `TestSetupLogger`
- Package: `main`

- [ ] **Step 3: Delete old test files**

```bash
rm main_test.go backoff_test.go exporter_metrics_test.go
```

- [ ] **Step 4: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: move tests to corresponding packages and remove old root files"
```

---

### Task 10: Update Taskfile.yml and Dockerfile

**Files:**
- Modify: `Taskfile.yml`
- Modify: `Dockerfile`

- [ ] **Step 1: Update Taskfile.yml**

All `go build` and `go run` commands change from `.` to `./cmd/exporter`:

```yaml
# build task
cmds:
  - go build -ldflags="-X main.Version=dev -X main.Commit=dev" -o xray-health-exporter ./cmd/exporter

# ci-test task
cmds:
  - go fmt ./...
  - go build -v -o xray-health-exporter ./cmd/exporter
  - go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
  - go tool cover -func=coverage.out | tail -1
  - echo "✅ Все проверки CI пройдены!"

# run task
cmds:
  - go run ./cmd/exporter
```

- [ ] **Step 2: Update Dockerfile**

```dockerfile
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" -o xray-health-exporter ./cmd/exporter
```

- [ ] **Step 3: Verify build works**

```bash
task build
task test
```

- [ ] **Step 4: Commit**

```bash
git add Taskfile.yml Dockerfile && git commit -m "refactor: update build system for new package structure"
```

---

### Task 11: Final verification and cleanup

- [ ] **Step 1: Run full CI test**

```bash
task ci-test
```

Verify coverage >= 75%.

- [ ] **Step 2: Verify Docker build**

```bash
task docker-build
```

- [ ] **Step 3: Clean up empty worktrees**

```bash
rm -rf .worktrees/ .claude/worktrees/
```

- [ ] **Step 4: Final commit if needed**

```bash
git add -A && git commit -m "chore: cleanup after package restructure"
```

---

### Task 12: Create pull request

- [ ] **Step 1: Push branch**

```bash
git push -u origin refactor/split-main-into-packages
```

- [ ] **Step 2: Create PR**

```bash
gh pr create --title "refactor: split main.go into packages" --body "$(cat <<'EOF'
## Summary

- Split monolithic `main.go` (2003 lines) into well-structured Go packages under `internal/` and `cmd/exporter/`
- Package structure: `socks`, `config`, `metrics`, `tunnel`, `checker`, `leaderelection`
- All tests moved to corresponding packages
- Build system (Taskfile, Dockerfile) updated for new entry point

Closes #34

## Test plan

- [ ] `task ci-test` passes with coverage >= 75%
- [ ] `task docker-build` succeeds
- [ ] `task run` starts exporter and serves metrics correctly
- [ ] Config hot-reload still works
- [ ] Subscription updates still work
EOF
)"
```
