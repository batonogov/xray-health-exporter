# Split main.go into packages

## Problem

`main.go` — 2003 строки в одном файле. Затрудняет навигацию, тестирование и поддержку.

## Solution

Разбить на пакеты по ответственности:

```
cmd/exporter/main.go                    # точка входа (~100 строк)
internal/
  config/
    config.go                            # типы + парсинг + валидация
    watcher.go                           # file watcher + subscription watcher
  tunnel/
    tunnel.go                            # TunnelInstance, TunnelManager, lifecycle
    xray.go                              # VLESSConfig, Xray JSON generation, startXray
  checker/
    checker.go                           # HealthChecker, MetricsUpdater, performCheck, runTunnelChecker, backoff, classifyError
  metrics/
    metrics.go                           # prometheus declarations, init(), Register, cleanup, errorReasons
  socks/
    dialer.go                            # socks5Dialer, DialContext
  leaderelection/
    leaderelection.go                    # leaderElectionConfig, readLeaderElectionConfig, runWithLeaderElection
```

## Package boundaries

### config/config.go
- Types: `Config`, `Defaults`, `Tunnel`, `Subscription`
- Functions: `loadConfig`, `applyTunnelDefaults`, `Tunnel.Validate`, `validateTunnels`
- Constants: default values (defaultListenAddr, defaultCheckURL, etc.)

### config/watcher.go
- Functions: `watchConfigFile`, `watchSubscriptions`
- Depends on: `tunnel.TunnelManager` (interface parameter)

### tunnel/tunnel.go
- Types: `TunnelInstance`, `TunnelManager`
- Functions: `NewTunnelManager`, `initTunnel`, `initializeTunnels`, `stopTunnels`, `runProbing`, `reloadConfig`
- Depends on: `checker.HealthChecker`, `checker.MetricsUpdater`, `config.Config`

### tunnel/xray.go
- Types: `VLESSConfig`, `MetricLabels`
- Functions: `parseVLESSURL`, `createXrayConfig`, `createStreamSettings`, `startXray`, `loadXrayConfigFile`, `extractMetricLabelsFromXrayConfig`
- No external dependencies beyond xray-core

### checker/checker.go
- Types: `HealthChecker` (interface), `CheckResult`, `MetricsUpdater` (interface), `defaultChecker`, `prometheusMetrics`
- Functions: `performCheck`, `checkAndRecord`, `runTunnelChecker`, `backoffDuration`, `classifyError`, `waitForSOCKSPort`
- Depends on: `tunnel.TunnelInstance` (parameter), `tunnel.MetricLabels`, `metrics` (for direct counter access in checkAndRecord)

### metrics/metrics.go
- All prometheus gauge/counter/histogram variable declarations
- `init()` with `prometheus.MustRegister` calls
- Functions: `tunnelMetricLabels`, `cleanupRemovedTunnelMetrics`
- Variables: `errorReasons`, exporter metrics, `exporterStartTime`
- Functions: `SetExporterStartTime`, `SetExporterTunnelsConfigured`, `IncConfigReload`, `IncConfigReloadError`, `SetLeader`

### socks/dialer.go
- Types: `socks5Dialer`
- Functions: `newSOCKS5Dialer`, `DialContext`
- No dependencies on other internal packages

### leaderelection/leaderelection.go
- Types: `leaderElectionConfig`
- Functions: `readLeaderElectionConfig`, `runWithLeaderElection`
- Variables: `serviceAccountNamespacePath`
- Depends on: `tunnel` (calls runProbing)

### cmd/exporter/main.go
- `Version`, `Commit` variables (set via -ldflags)
- `main()`: setupLogger, parse env, create HTTP server, signal handling
- Depends on: all internal packages

## Cross-package dependencies

```
cmd/exporter -> all internal packages
config       -> (none)
socks        -> (none)
metrics      -> (none)
checker      -> tunnel (TunnelInstance, MetricLabels), metrics, socks
tunnel       -> config, checker, metrics
leaderelection -> tunnel, metrics
```

## Testing

Tests move alongside their packages:
- `internal/config/config_test.go` — TestLoadConfig, TestValidateTunnels, etc.
- `internal/checker/checker_test.go` — TestClassifyError, TestCheckTunnel, TestRunTunnelChecker, etc.
- `internal/tunnel/tunnel_test.go` — TestInitializeTunnels, TestStopTunnels, etc.
- `internal/tunnel/xray_test.go` — TestParseVLESSURL, TestCreateStreamSettings, TestCreateXrayConfig, etc.
- `internal/socks/dialer_test.go` — TestSOCKS5Dialer, TestSOCKS5DialContext, etc.
- `internal/metrics/metrics_test.go` — TestCleanupRemovedTunnelMetrics, TestMetricsEndpoint, etc.
- `internal/leaderelection/leaderelection_test.go` — (if any)
- `cmd/exporter/main_test.go` — TestHealthEndpoint, TestMetricsEndpoint

## Constraints

- Coverage remains >= 75%
- `task build` — update `-ldflags` from `main.Version` to `main.Version` in cmd/exporter
- `task test` — no changes needed (tests `./...`)
- No behavioral changes — pure structural refactoring
