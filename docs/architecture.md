# Architecture

Internal structure of xray-health-exporter. After refactor (#111) the monolithic `main.go` was split into a package layout.

## Package map

```
cmd/exporter/        — entrypoint
  ├─ main.go         run-mode dispatch (RUN_ONCE / LEADER_ELECTION / daemon), HTTP server, graceful shutdown
  └─ auth.go         Basic Auth middleware for /metrics (crypto/subtle.ConstantTimeCompare)
internal/config/     — YAML config, defaults, env-overrides, subscription fetching
internal/checker/    — DefaultChecker: health-check implementation (http/ip/download)
internal/tunnel/     — TunnelManager, TunnelInstance, Xray lifecycle, watchers, RunOnce
  ├─ types.go        TunnelInstance, TunnelManager, HealthChecker / MetricsUpdater DI interfaces
  ├─ xray.go         ParseVLESSURL, CreateXrayConfig / CreateStreamSettings, LoadXrayConfigFile,
  │                  ExtractMetricLabelsFromXrayConfig, StartXray
  ├─ xray_init.go    Xray instance init helpers
  ├─ manager.go      InitializeTunnels, RunTunnelChecker, BackoffDuration, WaitForSOCKSPort,
  │                  CleanupRemovedTunnelMetrics, NewPrometheusMetrics, RunProbing
  ├─ watcher.go      WatchConfigFile (fsnotify), WatchSubscriptions (periodic)
  └─ run_once.go     RunOnce — single check cycle → Prometheus text-exposition → exit
internal/metrics/    — Prometheus metrics (metrics.go) + Pushgateway push (push.go)
internal/socks/      — SOCKS5 dialer (SOCKS5Dialer.DialContext)
internal/leaderelection/ — ReadLeaderElectionConfig, RunWithLeaderElection (k8s lease)
```

## Key entities

### `internal/config`
`Config` / `Defaults` / `Tunnel` / `Subscription`. `Defaults` holds default values; each `Tunnel` overrides them. A `Tunnel` has two mutually exclusive modes: `url` (VLESS URL) or `xray_config_file` (path to native Xray JSON). Check-method fields: `CheckMethod`, `IPCheckURL`, `DownloadURL`, `DownloadTimeout`, `DownloadMinSize`. Validation: `Tunnel.Validate()` and `ValidateTunnels()` (also checks `socks_port` uniqueness and range). Default priority: YAML `defaults:` → env vars (`ApplyEnvDefaults`) → built-in constants in `internal/metrics`.

### `internal/checker`
`DefaultChecker` implements `tunnel.HealthChecker`. `Check()` dispatches on `ti.CheckMethod`: `checkByIP` / `checkByDownload` / `PerformCheck` (http). TTFB instrumentation via helpers `ttfbRequest` + `resolveLatency` (falls back to `time.Since(start)` if the trace callback did not fire). `ResolveRealIP` resolves the host's real public IP once for the `ip` method (lazily via `sync.Once` if not set at startup).

### `internal/tunnel`
- `TunnelInstance` — config + `*core.Instance` + SOCKS port + `MetricLabels` + check-method params. `VLESSConfig` is `nil` for `xray_config_file` tunnels.
- `TunnelManager` — list of active instances under a mutex, hot reload.
- `HealthChecker` / `MetricsUpdater` — DI interfaces (decouple probing from concrete metric/checker implementations).
- SOCKS ports are assigned sequentially from `DefaultSocksPort` (1080), or per-tunnel `socks_port` (#99).

#### `xray.go`
- `ParseVLESSURL` — parse a VLESS URL.
- `CreateXrayConfig` / `CreateStreamSettings` — generate raw JSON for in-process Xray (SOCKS5 inbound → outbound), parsed via `serial.LoadJSONConfig`.
- `LoadXrayConfigFile` — load a native Xray config + inject the SOCKS5 inbound.
- `ExtractMetricLabelsFromXrayConfig` — derive metric labels from the first outbound: `vnext` for VLESS/VMess, `servers` for Trojan/Shadowsocks.
- `StartXray` — `core.StartInstance`.

#### `manager.go`
`InitializeTunnels`, `RunTunnelChecker` (check loop + backoff), `BackoffDuration`, `WaitForSOCKSPort`, `CleanupRemovedTunnelMetrics`, `NewPrometheusMetrics` (implements `MetricsUpdater`), `RunProbing` (daemon entry point: init + watchers + checker goroutines).

#### `watcher.go`
`WatchConfigFile` (fsnotify → reload), `WatchSubscriptions` (periodic update by the minimum `update_interval`).

#### `run_once.go`
`RunOnce` — one check cycle over all tunnels, writes metrics in Prometheus text-exposition format to an `io.Writer`, then returns. Watchers/server/leader-election do **not** start.

### `internal/metrics`
All Prometheus metrics ([metrics.md](./metrics.md)) and optional Pushgateway push ([push.go](../internal/metrics/push.go)). `ParsePushURL` strips credentials from the URL; `ReadPushConfig` reads `METRICS_PUSH_*`; `PushMetrics`/`PushLoop` push only when the instance is leader (fail-closed via the `xray_exporter_leader` gauge).

### `internal/socks`
`SOCKS5Dialer.DialContext`.

### `internal/leaderelection`
`ReadLeaderElectionConfig` (reads `LEADER_ELECTION_*`), `RunWithLeaderElection` (k8s lease; runs `tunnel.RunProbing` only on the leader; requires in-cluster config).

## Run modes (dispatch in `cmd/exporter/main.go`)

1. **`RUN_ONCE=true`** — `tunnel.RunOnce` → one cycle → metrics to **stdout** → `os.Exit` (0 = all up, 1 = any down/error). Logs go to **stderr**; watchers/HTTP/leader-election do not start.
2. **`LEADER_ELECTION=true`** — `RunWithLeaderElection` (only inside a k8s pod; uses `InClusterConfig`).
3. **Default (daemon)** — `tunnel.RunProbing` + HTTP server (`/metrics`, `/health`) + config/subscription watchers + optional `PushLoop`. Shutdown on SIGINT/SIGTERM.

## Hot reload

On config file change (fsnotify) or subscription update, old and new tunnels are compared. Unchanged instances are **reused** — an Xray instance is not recreated unless necessary (port conflicts). Validation runs **before** stopping existing tunnels (`ValidateTunnels`) so a bad reload is rejected without dropping running tunnels. Metrics of removed tunnels are cleaned via `CleanupRemovedTunnelMetrics`.

### Subscription reload limitations
- All subscriptions update on the **minimum** `update_interval` across the config.
- Only `vless://` URLs are accepted from subscription responses.
- Adding subscriptions via hot config reload does **not** start a new watcher — restart required.
