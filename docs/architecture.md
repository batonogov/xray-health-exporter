# Architecture

Internal structure of xray-health-exporter. After refactor (#111) the monolithic `main.go` was split into a package layout.

## Package map

```
cmd/exporter/        — entrypoint
  ├─ main.go         run-mode dispatch (RUN_ONCE / LEADER_ELECTION / daemon), HTTP server, graceful shutdown
  └─ auth.go         Basic Auth middleware for /metrics (crypto/subtle.ConstantTimeCompare)
internal/config/     — YAML config, defaults, env-overrides
  ├─ subscription.go — HTTP subscription fetching, text/Base64 and native Xray JSON parsing
  └─ subscription_clash.go — conversion of supported Clash proxies
internal/checker/    — DefaultChecker: health-check implementation (http/ip/download)
internal/tunnel/     — TunnelManager, TunnelInstance, Xray lifecycle, watchers, RunOnce
  ├─ types.go        TunnelInstance, HealthChecker / MetricsUpdater DI interfaces
  ├─ xray.go         ParseVLESSURL, CreateXrayConfig / CreateStreamSettings, LoadXrayConfigFile / LoadXrayConfigJSON,
  │                  ExtractMetricLabelsFromXrayConfig, StartXray
  ├─ share_links.go  VMess, Trojan and Shadowsocks share-link conversion
  ├─ xray_init.go    Side-effect registration of embedded Xray protocols, transports and features
  ├─ manager.go      TunnelManager, source cache/reconciliation, InitializeTunnels, RunTunnelChecker,
  │                  BackoffDuration, WaitForSOCKSPort,
  │                  CleanupRemovedTunnelMetrics, NewPrometheusMetrics, RunProbing
  ├─ watcher.go      WatchConfigFile (fsnotify), WatchSubscriptions (periodic)
  └─ run_once.go     RunOnce — single check cycle → Prometheus text-exposition → exit
internal/metrics/    — Tunnel/exporter metrics (metrics.go), subscription metrics (subscriptions.go), Pushgateway (push.go)
internal/socks/      — SOCKS5 dialer (SOCKS5Dialer.DialContext)
internal/leaderelection/ — ReadLeaderElectionConfig, RunWithLeaderElection (k8s lease)
```

## Key entities

### `internal/config`

`Config` / `Defaults` / `Tunnel` / `Subscription`. `Defaults` holds default values; each `Tunnel` overrides them. A `Tunnel` has two mutually exclusive modes: `url` (VLESS/VMess/Trojan/Shadowsocks URL) or `xray_config_file` (path to native Xray JSON); subscriptions can also provide an in-memory native Xray config. Check-method fields: `CheckMethod`, `IPCheckURL`, `DownloadURL`, `DownloadTimeout`, `DownloadMinSize`. Validation: `Tunnel.Validate()` and `ValidateTunnels()` (also checks `socks_port` uniqueness and range). Default priority: per-tunnel YAML → YAML `defaults:` → the five fields supported by `ApplyEnvDefaults` → built-in constants in `internal/metrics`.

### `internal/checker`

`DefaultChecker` implements `tunnel.HealthChecker`. `Check()` dispatches on `ti.CheckMethod`: `checkByIP` / `checkByDownload` / `PerformCheck` (http). TTFB instrumentation uses `ttfbRequest` + `resolveLatency` (falling back to total elapsed time on a successful check if the trace callback did not fire). `ResolveRealIP` normally resolves the host's real public IP once at startup for the `ip` method; if startup resolution fails, an `ip` check retries resolution.

### `internal/tunnel`

- `TunnelInstance` — config + `*core.Instance` + SOCKS port + `MetricLabels` + check-method params. `VLESSConfig` is `nil` for native configs and non-VLESS share links.
- `TunnelManager` — list of active instances under a mutex, hot reload.
- `HealthChecker` / `MetricsUpdater` — DI interfaces (decouple probing from concrete metric/checker implementations).
- SOCKS ports are assigned sequentially from `DefaultSocksPort` (1080), or per-tunnel `socks_port` (#99).

#### `xray.go`

- `ParseVLESSURL` — parse and validate a VLESS URL, normalize transport aliases, and reject unsupported or duplicate parameters.
- `CreateXrayConfig` / `CreateStreamSettings` — generate raw JSON for in-process Xray (SOCKS5 inbound → outbound).
- `LoadXrayConfigFile` — load a native Xray config, replace `log` and `inbounds` with exporter-controlled settings, and preserve other top-level sections.
- `ExtractMetricLabelsFromXrayConfig` — derive metric labels from the first outbound: `vnext` for VLESS/VMess, `servers` for Trojan/Shadowsocks.
- `StartXray` — unmarshal into `conf.Config`, build the protobuf config, create `core.Instance`, and call `Start`.

#### `manager.go`

`InitializeTunnels`, `RunTunnelChecker` (check loop + backoff), `BackoffDuration`, `WaitForSOCKSPort`, `CleanupRemovedTunnelMetrics`, `NewPrometheusMetrics` (implements `MetricsUpdater`), `RunProbing` (daemon entry point: init + watchers + checker goroutines).

#### `watcher.go`

`WatchConfigFile` (fsnotify → reload), `WatchSubscriptions` (dynamic, independent deadlines per subscription).

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

### Subscription refresh

A serialized refresh resolves only due sources, retaining a last-good response per source in memory. New sources without a usable response reject the update; failures for cached sources retain their running tunnels. Response state commits only after the complete candidate configuration starts successfully. Source identity includes request options but excludes the refresh interval.

The watcher runs even when no subscriptions exist and wakes on config changes. Desired source schedules are tracked separately from the applied tunnel configuration, so a newly added source retries automatically if its first request fails. Adding the first source or changing intervals does not require a restart. Reconciliation fingerprints effective tunnel settings (and native file contents), reuses unchanged instances, and allocates free ports for changed instances. A changed tunnel cannot replace another running instance on the same explicit SOCKS port; use a different port or restart.

`RUN_ONCE` reports subscription failures instead of silently checking only a partial server list.
