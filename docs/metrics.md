# Metrics

Authoritative reference — generated from [`internal/metrics/metrics.go`](../internal/metrics/metrics.go).

All `xray_tunnel_*` metrics carry the labels **`name`**, **`server`**, **`security`**, **`sni`**.

## Tunnel metrics

| Metric | Type | Extra labels | Description |
|---|---|---|---|
| `xray_tunnel_up` | gauge | — | Tunnel status (1 = up, 0 = down) |
| `xray_tunnel_latency_seconds` | gauge | — | TTFB (time to first byte), seconds |
| `xray_tunnel_latency_histogram_seconds` | histogram | — | TTFB histogram for `histogram_quantile()` |
| `xray_tunnel_check_total` | counter | `result` | Total checks by result (`success` / `failure`) |
| `xray_tunnel_last_success_timestamp` | gauge | — | Unix timestamp of the last successful check |
| `xray_tunnel_http_status` | gauge | — | HTTP status code from the last check |
| `xray_tunnel_error_total` | counter | `reason` | Total errors categorized by reason |

### Histogram buckets

`xray_tunnel_latency_histogram_seconds` uses these upper bounds (seconds):

```
0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
```

### Error reasons (`reason` label of `xray_tunnel_error_total`)

Produced by `metrics.ClassifyError`:

| Reason | Matched by |
|---|---|
| `timeout` | `context.DeadlineExceeded`, `net.Error` timeout, `deadline exceeded`, `i/o timeout`, `Client.Timeout`, `request canceled` |
| `tls` | `tls:`, `certificate`, `x509:`, `handshake failure` |
| `dns` | `lookup `, `no such host`, `dns:`, `name resolution`, `Name or service not known` |
| `connection_refused` | `connection refused` |
| `connection_reset` | `connection reset by peer`, `broken pipe` |
| `bad_status` | non-2xx/3xx HTTP status |
| `socks_error` | `SOCKS5` / `SOCKS` |
| `unknown` | anything else |

## Exporter metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `xray_exporter_build_info` | gauge | `version`, `go_version`, `commit` | Build info (value always 1) |
| `xray_exporter_uptime_seconds` | gauge | — | Time since the process started |
| `xray_exporter_leader` | gauge | — | 1 if actively probing tunnels (leader, or leader election disabled) |
| `xray_exporter_config_reload_total` | counter | — | Configuration reload attempts |
| `xray_exporter_config_reload_errors_total` | counter | — | Configuration reload errors |
| `xray_exporter_tunnels_configured` | gauge | — | Current number of configured tunnels |

## Endpoints

- `/metrics` — Prometheus exposition (optionally protected by Basic Auth via `METRICS_PROTECTED`).
- `/health` — always open (for k8s liveness/readiness probes).

## Example

```
xray_tunnel_up{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 1
xray_tunnel_latency_seconds{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 0.345
xray_tunnel_check_total{name="Server 1",...,result="success"} 42
xray_tunnel_error_total{name="Server 1",...,reason="timeout"} 3
xray_exporter_leader 1
```

See [`grafana/dashboard.json`](../grafana/dashboard.json) for a ready-to-use dashboard.
