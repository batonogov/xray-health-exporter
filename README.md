# Xray Health Exporter

[🇬🇧 English](README.md) | [🇷🇺 Русский](README.ru.md)

[![🧪 Testing](https://github.com/batonogov/xray-health-exporter/actions/workflows/test.yml/badge.svg)](https://github.com/batonogov/xray-health-exporter/actions/workflows/test.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/batonogov/xray-health-exporter)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Prometheus exporter for monitoring Xray-core tunnels.

**Features:**
- Multiple tunnel support in a single instance
- VLESS URL or native Xray JSON config (`xray_config_file`) — all protocols and transports
- Subscriptions (subscription URL) — automatic fetching and updating of server lists
- YAML configuration with hot reload
- Automatic SOCKS port allocation
- Per-tunnel settings

## Installation

**Download a pre-built binary:**

```bash
# Linux amd64
wget https://github.com/batonogov/xray-health-exporter/releases/latest/download/xray-health-exporter-linux-amd64
chmod +x xray-health-exporter-linux-amd64

# Linux arm64
wget https://github.com/batonogov/xray-health-exporter/releases/latest/download/xray-health-exporter-linux-arm64
chmod +x xray-health-exporter-linux-arm64
```

**Docker:**

```bash
# Pull latest
docker pull ghcr.io/batonogov/xray-health-exporter:latest
```

> The Docker image runs as an unprivileged user `xray` (UID 10001)

**Helm (Kubernetes):**

```bash
helm repo add batonogov https://batonogov.github.io/helm-charts
helm install xray-health-exporter batonogov/xray-health-exporter -f values.yaml
```

See [`charts/xray-health-exporter`](https://github.com/batonogov/helm-charts/tree/main/charts/xray-health-exporter) — the chart includes leader election, RBAC for Lease, and an optional `ServiceMonitor`.

## Quick Start

1. **Create a configuration file** `config.yaml`:

```yaml
defaults:
  check_url: "https://www.google.com"
  check_interval: "30s"
  check_timeout: "30s"

# Subscriptions (optional) — automatic server fetching
subscriptions:
  - url: "https://provider.example.com/api/v1/client/subscribe?token=xxx"
    update_interval: "1h"

tunnels:
  # Option 1: VLESS URL
  - name: "Server 1"
    url: "vless://uuid@host1:443?type=tcp&security=reality&pbk=...&sni=google.com"

  # Option 2: native Xray JSON config (any protocol)
  - name: "Server 2"
    xray_config_file: "/etc/xray/server2.json"
```

See [config.example.yaml](config.example.yaml) for a full example.

2. **Run:**

```bash
# Docker
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -p 9273:9273 \
  ghcr.io/batonogov/xray-health-exporter:latest

# Locally (requires Go 1.26+)
export CONFIG_FILE=./config.yaml
./xray-health-exporter-linux-amd64
```

## Metrics

All metrics contain labels: `name`, `server`, `security`, `sni`

- `xray_tunnel_up{name, server, security, sni}` - tunnel status (1=up, 0=down)
- `xray_tunnel_latency_seconds{name, server, security, sni}` - connection latency
- `xray_tunnel_check_total{name, server, security, sni, result}` - check counter
- `xray_tunnel_last_success_timestamp{name, server, security, sni}` - timestamp of the last successful check
- `xray_tunnel_http_status{name, server, security, sni}` - HTTP status code from the check
- `xray_exporter_leader` - 1 if this instance is actively probing tunnels (leader or leader election is disabled), 0 otherwise

**Example metrics:**
```
xray_tunnel_up{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 1
xray_tunnel_latency_seconds{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 0.345
xray_tunnel_check_total{name="Server 1",server="example.com:443",security="reality",sni="google.com",result="success"} 42
xray_tunnel_last_success_timestamp{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 1704117344
xray_tunnel_http_status{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 200
```

> The `name` label contains the tunnel name from the config (or `host:port` if no name is specified). Labels allow monitoring multiple servers simultaneously

**Endpoints:**
- `/metrics` - Prometheus metrics
- `/health` - healthcheck

## Configuration

Configuration is specified via a YAML file. Example:

```yaml
# Global defaults (optional)
defaults:
  check_url: "https://www.google.com"
  check_interval: "30s"
  check_timeout: "30s"

# Subscriptions — automatic server fetching (optional)
subscriptions:
  - url: "https://provider.example.com/subscribe?token=xxx"
    update_interval: "1h"  # how often to update (default: 1h)

# List of tunnels to monitor
tunnels:
  # Option 1: VLESS URL
  - url: "vless://uuid@host:443?type=tcp&security=reality&pbk=...&sni=google.com"

  # Option 2: native Xray JSON config (any protocol/transport)
  - name: "VMess Server"
    xray_config_file: "/etc/xray/vmess.json"

  # With overridden parameters
  - name: "Backup Server"
    url: "vless://uuid@host:443?..."
    check_url: "https://1.1.1.1"
    check_interval: "60s"
    check_timeout: "45s"
```

**Tunnel parameters:**
- `name` (optional) - tunnel name for logs. If not specified, `host:port` is used
- `url` - VLESS connection URL (mutually exclusive with `xray_config_file`)
- `xray_config_file` - path to a native Xray JSON config (mutually exclusive with `url`). The user provides only the outbound; a SOCKS5 inbound is injected automatically
- `check_url` (optional) - URL for availability checks
- `check_interval` (optional) - interval between checks
- `check_timeout` (optional) - check timeout

**Subscription parameters:**
- `url` (required) - subscription URL (returns a base64-encoded or plain text server list)
- `update_interval` (optional) - update interval (default: `1h`)

**Notes:**
- At least one tunnel or subscription must be specified
- SOCKS ports are assigned automatically starting from 1080 (1080, 1081, 1082...)
- Duration format: "30s", "1m", "1h30m"
- If a parameter is not specified for a tunnel, the value from `defaults` is used
- If not specified in `defaults`, the global default value is used

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_FILE` | `/app/config.yaml` | Path to YAML configuration |
| `LISTEN_ADDR` | `:9273` | HTTP server address |
| `LOG_FORMAT` | `text` | Log format: `text` or `json` |
| `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `XRAY_LOG_LEVEL` | `warning` | Xray log level |
| `DEBUG` | `false` | (Deprecated) Verbose output, use `LOG_LEVEL=debug` instead |
| `LEADER_ELECTION` | `false` | Enable k8s leader election (see below) |
| `LEADER_ELECTION_NAMESPACE` | pod namespace | Namespace for the Lease object |
| `LEADER_ELECTION_NAME` | `xray-health-exporter` | Lease name |
| `LEADER_ELECTION_IDENTITY` | `$HOSTNAME` | Unique replica ID |

## High Availability (Kubernetes)

> Ready-made Helm chart: **[`batonogov/xray-health-exporter`](https://github.com/batonogov/helm-charts/tree/main/charts/xray-health-exporter)** — deploys the exporter with everything below out of the box (replicas, leader election, RBAC for Lease, optional `ServiceMonitor` / `PrometheusRule`).
>
> ```bash
> helm repo add batonogov https://batonogov.github.io/helm-charts
> helm install xray-health-exporter batonogov/xray-health-exporter \
>   -f values.yaml
> ```

When running with `replicas: >1` and scraping via `ServiceMonitor`, Prometheus will hit each pod independently, duplicating tunnel metrics. To solve this, enable leader election:

```yaml
env:
  - name: LEADER_ELECTION
    value: "true"
  - name: LEADER_ELECTION_IDENTITY
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: LEADER_ELECTION_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
```

Behavior:
- Only the leader initializes Xray tunnels and publishes `xray_tunnel_*` metrics; `xray_exporter_leader=1`.
- Followers respond to `/metrics` and `/health` but publish only `xray_exporter_leader=0` (no `xray_tunnel_*` series).
- On graceful leader termination (SIGTERM), the Lease is released immediately (`ReleaseOnCancel`), and a follower takes over within ~`RetryPeriod` (~5s). On a hard crash — within `LeaseDuration` (~30s).

**Warning:** If multiple different exporter deployments run in the same namespace, you **must** set a unique `LEADER_ELECTION_NAME` for each — otherwise they will contend for the same Lease.

**Warning:** `LEADER_ELECTION=true` requires running inside a Kubernetes pod (`InClusterConfig` is used). Outside a cluster, the exporter will fail with a config loading error.

Minimal RBAC (creates and updates Lease):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: xray-health-exporter
rules:
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "create", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: xray-health-exporter
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: xray-health-exporter
subjects:
  - kind: ServiceAccount
    name: xray-health-exporter
```

Since followers do not publish any `xray_tunnel_*` metrics, standard alerts (`xray_tunnel_up == 0`, `xray_tunnel_latency_seconds > X`) fire only on leader data — duplicates are excluded without additional PromQL filters.

## Prometheus

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'xray-health'
    static_configs:
      - targets: ['localhost:9273']
```

Alert examples:

```yaml
groups:
  - name: xray
    rules:
      # Tunnel is down
      - alert: XrayTunnelDown
        expr: xray_tunnel_up == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Tunnel {{ $labels.name }} is down"
          description: "Tunnel {{ $labels.name }} ({{ $labels.server }}, {{ $labels.security }}) has been down for more than 5 minutes"

      # High latency
      - alert: XrayHighLatency
        expr: xray_tunnel_latency_seconds > 2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High latency on {{ $labels.name }}"
          description: "Tunnel {{ $labels.name }} has latency of {{ $value }}s (threshold: 2s)"

      # Tunnel not checked recently
      - alert: XrayNoRecentCheck
        expr: (time() - xray_tunnel_last_success_timestamp) > 300
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.name }} has not been checked recently"
          description: "Tunnel {{ $labels.name }} has not been successfully checked for {{ $value }}s"
```

## Development

```bash
# Install pre-commit hooks
task install-hooks

# Run tests
task test
# or
go test -v -cover ./...

# Run tests with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Local build
task build
```

### CI/CD

**Automated testing in Pull Requests:**
- All tests run on every PR
- Code coverage check (minimum 65%)
- Code formatting check
- Build check
- Automatic comment with results in PR

**Pre-commit checks:**
- Go formatting (`go fmt`)
- Run tests
- Build check
- **Secret protection** (gitleaks, detect-private-key)

## License

MIT
