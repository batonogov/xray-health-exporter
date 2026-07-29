# Configuration

Configuration sources, from highest to lowest priority: per-tunnel YAML → YAML `defaults:` → the five supported env defaults (`CHECK_METHOD`, `IP_CHECK_URL`, `DOWNLOAD_URL`, `DOWNLOAD_TIMEOUT`, `DOWNLOAD_MIN_SIZE`) → built-in constants in [`internal/metrics`](../internal/metrics/metrics.go). Other environment variables configure the process rather than tunnel defaults.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `CONFIG_FILE` | `/app/config.yaml` | Path to the YAML config |
| `LISTEN_ADDR` | `:9273` | HTTP server address |
| `LOG_FORMAT` | `text` | `text` or `json` |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` (`warning`) / `error` |
| `XRAY_LOG_LEVEL` | `warning` | Log level of the embedded Xray |
| `DEBUG` | `false` | Deprecated — use `LOG_LEVEL=debug` |
| `RUN_ONCE` | `false` | `true` → single check cycle, print metrics to stdout, exit |
| `CHECK_METHOD` | `http` | Default check method: `http` / `ip` / `download` |
| `IP_CHECK_URL` | `https://api.ipify.org?format=text` | IP-echo URL for the `ip` method |
| `DOWNLOAD_URL` | `https://proof.ovh.net/files/1Mb.dat` | File URL for the `download` method |
| `DOWNLOAD_TIMEOUT` | `60s` | Timeout for the `download` method |
| `DOWNLOAD_MIN_SIZE` | `51200` | Minimum bytes for the `download` method |
| `METRICS_PROTECTED` | `false` | `true` → enable Basic Auth on `/metrics` |
| `METRICS_USERNAME` | `metricsUser` | Basic Auth username |
| `METRICS_PASSWORD` | _(required when `METRICS_PROTECTED=true`)_ | Basic Auth password |
| `METRICS_PUSH_URL` | _(empty)_ | Full Pushgateway URL (may include `user:pass@`); empty disables push |
| `METRICS_PUSH_INTERVAL` | min `check_interval`, or `30s` | Push interval (Go duration string) |
| `METRICS_INSTANCE` | `os.Hostname()` | Value of the `instance` grouping label for pushed metrics |
| `LEADER_ELECTION` | `false` | `true` → enable k8s leader election (pod only) |
| `LEADER_ELECTION_NAMESPACE` | _(from ServiceAccount, or required)_ | Namespace for the Lease object |
| `LEADER_ELECTION_NAME` | `xray-health-exporter` | Lease name |
| `LEADER_ELECTION_IDENTITY` | `$HOSTNAME` / `os.Hostname()` | Leader identity |

## YAML schema

### `defaults` (optional)

Applied to every tunnel unless the tunnel overrides the field.

| Field | Type | Default | Notes |
|---|---|---|---|
| `check_url` | string | `https://www.google.com` | URL for `http` checks |
| `check_interval` | duration | `30s` | Time between checks |
| `check_timeout` | duration | `30s` | Per-check timeout |
| `max_backoff` | duration | `5m` | Max backoff on repeated failures; must be a valid Go duration |
| `backoff_multiplier` | float | `2.0` | Backoff growth factor; must be ≥ 1.0 |
| `check_method` | string | `http` | `http` / `ip` / `download` |
| `ip_check_url` | string | `https://api.ipify.org?format=text` | IP-echo URL for `ip` |
| `download_url` | string | `https://proof.ovh.net/files/1Mb.dat` | File URL for `download` |
| `download_timeout` | duration | `60s` | Timeout for `download` |
| `download_min_size` | int | `51200` | Minimum bytes for `download` |

### `subscriptions` (optional, list)

| Field | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | Returns a plain-text or standard/URL-safe Base64 server list |
| `update_interval` | no | `1h` | How often to refresh |

Only lowercase `vless://` URLs are accepted from subscription responses; other entries are skipped. Fetches use a 30-second timeout and read at most 10 MiB. A tunnel name comes from the URL fragment, or from `host:port` when the fragment is absent.

The watcher cadence is calculated once at startup from the shortest configured `update_interval`. Adding the first subscription through hot reload fetches it once but does not start periodic refresh; changing intervals does not retune an existing watcher. Restart the exporter to apply either watcher change.

#### VLESS URL compatibility

The URL parser follows the current Xray share-link proposal:

| Area | Supported values |
|---|---|
| Transport | `tcp`/`raw`, `xhttp`/`splithttp`, `grpc`, `ws`/`websocket`, `httpupgrade`, `kcp`/`mkcp` |
| VLESS | `encryption`, `flow` |
| XHTTP | `host`, `path`, `mode` (`auto`, `packet-up`, `stream-up`, `stream-one`), `extra` (JSON object) |
| gRPC | `serviceName` (required), `authority`, `mode` (`gun`, `guna`, `multi`), `multiMode=true` |
| WebSocket / HTTPUpgrade | `host`, `path` |
| mKCP | `mtu`, `tti` |
| Security | `none`, `tls`, `reality` |
| TLS | `sni`, `fp`, `alpn`, `ech`, `pcs`, `vcn` |
| REALITY | `pbk`, `sid`, `pqv`, `spx` |
| Additional | `fm` (FinalMask JSON) |

Legacy `type=http`, `h2`, and `h3` links are normalized to XHTTP `stream-one`. For TLS and REALITY, `sni` defaults to the server address and `fp` defaults to `chrome`; REALITY requires `pbk`. The parser validates the presence of UUID and address, the port range, duplicate parameters, positive mKCP integers, and JSON-valued `extra`/`fm` before Xray starts.

### `tunnels` (list)

Each tunnel has **either** `url` **or** `xray_config_file` (mutually exclusive).

| Field | Type | Notes |
|---|---|---|
| `name` | string | Optional; defaults to `host:port`. Used in logs and as the `name` metric label |
| `url` | string | VLESS connection URL |
| `xray_config_file` | string | Path to a native Xray JSON config. The exporter replaces `log` and `inbounds`; other sections are preserved |
| `check_url` | string | Overrides `defaults.check_url` |
| `check_interval` | duration | Overrides `defaults.check_interval` |
| `check_timeout` | duration | Overrides `defaults.check_timeout` |
| `max_backoff` | duration | Overrides `defaults.max_backoff`; must be a valid Go duration |
| `backoff_multiplier` | float | Overrides `defaults.backoff_multiplier`; must be ≥ 1.0 |
| `socks_port` | int | Optional; auto-assigned from 1080 if unset. Validated unique, range 1–65535 |
| `check_method` | string | `http` / `ip` / `download` |
| `ip_check_url` | string | IP-echo URL for `ip` |
| `download_url` | string | File URL for `download` |
| `download_timeout` | duration | Timeout for `download` |
| `download_min_size` | int | Minimum bytes for `download` |

Runtime support for a native JSON config is limited to protocols and transports registered by the Xray-core version pinned in `go.mod`. Metric labels are derived from the first outbound when it uses VLESS/VMess `vnext` or Trojan/Shadowsocks `servers`; otherwise labels may be empty.

Duration format: Go duration strings (`30s`, `1m`, `1h30m`). At least one tunnel or subscription is required. See [`config.example.yaml`](../config.example.yaml) for a full example.
