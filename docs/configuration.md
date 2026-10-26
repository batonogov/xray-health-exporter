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
| `METRICS_PUSH_INTERVAL` | min static-tunnel `check_interval`, or `30s` | Set once at startup; subscription tunnels are not included in the inferred minimum |
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
| `url` | yes | — | Absolute HTTP(S) subscription URL |
| `name` | no | `subscription-N` in metrics | Stable, nonsecret source name |
| `update_interval` | no | `1h` | Positive Go duration; scheduled separately per source |
| `timeout` | no | `30s` | Positive request timeout |
| `format` | no | `auto` | `auto`, `text`, `xray`, or `clash` |
| `user_agent` | no | Go HTTP client default | Override User-Agent for provider compatibility |
| `headers` | no | — | Map of request headers, including provider authentication |

Supported response formats:

- Plain-text or standard/URL-safe Base64 lists of `vless://`, `vmess://`, `trojan://`, and `ss://` links. Exact duplicate lines are collapsed. Names come from link fragments or VMess remarks, with generated fallbacks.
- Native Xray JSON: one complete config or an array of configs. Each config becomes one monitored tunnel; its routing and outbounds stay together. Exporter-controlled logging and a local SOCKS inbound replace the supplied `log` and `inbounds`.
- Clash YAML/JSON proxy lists for the supported protocol and transport subset. These are converted into individual Xray tunnels; Clash policy groups and routing are not executed. Unsupported proxy options fail explicitly.

Clash conversion supports `tcp`, `ws`, and `grpc`, TLS with certificate verification, and VLESS Reality. Common fields are `name`, `type`, `server`, `port`, and `udp`; protocol fields are `uuid`/`flow` (VLESS), `uuid`/`cipher`/`alterId: 0` (VMess), `password` (Trojan), and `cipher`/`password` (Shadowsocks). Transport fields are `ws-opts.path`, `ws-opts.headers`, and `grpc-opts.grpc-service-name`. TLS uses `servername` or `sni`, `client-fingerprint`, and `alpn`; Reality uses `reality-opts.public-key` and `reality-opts.short-id`. Nonzero VMess alter IDs, `skip-cert-verify: true`, external Shadowsocks plugins, and unsupported options are rejected.

VMess share links support Base64 JSON and URI forms. VMess ciphers are limited to `auto`, `aes-128-gcm`, and `chacha20-poly1305`; `none`, `zero`, and unknown values are rejected because the embedded core cannot preserve them. VMess KCP seeds are unsupported for both `kcp` and `mkcp` aliases. Shadowsocks supports SIP002 and legacy whole-link Base64; Trojan supports transport/TLS parameters shared with VLESS. Other client formats, including sing-box documents, SSR, and Hysteria share links, are not converted. Native Xray JSON remains the path for other configurations supported by the embedded core.

Requests are limited to 10 MiB. Empty, malformed, unsupported, and oversized responses are errors, rather than instructions to delete servers. Custom authentication headers are removed on cross-origin redirects. Subscription redirects never send a `Referer`, so URL path/query tokens are not forwarded. Errors do not include the subscription URL or response body.

Each source keeps its last successfully applied list **in memory** when refresh fails. A source without a usable cached list prevents the new configuration from being applied. In daemon mode, newly configured sources retry automatically on their schedules even if their first request fails. The cache does not survive restarts. Remove a source from YAML to intentionally remove its tunnels. Subscription metrics distinguish a failed refresh from unhealthy proxy servers. Applying an older staged response updates the accepted server count but preserves any newer fetch failure and the original successful fetch timestamp. `RUN_ONCE` fails if any subscription cannot be loaded, even if other sources work.

The watcher applies new sources and changed intervals without a restart. Unchanged tunnels retain their running Xray instances and SOCKS ports. New or modified tunnels start before removed instances stop. Replacing a changed tunnel that uses an already occupied explicit `socks_port` requires a restart or a different port; unchanged explicit ports are reused.

#### Upgrade behavior

Unsupported entries reject the entire subscription response; they are not silently skipped as in older VLESS-only subscriptions. Mixed lists containing unsupported protocols must be filtered by the provider before use. A failed initial source with no accepted cache blocks startup; failed refreshes retain accepted state in memory. Use explicit, unique source names to keep metric identities stable when reordering subscriptions.

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

### `tunnels` (optional list when subscriptions are configured)

Each tunnel has **either** `url` **or** `xray_config_file` (mutually exclusive).

| Field | Type | Notes |
|---|---|---|
| `name` | string | Optional; static tunnels use the extracted server endpoint, or `tunnel-port-N` if unavailable. Subscription names come from their format-specific metadata or generated fallbacks |
| `url` | string | VLESS, VMess, Trojan, or Shadowsocks connection URL |
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

Duration format: Go duration strings (`30s`, `1m`, `1h30m`). Use strictly positive check intervals and timeouts: unlike subscription intervals, the current tunnel validation does not reject every nonpositive duration; `check_interval: "0s"` can crash the checker. At least one tunnel or subscription is required. See [`config.example.yaml`](../config.example.yaml) for a full example.

Native `xray_config_file` paths resolve inside the exporter process/container, not relative to the YAML file. Mount these files separately when using Docker; mounting only `config.yaml` is insufficient. Replace all demo credentials/URLs and remove unused sample entries before starting.
