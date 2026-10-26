# Check methods

Three health-check methods, selectable per tunnel via `check_method` (or globally via `defaults.check_method` / the `CHECK_METHOD` env var). All three measure successful-check latency as **TTFB** (time to first byte) using `net/http/httptrace`.

## `http` (default)

Performs a `GET` against `check_url` through the tunnel's SOCKS5 proxy. The current implementation accepts status **200, 301, 302, or 307**.

- Pass: HTTP status is 200, 301, 302, or 307.
- Fail: any other status, or an error before receiving an accepted response (classified into `xray_tunnel_error_total{reason=...}`).

The HTTP client follows redirects; the status check applies to the resulting response. After an accepted status, the checker reads up to 1024 response bytes. A body-read error is reported as a warning but the tunnel remains up.

## `ip`

Fetches an IP-echo service (`ip_check_url`, default `https://api.ipify.org?format=text`) **through the proxy** and compares the returned IP with the host's real public IP.

- Pass: both requests return status 200 and a valid plain-text IPv4 or IPv6 address, and the canonical addresses differ.
- Fail: a non-200 status, invalid/empty/oversized response, incomplete body, identical addresses, or a request/read error. JSON and HTML are rejected.

Responses are limited to 256 bytes including surrounding whitespace. IPv6 spellings are normalized, and IPv4-mapped IPv6 addresses compare equal to their IPv4 counterparts. Scoped IPv6 addresses (such as `fe80::1%eth0`) are rejected. Identical public IPs can occur when a working proxy shares the host’s egress; this check remains a heuristic, not proof that traffic bypassed the proxy.

The direct and proxied requests use the same effective tunnel `ip_check_url`, including YAML defaults and per-tunnel overrides. Direct requests bypass HTTP proxy environment variables. No IP lookup runs during startup or for `http`/`download` checks. Daemon mode and RUN_ONCE use the same lazy lookup path.

Successful direct lookups are cached in memory for **5 minutes per endpoint URL**. Concurrent checks of the same endpoint share an in-flight lookup; different endpoints have independent cache entries. The first check after expiry refreshes the address. A failed refresh fails the check without using the expired address; later checks retry. The direct lookup (when needed), SOCKS connection, and proxied request share the tunnel’s `check_timeout` budget; direct requests also have a 30-second cap. Latency measures only the proxied request’s TTFB, excluding a direct lookup.

## `download`

Downloads a file (`download_url`) through the proxy and verifies that at least `download_min_size` bytes are received within `download_timeout`.

- Pass: status is 200 and byte count ≥ `download_min_size` before `download_timeout`.
- Fail: a non-200 status, fewer bytes, or a transport error.

## TTFB instrumentation

Latency is captured by `ttfbRequest` + `resolveLatency` via `httptrace.ClientTrace.GotFirstResponseByte`. For a successful check, if the trace callback does not fire, latency falls back to total elapsed time.

Latency is exposed both as a gauge (`xray_tunnel_latency_seconds`) and a histogram (`xray_tunnel_latency_histogram_seconds`).

## Configuration example

```yaml
defaults:
  check_method: "ip"
  ip_check_url: "https://api.ipify.org?format=text"
tunnels:
  - name: "Server 1"
    url: "vless://..."
    check_method: "download"
    download_url: "https://proof.ovh.net/files/1Mb.dat"
    download_min_size: 51200
    download_timeout: 60s
```

## Defaults

| Parameter | Default |
|---|---|
| `check_method` | `http` |
| `ip_check_url` | `https://api.ipify.org?format=text` |
| `download_url` | `https://proof.ovh.net/files/1Mb.dat` |
| `download_timeout` | `60s` |
| `download_min_size` | `51200` |
