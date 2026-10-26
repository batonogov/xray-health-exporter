# Check methods

Three health-check methods, selectable per tunnel via `check_method` (or globally via `defaults.check_method` / the `CHECK_METHOD` env var). All three measure successful-check latency as **TTFB** (time to first byte) using `net/http/httptrace`.

## `http` (default)

Performs a `GET` against `check_url` through the tunnel's SOCKS5 proxy. The current implementation accepts status **200, 301, 302, or 307**.

- Pass: HTTP status is 200, 301, 302, or 307.
- Fail: any other status, or an error before receiving an accepted response (classified into `xray_tunnel_error_total{reason=...}`).

The HTTP client follows redirects; the status check applies to the resulting response. After an accepted status, the checker reads up to 1024 response bytes. A body-read error is reported as a warning but the tunnel remains up.

## `ip`

Fetches an IP-echo service (`ip_check_url`, default `https://api.ipify.org?format=text`) **through the proxy** and compares the returned IP with the host's real public IP.

- Pass: status is 200 and the trimmed response body differs from the trimmed direct response.
- Fail: a non-200 status, identical response bodies, or a request/read error.

The current implementation compares strings, reading at most 256 bytes, and does not validate that either response is an IP address. Use a service that returns a plain-text IP, not JSON or HTML. Identical public IPs can also occur when the proxy shares the host’s egress; this check is a heuristic, not proof that traffic bypassed the proxy.

In daemon mode, the direct response is resolved once at startup using `IP_CHECK_URL` (or the built-in default), independently of YAML defaults and per-tunnel URLs. It is not periodically refreshed. If startup lookup fails, each `ip` check retries using that tunnel’s `ip_check_url`. RUN_ONCE uses the latter path for every tunnel. The direct retry has its own 30-second timeout, in addition to the proxied request timeout.

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
