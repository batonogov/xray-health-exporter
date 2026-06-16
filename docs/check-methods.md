# Check methods

Three health-check methods, selectable per tunnel via `check_method` (or globally via `defaults.check_method` / the `CHECK_METHOD` env var). All three measure latency as **TTFB** (time to first byte) using `net/http/httptrace`.

## `http` (default)

Performs a `GET` against `check_url` through the tunnel's SOCKS5 proxy and expects a **2xx or 3xx** status code. This is the original behaviour.

- Pass: HTTP status is 2xx/3xx.
- Fail: non-2xx/3xx status, or a transport error (classified into `xray_tunnel_error_total{reason=...}`).

## `ip`

Fetches an IP-echo service (`ip_check_url`, default `https://api.ipify.org?format=text`) **through the proxy** and compares the returned IP with the host's real public IP, resolved once at startup (`DefaultChecker.ResolveRealIP`, lazily via `sync.Once` if not provided).

- Pass: the proxy-reported IP **differs** from the real public IP → traffic is actually routing through the proxy.
- Fail: the IPs match (proxy not in use) or the request errors.

## `download`

Downloads a file (`download_url`) through the proxy and verifies that at least `download_min_size` bytes are received within `download_timeout`.

- Pass: byte count ≥ `download_min_size` before `download_timeout`.
- Fail: fewer bytes, or a transport error.

## TTFB instrumentation

Latency is captured by `ttfbRequest` + `resolveLatency` via `httptrace.ClientTrace.GotFirstResponseByte`. If the trace callback does not fire (e.g. the request failed before any byte), latency falls back to `time.Since(start)`.

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
