# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, Cursor, Aider, Jules, etc.) working in this repository.
This file is the canonical source of agent guidance. `CLAUDE.md` is a thin pointer to it.

> Deep reference lives in [`docs/`](./docs/):
> [architecture](./docs/architecture.md) · [configuration](./docs/configuration.md) · [metrics](./docs/metrics.md) · [check-methods](./docs/check-methods.md)
> User-facing docs: [`README.md`](./README.md) (EN) / [`README.ru.md`](./README.ru.md) (RU)

## Project overview

Prometheus exporter on **Go 1.26+** for monitoring Xray-core tunnels. Supports VLESS URLs, native Xray JSON configs (`xray_config_file`), and subscription URLs for automatic server fetching. Uses **embedded Xray-core** (`github.com/xtls/xray-core`) as a library — it does **not** spawn an external process. For each tunnel a local SOCKS5 inbound is raised, and health checks run through it.

Three selectable check methods per tunnel via `check_method`: `http` (default, GET + accepted status), `ip` (IP-echo through the proxy compared to the host's real public IP), `download` (≥ `download_min_size` bytes received). The `http` method accepts status `200`, `301`, `302`, or `307`; `ip` and `download` require status `200`. Latency is **TTFB** (time to first byte) in all methods, instrumented via `net/http/httptrace`.

Run modes: daemon (HTTP server with `/metrics` + `/health`), optional push to Prometheus Pushgateway, optional Kubernetes leader election, and `RUN_ONCE` for a single check cycle (CI/scripts).

Entry point is **`./cmd/exporter`** (not `.`). Release versions are managed by release-please; use `.release-please-manifest.json`, `CHANGELOG.md`, or the latest GitHub release instead of hardcoding the current version in documentation.

## Build and test

Task runner: [`Taskfile.yml`](./Taskfile.yml) (https://taskfile.dev).

```bash
task build          # go build -ldflags="-X main.Version=dev -X main.Commit=dev" -o xray-health-exporter ./cmd/exporter
task test           # go test -v -cover ./...
task test-race      # with the race detector
task test-coverage  # writes coverage.out + prints per-function coverage
task ci-test        # local CI-like run: fmt + build + race + coverage summary
task run            # go run ./cmd/exporter
task docker-build
```

GitHub Actions additionally enforces the 75% coverage threshold and builds the Docker image; `task ci-test` does not.

Run a single test:

```bash
go test -v -run TestName ./...
```

Local run: `CONFIG_FILE=./config.yaml go run ./cmd/exporter` (listens on `:9273` by default).

## Conventions

- **Go formatting**: `gofmt -s` is enforced in CI; unformatted code fails the build.
- **Coverage gate**: CI requires **≥ 75%** total coverage (`THRESHOLD=75` in `.github/workflows/test.yml`).
- **Tests**: write/extend tests for code you change, even if not asked. Tests live next to source (`*_test.go`).
- **Conventional commits**: the repo uses release-please (`release-type: go`). Commit types `docs`/`ci`/`test`/`style`/`build` are hidden from the CHANGELOG.
- **Versioning**: version + commit are injected via `-ldflags="-X main.Version=... -X main.Commit=..."` (see `task build`).
- **Secrets**: never commit `config.yaml` (gitignored) or any credentials. Use [`config.example.yaml`](./config.example.yaml) as a template. Pre-commit runs gitleaks + private-key detection.
- **Language**: source comments, commit messages, PR descriptions, `README.md`, and `docs/*.md` are in English. Keep the Russian user-facing mirrors (`README.ru.md` and comments in `config.example.yaml`) aligned whenever behavior changes.

## Architecture (brief)

```
cmd/exporter/        — entrypoint: main.go (run-mode dispatch, HTTP server, Basic Auth), auth.go
internal/config/     — YAML config, defaults, env-overrides, subscriptions
internal/checker/    — health-check implementation (DefaultChecker: http/ip/download)
internal/tunnel/     — TunnelManager, TunnelInstance, Xray lifecycle, watchers, RunOnce
internal/metrics/    — Prometheus metrics (metrics.go) + Pushgateway push (push.go)
internal/socks/      — SOCKS5 dialer
internal/leaderelection/ — k8s lease-based leader election (optional)
```

Run-mode dispatch happens in `cmd/exporter/main.go`:

1. **`RUN_ONCE=true`** → `tunnel.RunOnce`: one cycle → metrics to **stdout** → exit (0 = all up, 1 = any down/error). Watchers/HTTP/leader-election do **not** start.
2. **`LEADER_ELECTION=true`** → `leaderelection.RunWithLeaderElection` (only inside a k8s pod).
3. **Otherwise (default)** → daemon: `tunnel.RunProbing` (init + watchers + checker goroutines) + HTTP server + optional `PushLoop`. Shutdown on SIGINT/SIGTERM.

See [`docs/architecture.md`](./docs/architecture.md) for the full package map, key entities, run-mode details, and the hot-reload lifecycle.

## Gotchas (read before touching tunnel/Xray code)

- **SOCKS ports** are auto-assigned starting at 1080 (1080, 1081, …). Do not hardcode a port unless a tunnel sets an explicit `socks_port` (validated unique, range 1–65535).
- **Embedded Xray**: `CreateXrayConfig` builds raw JSON; `StartXray` unmarshals it into `conf.Config`, calls `Build`, creates `core.Instance`, and starts it. Xray config-schema changes can break compatibility — check the pinned version in `go.mod`.
- **`WaitForSOCKSPort`** gives Xray time to start before the first check; respect it in new check paths.
- **Hot reload** compares old vs new tunnels; unchanged instances are reused. Do **not** recreate an Xray instance unnecessarily — ports can conflict. Metrics of removed tunnels are cleaned via `CleanupRemovedTunnelMetrics`.
- **`xray_config_file`**: the full JSON is loaded, but its `log` and `inbounds` sections are replaced with exporter-controlled settings (including one local SOCKS5 inbound). Other top-level sections, including `outbounds`, are preserved. Runtime support is limited to protocols and transports registered by the Xray-core version pinned in `go.mod`.
- **VLESS share links**: accepted transports are `tcp`/`raw`, `xhttp`/`splithttp`, `grpc`, `ws`/`websocket`, `httpupgrade`, and `kcp`/`mkcp`. Legacy `http`/`h2`/`h3` aliases normalize to XHTTP `stream-one`; unsupported transports, security values, duplicate query parameters, and malformed JSON parameters are rejected.
- **Subscriptions**: the watcher interval is calculated once at startup from the minimum `update_interval`. Server-list changes rebuild tunnels like hot reload. Only `vless://` URLs are accepted. Adding the first subscription via hot reload fetches it once but does **not** start a watcher; changing intervals or adding a shorter interval does not retune the existing watcher. Restart to apply either watcher change.
- **`/metrics`** can be protected by Basic Auth (`METRICS_PROTECTED=true`); credentials are compared via `crypto/subtle.ConstantTimeCompare`. `/health` is always open (for k8s probes).
- **Pushgateway push** is complementary: the pull `/metrics` endpoint stays available; push runs only on the leader (fail-closed via the `xray_exporter_leader` gauge).

## Metrics

All `xray_tunnel_*` metrics carry labels `name, server, security, sni`. The error counter uses the label **`reason`** (not `error_type`), with categories from `metrics.ClassifyError`: `timeout`, `dns`, `tls`, `connection_refused`, `connection_reset`, `bad_status`, `socks_error`, `unknown`.

Full list with types, buckets, and exporter-level metrics: [`docs/metrics.md`](./docs/metrics.md).

## Do not commit

- `config.yaml` — real config with secrets (gitignored).
- `.claude/` — local Claude Code state (gitignored).
- Binary `xray-health-exporter`, `coverage.out`, `*.test`.
