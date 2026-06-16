# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## О проекте

Prometheus exporter на Go для мониторинга туннелей Xray-core. Поддерживает VLESS URL, нативные Xray JSON-конфиги (`xray_config_file`) и subscription URL для автоматического получения серверов. Использует встроенный Xray-core (`github.com/xtls/xray-core`) как библиотеку — не запускает внешний процесс. Для каждого туннеля поднимается локальный SOCKS5 inbound, через который выполняются health-check запросы.

Три selectable check-метода per-tunnel через `check_method`: `http` (default, GET + 2xx/3xx), `ip` (IP-echo через прокси, сравнение с real public IP хоста), `download` (скачивание ≥ `download_min_size` байт). Latency во всех методах — **TTFB** (time to first byte) через `net/http/httptrace`.

Режимы запуска: постоянный (HTTP-сервер с pull `/metrics`), опциональный push в Prometheus Pushgateway, опциональная Kubernetes leader election, и `RUN_ONCE` для однократного прогона (CI/скрипты).

## Команды

Task runner — `Taskfile.yml` (https://taskfile.dev). Требуется Go 1.26+. **Entrypoint — `./cmd/exporter`** (не `.`).

```bash
task build          # go build -ldflags="... -X main.Version=... -X main.Commit=..." -o xray-health-exporter ./cmd/exporter
task test           # go test -v -cover ./...
task test-race      # с детектором гонок
task test-coverage  # с отчётом покрытия (coverage.out)
task ci-test        # полный CI прогон: fmt + build + race + coverage
task run            # go run ./cmd/exporter
task docker-build
```

Запуск одного теста:
```bash
go test -v -run TestИмя ./...
```

Локальный запуск: `CONFIG_FILE=./config.yaml go run ./cmd/exporter` (по умолчанию слушает `:9273`).

CI требует покрытие ≥ 75%.

## Архитектура

После рефакторинга (#111) монолитный `main.go` разбит на пакетную структуру:

```
cmd/exporter/        — entrypoint: main.go (run-mode dispatch, HTTP-сервер, Basic Auth), auth.go
internal/config/     — YAML-конфиг, defaults, env-overrides, subscriptions
internal/checker/    — реализация health-checks (DefaultChecker: http/ip/download)
internal/tunnel/     — TunnelManager, TunnelInstance, Xray lifecycle, watchers, RunOnce
internal/metrics/    — Prometheus-метрики (metrics.go) + Pushgateway push (push.go)
internal/socks/      — SOCKS5 dialer
internal/leaderelection/ — k8s lease-based leader election (опционально)
```

### Ключевые сущности

- **`internal/config`** — `Config` / `Defaults` / `Tunnel` / `Subscription`. `Defaults` задаёт значения по умолчанию, каждый `Tunnel` переопределяет. `Tunnel` поддерживает два взаимоисключающих режима: `url` (VLESS URL) и `xray_config_file` (путь к нативному Xray JSON). Поля check-методов: `CheckMethod`, `IPCheckURL`, `DownloadURL`, `DownloadTimeout`, `DownloadMinSize`. Валидация — `Tunnel.Validate()` и `ValidateTunnels()`. Приоритет дефолтов: YAML `defaults:` → env vars (`ApplyEnvDefaults`) → built-in константы.
- **`internal/checker`** — `DefaultChecker` реализует `tunnel.HealthChecker`. `Check()` диспетчеризует по `ti.CheckMethod`: `checkByIP` / `checkByDownload` / `PerformCheck` (http). TTFB-инструментирование через helper'ы `ttfbRequest` + `resolveLatency` (fallback на `time.Since(start)` если callback не сработал). `ResolveRealIP` — единоразовый резолв real public IP для ip-метода (lazy через `sync.Once` если не задан на старте).
- **`internal/tunnel`** — `TunnelInstance` (конфиг + `*core.Instance` + SOCKS-порт + `MetricLabels` + параметры check-метода), `TunnelManager` (список активных инстансов под мьютексом, горячий reload). `HealthChecker` / `MetricsUpdater` — DI-интерфейсы. `VLESSConfig` — `nil` для `xray_config_file` туннелей. SOCKS-порты назначаются последовательно от `DefaultSocksPort` (1080), либо `socks_port` per-tunnel (#99).
  - `xray.go`: `ParseVLESSURL`, `CreateXrayConfig` / `CreateStreamSettings` (генерация JSON для in-process Xray: SOCKS5 inbound → outbound), `LoadXrayConfigFile` (загрузка нативного Xray-конфига + инъекция SOCKS5 inbound), `ExtractMetricLabelsFromXrayConfig` (метки из первого outbound: vnext для VLESS/VMess, servers для Trojan/Shadowsocks), `StartXray` (`core.StartInstance`).
  - `manager.go`: `InitializeTunnels`, `RunTunnelChecker` (цикл проверок + backoff), `BackoffDuration`, `WaitForSOCKSPort`, `CleanupRemovedTunnelMetrics`, `NewPrometheusMetrics` (реализация `MetricsUpdater`), `RunProbing` (точка входа daemon-режима: инициализация + watchers + checker-горутины).
  - `watcher.go`: `WatchConfigFile` (fsnotify → reload), `WatchSubscriptions` (периодическое обновление подписок по минимальному `update_interval`).
  - `run_once.go`: `RunOnce` — один цикл проверок по всем туннелям, вывод метрик в Prometheus text-exposition в `io.Writer`, выход. Watchers/server/leader-election не стартуют.
- **`internal/metrics`** — все Prometheus-метрики (`metrics.go`) и опциональный push в Pushgateway (`push.go`). `ParsePushURL` вырезает креды из URL, `ReadPushConfig` читает `METRICS_PUSH_*`, `PushMetrics`/`PushLoop` выполняют push только когда инстанс — leader (fail-closed через gauge `xray_exporter_leader`).
- **`internal/socks`** — `SOCKS5Dialer.DialContext`.
- **`internal/leaderelection`** — `ReadLeaderElectionConfig` (читает `LEADER_ELECTION_*`), `RunWithLeaderElection` (k8s lease, запускает `tunnel.RunProbing` только на leader; требует in-cluster config).

### Режимы запуска (dispatch в `cmd/exporter/main.go`)

1. **`RUN_ONCE=true`** — `tunnel.RunOnce` → один прогон → печать метрик в stdout → `os.Exit` (0 = все up, 1 = есть down/ошибка). Логи идут в **stderr**, watchers/HTTP/leader-election не стартуют.
2. **`LEADER_ELECTION=true`** — `RunWithLeaderElection` (только в k8s-поде).
3. **Иначе (default)** — daemon: инициализация туннелей, checker-горутины (`RunTunnelChecker`), HTTP-сервер (`/metrics`, `/health`), config/subscription watchers, опциональный `PushLoop`. Shutdown по SIGINT/SIGTERM.

### Важные детали

- SOCKS-порты раздаются автоматически начиная с 1080 — не хардкодить порт в туннеле (если не задан явный `socks_port`).
- Xray-core встроен как библиотека: в `CreateXrayConfig` формируется сырой JSON, парсится через `serial.LoadJSONConfig`. При изменении схемы конфига Xray возможны несовместимости — смотреть версию в `go.mod`.
- `WaitForSOCKSPort` даёт Xray время на старт перед первой проверкой.
- Горячий reload: сравниваются старые и новые туннели, не изменившиеся переиспользуются (важно — не пересоздавать Xray instance без необходимости, порты могут конфликтовать). Метрики исчезнувших туннелей удаляются через `CleanupRemovedTunnelMetrics`.
- `xray_config_file` — пользователь задаёт только outbound часть, SOCKS5 inbound инжектится автоматически. Поддерживает все текущие и будущие протоколы/транспорты Xray-core.
- Подписки обновляются периодически по `update_interval`. При изменении списка серверов туннели пересоздаются аналогично hot reload. Ограничения: все подписки обновляются по минимальному `update_interval` из всех; добавление подписок через hot reload конфига не запускает новый watcher (требуется перезапуск).
- `/metrics` может защищаться Basic Auth (`METRICS_PROTECTED=true`); креды сравниваются через `crypto/subtle.ConstantTimeCompare` безусловно (оба поля). `/health` всегда открыт (для k8s probes).
- Push в Pushgateway — complementary: pull-эндпоинт `/metrics` остаётся доступным; push идёт только от leader.

## Переменные окружения

| Переменная | Default | Назначение |
|---|---|---|
| `CONFIG_FILE` | `/app/config.yaml` | Путь к YAML-конфигу |
| `LISTEN_ADDR` | `:9273` | Адрес HTTP-сервера |
| `LOG_FORMAT` | `text` | `text` или `json` |
| `LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `XRAY_LOG_LEVEL` | `warning` | Уровень логов встроенного Xray |
| `DEBUG` | `false` | Deprecated — используйте `LOG_LEVEL=debug` |
| `RUN_ONCE` | `false` | `true` — однократный прогон, печать метрик в stdout, выход |
| `CHECK_METHOD` | `http` | Метод проверки по умолчанию: `http`/`ip`/`download` |
| `IP_CHECK_URL` | `https://api.ipify.org?format=text` | IP-echo URL для метода `ip` |
| `DOWNLOAD_URL` | `https://proof.ovh.net/files/1Mb.dat` | URL файла для метода `download` |
| `DOWNLOAD_TIMEOUT` | `60s` | Таймаут для метода `download` |
| `DOWNLOAD_MIN_SIZE` | `51200` | Минимум байт для метода `download` |
| `METRICS_PROTECTED` | `false` | `true` — включить Basic Auth на `/metrics` |
| `METRICS_USERNAME` | `metricsUser` | Логин Basic Auth |
| `METRICS_PASSWORD` | _(обязателен при `METRICS_PROTECTED=true`)_ | Пароль Basic Auth |
| `METRICS_PUSH_URL` | _(пусто)_ | Полный URL Pushgateway (с `user:pass@`); пусто — push отключён |
| `METRICS_PUSH_INTERVAL` | min `check_interval`, или `30s` | Интервал push |
| `METRICS_INSTANCE` | `os.Hostname()` | Label `instance` для push |
| `LEADER_ELECTION` | `false` | `true` — включить k8s leader election (только в поде) |
| `LEADER_ELECTION_NAMESPACE` | _(из SA или required)_ | Namespace |
| `LEADER_ELECTION_NAME` | `xray-health-exporter` | Имя lease-объекта |
| `LEADER_ELECTION_IDENTITY` | `HOSTNAME`/`os.Hostname()` | Identity лидера |

## Метрики

Все tunnel-метрики имеют labels `name, server, security, sni`.

- `xray_tunnel_up` (gauge) — статус туннеля (1=up, 0=down)
- `xray_tunnel_latency_seconds` (gauge) — TTFB (time to first byte)
- `xray_tunnel_latency_histogram_seconds` (histogram) — TTFB для перцентилей
- `xray_tunnel_check_total` (counter, labels + `result`) — счётчик проверок
- `xray_tunnel_last_success_timestamp` (gauge) — timestamp последнего успеха
- `xray_tunnel_http_status` (gauge) — HTTP-статус последней проверки
- `xray_tunnel_error_total` (counter, labels + `error_type`) — счётчик ошибок, типы через `ClassifyError`

Экспортёр-метрики: `xray_exporter_build_info` (version/go_version/commit), `xray_exporter_uptime_seconds`, `xray_exporter_leader`, `xray_exporter_config_reload_total`, `xray_exporter_config_reload_errors_total`, `xray_exporter_tunnels_configured`.

## Не коммитить

`docs/superpowers/` — это артефакты superpowers-скиллов, не относятся к проекту. Директория в `.gitignore`, но если файлы уже отслеживаются git — не добавлять в коммиты.

## Релизы

Автоматизированы через release-please (`release-please-config.json`, `release-type: go`). Tag-based SemVer — версии формируются из conventional commits. Конфиг скрывает из CHANGELOG типы `docs`/`ci`/`test`/`style`/`build` (`changelog-sections`). Версия прокидывается через `-ldflags="-X main.Version=... -X main.Commit=..."` (`task build`). Актуальный релиз — **v1.6.0**.
