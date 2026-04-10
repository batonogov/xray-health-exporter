# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## О проекте

Prometheus exporter на Go для мониторинга множественных VLESS туннелей. Использует встроенный Xray-core (`github.com/xtls/xray-core`) как библиотеку — не запускает внешний процесс. Для каждого туннеля поднимается локальный SOCKS5 inbound, через который выполняются HTTP health-check запросы.

## Команды

Task runner — `Taskfile.yml` (https://taskfile.dev). Требуется Go 1.25+.

```bash
task build          # сборка бинарника
task test           # go test -v -cover ./...
task test-race      # с детектором гонок
task test-coverage  # с отчётом покрытия (coverage.out)
task ci-test        # полный CI прогон: fmt + build + race + coverage
task run            # go run .
task docker-build
```

Запуск одного теста:
```bash
go test -v -run TestИмя ./...
```

Локальный запуск: `CONFIG_FILE=./config.yaml go run .` (по умолчанию слушает `:9273`).

CI требует покрытие ≥ 65%.

## Архитектура

Весь код в одном файле — `main.go` (~1000 строк). Тесты в `main_test.go`. Ключевые сущности:

- **Config / Defaults / Tunnel** (`main.go:98+`) — YAML-конфиг. `Defaults` задаёт значения по умолчанию, каждый `Tunnel` может их переопределить. Валидация — `Tunnel.Validate()` и `validateTunnels()`.
- **VLESSConfig** (`main.go:117`) — распарсенный VLESS URL (`parseVLESSURL`). Поддерживает `security`: tls/reality/none, transport: tcp/ws/grpc и т.д.
- **createXrayConfig / createStreamSettings** (`main.go:231`, `:278`) — генерируют JSON-конфиг для Xray in-process: SOCKS5 inbound на `socksPort` → VLESS outbound. Стартует через `startXray()` (`core.StartInstance`).
- **TunnelInstance** (`main.go:130`) — связка `Tunnel` + `*core.Instance` + выделенный SOCKS порт + HTTP client, который ходит через этот SOCKS (`socks5Dialer`, `main.go:403`). SOCKS порты назначаются последовательно от `baseSocksPort` (по умолчанию 1080).
- **TunnelManager** (`main.go:142`) — держит список активных `TunnelInstance`ов под мьютексом, умеет горячую перезагрузку конфига (`reloadConfig`, `main.go:766`). `watchConfigFile` (`main.go:808`) через fsnotify отслеживает изменения `CONFIG_FILE` и вызывает reload; при reload метрики для исчезнувших туннелей удаляются через `cleanupRemovedTunnelMetrics`.
- **checkTunnel / runTunnelChecker** (`main.go:502`, `:602`) — цикл проверок на туннель: делает HTTP GET через SOCKS, обновляет Prometheus метрики (`xray_tunnel_up`, `_latency_seconds`, `_check_total`, `_last_success_timestamp`, `_http_status`). Все метрики имеют labels `name, server, security, sni` — см. `tunnelMetricLabels`.
- **main()** (`main.go:951`) — загружает конфиг, инициализирует туннели, запускает checker-горутины, HTTP сервер (`/metrics`, `/health`), config watcher, обрабатывает SIGINT/SIGTERM → `stopTunnels`.

### Важные детали

- SOCKS порты раздаются автоматически начиная с 1080 — не хардкодить порт в туннеле.
- Xray-core встроен как библиотека: в `createXrayConfig` формируется сырой JSON, парсится через `serial.LoadJSONConfig`. При изменении схемы конфига Xray возможны несовместимости — смотреть версию в `go.mod`.
- `waitForSOCKSPort` (`main.go:620`) даёт Xray время на старт перед первой проверкой.
- Горячий reload: сравниваются старые и новые туннели, не изменившиеся переиспользуются (важно — не пересоздавать Xray instance без необходимости, порты могут конфликтовать).

## Переменные окружения

`CONFIG_FILE` (default `/app/config.yaml`), `LISTEN_ADDR` (`:9273`), `XRAY_LOG_LEVEL` (`warning`), `DEBUG` (`false`).

## Релизы

Автоматизированы через release-please (`release-please-config.json`, см. коммит 4de0159). Используется tag-based SemVer — версии формируются из conventional commits. В `task build` версия прокидывается через `-ldflags="-X main.Version=..."`.
