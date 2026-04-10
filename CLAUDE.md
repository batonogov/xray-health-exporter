# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## О проекте

Prometheus exporter на Go для мониторинга туннелей Xray-core. Поддерживает VLESS URL, нативные Xray JSON-конфиги (`xray_config_file`) и subscription URL для автоматического получения серверов. Использует встроенный Xray-core (`github.com/xtls/xray-core`) как библиотеку — не запускает внешний процесс. Для каждого туннеля поднимается локальный SOCKS5 inbound, через который выполняются HTTP health-check запросы.

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

- **Config / Defaults / Tunnel / Subscription** — YAML-конфиг. `Defaults` задаёт значения по умолчанию, каждый `Tunnel` может их переопределить. `Tunnel` поддерживает два режима: `url` (VLESS URL) и `xray_config_file` (путь к нативному Xray JSON-конфигу) — взаимоисключающие. `Subscription` — URL подписки с `update_interval`. Валидация — `Tunnel.Validate()` и `validateTunnels()`.
- **VLESSConfig** — распарсенный VLESS URL (`parseVLESSURL`). Поддерживает `security`: tls/reality/none, transport: tcp/ws/grpc и т.д.
- **MetricLabels** — абстракция меток Prometheus (Server, Security, SNI), не зависящая от конкретного протокола. Заполняется из VLESSConfig или извлекается из Xray JSON-конфига через `extractMetricLabelsFromXrayConfig`.
- **createXrayConfig / createStreamSettings** — генерируют JSON-конфиг для Xray in-process: SOCKS5 inbound на `socksPort` → VLESS outbound. Стартует через `startXray()` (`core.StartInstance`).
- **loadXrayConfigFile / extractMetricLabelsFromXrayConfig** — загрузка нативного Xray JSON-конфига: читает файл, инжектит SOCKS5 inbound и log, извлекает метки для Prometheus из первого outbound (поддерживает vnext для VLESS/VMess и servers для Trojan/Shadowsocks).
- **TunnelInstance** — связка конфига + `*core.Instance` + выделенный SOCKS порт + `MetricLabels`. `VLESSConfig` — `nil` для `xray_config_file` туннелей. SOCKS порты назначаются последовательно от `baseSocksPort` (по умолчанию 1080).
- **TunnelManager** — держит список активных `TunnelInstance`ов и текущий `Config` под мьютексом, умеет горячую перезагрузку конфига (`reloadConfig`). `watchConfigFile` через fsnotify отслеживает изменения `CONFIG_FILE` и вызывает reload; при reload метрики для исчезнувших туннелей удаляются через `cleanupRemovedTunnelMetrics`.
- **fetchSubscription / resolveSubscriptions** — получение списка серверов из subscription URL (base64-encoded или plain text). `resolveSubscriptions` итерирует все подписки, применяет defaults, возвращает список туннелей. Неудачные подписки логируются и пропускаются.
- **watchSubscriptions** — горутина периодического обновления подписок по минимальному `update_interval`, вызывает `reloadConfig`.
- **checkTunnel / runTunnelChecker** — цикл проверок на туннель: делает HTTP GET через SOCKS, обновляет Prometheus метрики (`xray_tunnel_up`, `_latency_seconds`, `_check_total`, `_last_success_timestamp`, `_http_status`). Все метрики имеют labels `name, server, security, sni` — см. `tunnelMetricLabels`.
- **main()** — загружает конфиг, резолвит подписки, инициализирует туннели, запускает checker-горутины, HTTP сервер (`/metrics`, `/health`), config watcher, subscription watcher, обрабатывает SIGINT/SIGTERM → `stopTunnels`.

### Важные детали

- SOCKS порты раздаются автоматически начиная с 1080 — не хардкодить порт в туннеле.
- Xray-core встроен как библиотека: в `createXrayConfig` формируется сырой JSON, парсится через `serial.LoadJSONConfig`. При изменении схемы конфига Xray возможны несовместимости — смотреть версию в `go.mod`.
- `waitForSOCKSPort` (`main.go:620`) даёт Xray время на старт перед первой проверкой.
- Горячий reload: сравниваются старые и новые туннели, не изменившиеся переиспользуются (важно — не пересоздавать Xray instance без необходимости, порты могут конфликтовать).
- `xray_config_file` — пользователь задаёт только outbound часть, SOCKS5 inbound инжектится автоматически. Поддерживает все текущие и будущие протоколы/транспорты Xray-core.
- Подписки обновляются периодически по `update_interval`. При изменении списка серверов туннели пересоздаются аналогично hot reload.

## Переменные окружения

`CONFIG_FILE` (default `/app/config.yaml`), `LISTEN_ADDR` (`:9273`), `XRAY_LOG_LEVEL` (`warning`), `DEBUG` (`false`).

## Релизы

Автоматизированы через release-please (`release-please-config.json`, см. коммит 4de0159). Используется tag-based SemVer — версии формируются из conventional commits. В `task build` версия прокидывается через `-ldflags="-X main.Version=..."`.
