# Xray Health Exporter

[🇷🇺 Русский](README.md) | [🇬🇧 English](README.en.md)

[![🧪 Тестирование](https://github.com/batonogov/xray-health-exporter/actions/workflows/test.yml/badge.svg)](https://github.com/batonogov/xray-health-exporter/actions/workflows/test.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/batonogov/xray-health-exporter)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Prometheus exporter для мониторинга туннелей Xray-core.

**Особенности:**
- Поддержка множественных туннелей в одном экземпляре
- VLESS URL или нативный Xray JSON-конфиг (`xray_config_file`) — все протоколы и транспорты
- Подписки (subscription URL) — автоматическое получение и обновление списка серверов
- Конфигурация через YAML файл с горячей перезагрузкой
- Автоматическое распределение SOCKS портов
- Индивидуальные настройки для каждого туннеля

## Установка

**Скачать готовый бинарник:**

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
# Скачать latest
docker pull ghcr.io/batonogov/xray-health-exporter:latest
```

> 🔒 Docker образ запускается от непривилегированного пользователя `xray` (UID 10001)

**Helm (Kubernetes):**

```bash
helm repo add batonogov https://batonogov.github.io/helm-charts
helm install xray-health-exporter batonogov/xray-health-exporter -f values.yaml
```

См. [`charts/xray-health-exporter`](https://github.com/batonogov/helm-charts/tree/main/charts/xray-health-exporter) — чарт включает leader election, RBAC под Lease и опциональный `ServiceMonitor`.

## Быстрый старт

1. **Создайте конфигурационный файл** `config.yaml`:

```yaml
defaults:
  check_url: "https://www.google.com"
  check_interval: "30s"
  check_timeout: "30s"

# Подписки (опционально) — автоматическое получение серверов
subscriptions:
  - url: "https://provider.example.com/api/v1/client/subscribe?token=xxx"
    update_interval: "1h"

tunnels:
  # Вариант 1: VLESS URL
  - name: "Server 1"
    url: "vless://uuid@host1:443?type=tcp&security=reality&pbk=...&sni=google.com"

  # Вариант 2: нативный Xray JSON-конфиг (любой протокол)
  - name: "Server 2"
    xray_config_file: "/etc/xray/server2.json"
```

См. [config.example.yaml](config.example.yaml) для полного примера.

2. **Запустите:**

```bash
# Docker
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -p 9273:9273 \
  ghcr.io/batonogov/xray-health-exporter:latest

# Локально (требуется Go 1.26+)
export CONFIG_FILE=./config.yaml
./xray-health-exporter-linux-amd64
```

## Метрики

Все метрики содержат labels: `name`, `server`, `security`, `sni`

- `xray_tunnel_up{name, server, security, sni}` - статус туннеля (1=работает, 0=не работает)
- `xray_tunnel_latency_seconds{name, server, security, sni}` - латентность подключения
- `xray_tunnel_check_total{name, server, security, sni, result}` - счётчик проверок
- `xray_tunnel_last_success_timestamp{name, server, security, sni}` - timestamp последней успешной проверки
- `xray_tunnel_http_status{name, server, security, sni}` - HTTP статус код при проверке
- `xray_exporter_leader` - 1 если этот инстанс активно опрашивает туннели (лидер или leader election выключен), 0 иначе

**Пример метрик:**
```
xray_tunnel_up{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 1
xray_tunnel_latency_seconds{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 0.345
xray_tunnel_check_total{name="Server 1",server="example.com:443",security="reality",sni="google.com",result="success"} 42
xray_tunnel_last_success_timestamp{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 1704117344
xray_tunnel_http_status{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 200
```

> 💡 Label `name` содержит имя туннеля из конфига (или `host:port` если имя не указано). Labels позволяют мониторить несколько серверов одновременно

**Endpoints:**
- `/metrics` - Prometheus метрики
- `/health` - healthcheck

## Конфигурация

Конфигурация задается через YAML файл. Пример:

```yaml
# Глобальные настройки по умолчанию (опционально)
defaults:
  check_url: "https://www.google.com"
  check_interval: "30s"
  check_timeout: "30s"

# Подписки — автоматическое получение серверов (опционально)
subscriptions:
  - url: "https://provider.example.com/subscribe?token=xxx"
    update_interval: "1h"  # как часто обновлять (по умолчанию 1h)

# Список туннелей для мониторинга
tunnels:
  # Вариант 1: VLESS URL
  - url: "vless://uuid@host:443?type=tcp&security=reality&pbk=...&sni=google.com"

  # Вариант 2: нативный Xray JSON-конфиг (любой протокол/транспорт)
  - name: "VMess Server"
    xray_config_file: "/etc/xray/vmess.json"

  # С переопределением параметров
  - name: "Backup Server"
    url: "vless://uuid@host:443?..."
    check_url: "https://1.1.1.1"
    check_interval: "60s"
    check_timeout: "45s"
```

**Параметры туннеля:**
- `name` (опционально) - имя туннеля для логов. Если не указано, используется `host:port`
- `url` - VLESS URL подключения (взаимоисключающе с `xray_config_file`)
- `xray_config_file` - путь к нативному Xray JSON-конфигу (взаимоисключающе с `url`). Пользователь задаёт только outbound, SOCKS5 inbound инжектится автоматически
- `check_url` (опционально) - URL для проверки доступности
- `check_interval` (опционально) - интервал между проверками
- `check_timeout` (опционально) - таймаут проверки

**Параметры подписки:**
- `url` (обязательно) - URL подписки (возвращает base64-encoded или plain text список серверов)
- `update_interval` (опционально) - интервал обновления (по умолчанию `1h`)

**Примечания:**
- Должен быть указан хотя бы один туннель или подписка
- SOCKS порты назначаются автоматически начиная с 1080 (1080, 1081, 1082...)
- Формат duration: "30s", "1m", "1h30m"
- Если параметр не указан в туннеле, используется значение из `defaults`
- Если не указан в `defaults`, используется глобальное значение по умолчанию

## Переменные окружения

| Переменная | По умолчанию | Описание |
|-----------|--------------|----------|
| `CONFIG_FILE` | `/app/config.yaml` | Путь к YAML конфигурации |
| `LISTEN_ADDR` | `:9273` | Адрес HTTP сервера |
| `XRAY_LOG_LEVEL` | `warning` | Уровень логов Xray |
| `DEBUG` | `false` | Детальный вывод |
| `LEADER_ELECTION` | `false` | Включить k8s leader election (см. ниже) |
| `LEADER_ELECTION_NAMESPACE` | namespace pod-а | Namespace для Lease объекта |
| `LEADER_ELECTION_NAME` | `xray-health-exporter` | Имя Lease |
| `LEADER_ELECTION_IDENTITY` | `$HOSTNAME` | Уникальный ID реплики |

## Высокая доступность (Kubernetes)

> 📦 Готовый Helm-чарт: **[`batonogov/xray-health-exporter`](https://github.com/batonogov/helm-charts/tree/main/charts/xray-health-exporter)** — поднимает экспортёр со всем нижеописанным «из коробки» (replicas, leader election, RBAC под Lease, опциональные `ServiceMonitor` / `PrometheusRule`).
>
> ```bash
> helm repo add batonogov https://batonogov.github.io/helm-charts
> helm install xray-health-exporter batonogov/xray-health-exporter \
>   -f values.yaml
> ```

При запуске с `replicas: >1` и скрейпом через `ServiceMonitor` Prometheus попадёт на каждый pod независимо, и метрики туннелей задублируются. Чтобы решить это, включите leader election:

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

Поведение:
- Только лидер инициализирует Xray-туннели и публикует `xray_tunnel_*` метрики; `xray_exporter_leader=1`.
- Followers отвечают на `/metrics` и `/health`, но публикуют только `xray_exporter_leader=0` (никаких `xray_tunnel_*` серий).
- При штатном завершении лидера (SIGTERM) Lease отпускается сразу (`ReleaseOnCancel`), и follower подхватывает за ~`RetryPeriod` (≈5s). При жёстком падении — за `LeaseDuration` (≈30s).

⚠️ Если в одном namespace запущено несколько разных деплоев экспортёра, **обязательно** задайте свой `LEADER_ELECTION_NAME` каждому — иначе они начнут драться за один и тот же Lease.

⚠️ `LEADER_ELECTION=true` требует запуска внутри Kubernetes pod-а (используется `InClusterConfig`). Вне кластера экспортёр упадёт с ошибкой загрузки конфига.

Минимальный RBAC (создаст и обновит Lease):

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

Поскольку followers вообще не публикуют `xray_tunnel_*`, стандартные алерты (`xray_tunnel_up == 0`, `xray_tunnel_latency_seconds > X`) автоматически срабатывают только на данных лидера — дубликаты исключены без дополнительных PromQL-фильтров.

## Prometheus

Добавьте в `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'xray-health'
    static_configs:
      - targets: ['localhost:9273']
```

Примеры алертов:

```yaml
groups:
  - name: xray
    rules:
      # Туннель не работает
      - alert: XrayTunnelDown
        expr: xray_tunnel_up == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Туннель {{ $labels.name }} не работает"
          description: "Туннель {{ $labels.name }} ({{ $labels.server }}, {{ $labels.security }}) не работает более 5 минут"

      # Высокая задержка
      - alert: XrayHighLatency
        expr: xray_tunnel_latency_seconds > 2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Высокая задержка на {{ $labels.name }}"
          description: "Туннель {{ $labels.name }} имеет задержку {{ $value }}s (порог: 2s)"

      # Туннель давно не проверялся
      - alert: XrayNoRecentCheck
        expr: (time() - xray_tunnel_last_success_timestamp) > 300
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.name }} давно не проверялся"
          description: "Туннель {{ $labels.name }} не проверялся успешно {{ $value }}s"
```

## Разработка

```bash
# Установить pre-commit хуки
task install-hooks

# Запустить тесты
task test
# или
go test -v -cover ./...

# Запустить тесты с отчетом о покрытии
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Локальная сборка
task build
```

### 🔄 CI/CD

**Автоматическое тестирование в Pull Requests:**
- 🧪 Запуск всех тестов при каждом PR
- 📊 Проверка покрытия кода (минимум 65%)
- 🔍 Проверка форматирования кода
- 🏗️ Проверка сборки
- 💬 Автоматический комментарий с результатами в PR

**Pre-commit проверки:**
- ✅ Go форматирование (`go fmt`)
- ✅ Запуск тестов
- ✅ Проверка сборки
- ✅ **Защита от секретов** (gitleaks, detect-private-key)

## Лицензия

MIT
