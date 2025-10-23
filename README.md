# Xray Health Exporter

[![🧪 Тестирование](https://github.com/batonogov/xray-health-exporter/actions/workflows/test.yml/badge.svg)](https://github.com/batonogov/xray-health-exporter/actions/workflows/test.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/batonogov/xray-health-exporter)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Prometheus exporter для мониторинга множественных VLESS туннелей со встроенным Xray-core.

**Особенности:**
- Поддержка множественных туннелей в одном экземпляре
- Конфигурация через YAML файл
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

# Или конкретную версию
docker pull ghcr.io/batonogov/xray-health-exporter:v2025.10.13-abc1234
```

> 🔒 Docker образ запускается от непривилегированного пользователя `xray` (UID 1000)

## Быстрый старт

1. **Создайте конфигурационный файл** `config.yaml`:

```yaml
defaults:
  check_url: "https://speed.cloudflare.com/__down"
  check_interval: "30s"
  check_timeout: "30s"
  download_test_mb: 10

tunnels:
  - name: "Server 1"
    url: "vless://uuid@host1:443?type=tcp&security=reality&pbk=...&sni=google.com"
  - name: "Server 2"
    url: "vless://uuid@host2:443?type=tcp&security=tls&sni=example.com"
```

См. [config.example.yaml](config.example.yaml) для полного примера.

2. **Запустите:**

```bash
# Docker
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -p 9090:9090 \
  ghcr.io/batonogov/xray-health-exporter:latest

# Локально (требуется Go 1.25+)
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
- `xray_tunnel_download_bytes_total{name, server, security, sni}` - общее количество скачанных байт
- `xray_tunnel_download_speed_bytes_per_second{name, server, security, sni}` - скорость скачивания в байтах/секунду

**Пример метрик:**
```
xray_tunnel_up{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 1
xray_tunnel_latency_seconds{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 0.345
xray_tunnel_check_total{name="Server 1",server="example.com:443",security="reality",sni="google.com",result="success"} 42
xray_tunnel_last_success_timestamp{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 1704117344
xray_tunnel_http_status{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 200
xray_tunnel_download_bytes_total{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 52428800
xray_tunnel_download_speed_bytes_per_second{name="Server 1",server="example.com:443",security="reality",sni="google.com"} 2621440
```

> 💡 Label `name` содержит имя туннеля из конфига (или `host:port` если имя не указано). Labels позволяют мониторить несколько VLESS серверов одновременно

**Endpoints:**
- `/metrics` - Prometheus метрики
- `/health` - healthcheck

## Конфигурация

Конфигурация задается через YAML файл. Пример:

```yaml
# Глобальные настройки по умолчанию (опционально)
defaults:
  check_url: "https://speed.cloudflare.com/__down"
  check_interval: "30s"
  check_timeout: "30s"
  download_test_mb: 10

# Список туннелей для мониторинга
tunnels:
  # Минимальная конфигурация
  - url: "vless://uuid@host:443?type=tcp&security=reality&pbk=...&sni=google.com"

  # С именем
  - name: "Production Server"
    url: "vless://uuid@host:443?..."

  # С переопределением параметров
  - name: "Backup Server"
    url: "vless://uuid@host:443?..."
    check_url: "https://1.1.1.1"
    check_interval: "60s"
    check_timeout: "45s"
    download_test_mb: 5
```

**Параметры туннеля:**
- `name` (опционально) - имя туннеля для логов. Если не указано, используется `host:port`
- `url` (обязательно) - VLESS URL подключения
- `check_url` (опционально) - URL для проверки доступности (по умолчанию Cloudflare speed test)
- `check_interval` (опционально) - интервал между проверками
- `check_timeout` (опционально) - таймаут проверки
- `download_test_mb` (опционально) - размер теста скорости скачивания в мегабайтах (по умолчанию 10 MB). Для Cloudflare speed test размер добавляется автоматически в URL как параметр `?bytes=`

**Примечания:**
- SOCKS порты назначаются автоматически начиная с 1080 (1080, 1081, 1082...)
- Формат duration: "30s", "1m", "1h30m"
- Если параметр не указан в туннеле, используется значение из `defaults`
- Если не указан в `defaults`, используется глобальное значение по умолчанию

## Переменные окружения

| Переменная | По умолчанию | Описание |
|-----------|--------------|----------|
| `CONFIG_FILE` | `/app/config.yaml` | Путь к YAML конфигурации |
| `LISTEN_ADDR` | `:9090` | Адрес HTTP сервера |
| `XRAY_LOG_LEVEL` | `warning` | Уровень логов Xray |
| `DEBUG` | `false` | Детальный вывод |

## Prometheus

Добавьте в `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'xray-health'
    static_configs:
      - targets: ['localhost:9090']
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

      # Низкая скорость скачивания
      - alert: XrayLowDownloadSpeed
        expr: xray_tunnel_download_speed_bytes_per_second < 131072  # 1 Mbps в байтах/сек
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Низкая скорость на {{ $labels.name }}"
          description: "Туннель {{ $labels.name }} имеет низкую скорость {{ $value | humanize }}B/s (порог: 1 Mbps)"
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

### 🧪 Тестирование

**Текущее покрытие тестами:** 69.2%

Проект включает обширный набор тестов:
- ✅ Unit-тесты для всех основных функций
- ✅ Интеграционные тесты с mock серверами
- ✅ Тесты сетевых ошибок (timeout, DNS, TLS)
- ✅ Тесты HTTP endpoints (/health, /metrics)
- ✅ Тесты Prometheus метрик

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
