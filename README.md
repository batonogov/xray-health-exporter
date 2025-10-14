# Xray Health Exporter

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
  check_url: "https://www.google.com"
  check_interval: "30s"
  check_timeout: "30s"

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

Все метрики содержат labels: `server`, `security`, `sni`

- `xray_tunnel_up{server, security, sni}` - статус туннеля (1=работает, 0=не работает)
- `xray_tunnel_latency_seconds{server, security, sni}` - латентность подключения
- `xray_tunnel_check_total{server, security, sni, result}` - счётчик проверок
- `xray_tunnel_last_success_timestamp{server, security, sni}` - timestamp последней успешной проверки
- `xray_tunnel_http_status{server, security, sni}` - HTTP статус код при проверке

**Пример метрик:**
```
xray_tunnel_up{server="example.com:443",security="reality",sni="google.com"} 1
xray_tunnel_latency_seconds{server="example.com:443",security="reality",sni="google.com"} 0.345
xray_tunnel_check_total{server="example.com:443",security="reality",sni="google.com",result="success"} 42
xray_tunnel_last_success_timestamp{server="example.com:443",security="reality",sni="google.com"} 1704117344
xray_tunnel_http_status{server="example.com:443",security="reality",sni="google.com"} 200
```

> 💡 Labels позволяют мониторить несколько VLESS серверов одновременно

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
```

**Параметры туннеля:**
- `name` (опционально) - имя туннеля для логов. Если не указано, используется `host:port`
- `url` (обязательно) - VLESS URL подключения
- `check_url` (опционально) - URL для проверки доступности
- `check_interval` (опционально) - интервал между проверками
- `check_timeout` (опционально) - таймаут проверки

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
          summary: "Туннель {{ $labels.server }} не работает"
          description: "Туннель до {{ $labels.server }} ({{ $labels.security }}) не работает более 5 минут"

      # Высокая задержка
      - alert: XrayHighLatency
        expr: xray_tunnel_latency_seconds > 2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Высокая задержка на {{ $labels.server }}"
          description: "Задержка туннеля {{ $value }}s (порог: 2s)"

      # Туннель давно не проверялся
      - alert: XrayNoRecentCheck
        expr: (time() - xray_tunnel_last_success_timestamp) > 300
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.server }} давно не проверялся"
          description: "Последняя успешная проверка была {{ $value }}s назад"
```

## Разработка

```bash
# Установить pre-commit хуки
task install-hooks

# Запустить тесты
task test

# Локальная сборка
task build
```

**Pre-commit проверки:**
- ✅ Go форматирование (`go fmt`)
- ✅ Запуск тестов
- ✅ Проверка сборки
- ✅ **Защита от секретов** (gitleaks, detect-private-key)

## Лицензия

MIT
