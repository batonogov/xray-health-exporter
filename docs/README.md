# Documentation

Deep technical reference for xray-health-exporter. For operational/agent guidance see [`../AGENTS.md`](../AGENTS.md); for user-facing usage see [`../README.md`](../README.md) (English) or [`../README.ru.md`](../README.ru.md) (Russian). The compact LLM index is [`../llms.txt`](../llms.txt).

| Document | Contents |
|---|---|
| [architecture.md](./architecture.md) | Package map, key entities, run modes, Xray lifecycle, hot-reload mechanics |
| [configuration.md](./configuration.md) | Full environment-variable table and YAML schema with defaults |
| [metrics.md](./metrics.md) | Authoritative Prometheus metric list: types, labels, histogram buckets, error reasons |
| [check-methods.md](./check-methods.md) | The three health-check methods (`http`/`ip`/`download`) and TTFB instrumentation |
