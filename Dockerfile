FROM golang:1.25.5-alpine AS builder

WORKDIR /app

# Копируем файлы go mod
COPY go.mod go.sum* ./
RUN go mod download

# Копируем исходный код
COPY . .

# Сборка
RUN CGO_ENABLED=0 GOOS=linux go build -o xray-health-exporter .

# Финальная стадия
FROM alpine:3.23.2

RUN apk --no-cache --no-scripts add ca-certificates && \
    addgroup -g 10001 xray && \
    adduser -D -u 10001 -G xray xray

WORKDIR /app

COPY --from=builder --chown=xray:xray /app/xray-health-exporter .

USER xray

EXPOSE 9273

CMD ["./xray-health-exporter"]
