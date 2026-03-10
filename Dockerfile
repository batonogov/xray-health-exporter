FROM golang:1.26.1-alpine AS builder

WORKDIR /app

# Копируем файлы go mod
COPY go.mod go.sum* ./
RUN go mod download

# Копируем исходный код
COPY . .

# Сборка
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o xray-health-exporter .

# Финальная стадия
FROM alpine:3.23.3

RUN apk --no-cache --no-scripts add ca-certificates && \
    addgroup -g 10001 xray && \
    adduser -D -u 10001 -G xray xray

WORKDIR /app

COPY --from=builder --chown=xray:xray /app/xray-health-exporter .

USER xray

EXPOSE 9273

CMD ["./xray-health-exporter"]
