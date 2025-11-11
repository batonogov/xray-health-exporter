FROM golang:1.25.4-alpine AS builder

WORKDIR /app

# Копируем файлы go mod
COPY go.mod go.sum* ./
RUN go mod download

# Копируем исходный код
COPY . .

# Сборка
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o xray-health-exporter .

# Финальная стадия
FROM alpine:3.22.2

RUN apk --no-cache add ca-certificates && \
    addgroup -g 1000 xray && \
    adduser -D -u 1000 -G xray xray

WORKDIR /app

COPY --from=builder /app/xray-health-exporter .

RUN chown -R xray:xray /app

USER xray

EXPOSE 9090

CMD ["./xray-health-exporter"]
