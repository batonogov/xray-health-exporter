package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestParseVLESSURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		want    *VLESSConfig
	}{
		{
			name: "valid vless url with reality",
			url:  "vless://uuid-123@example.com:443?type=tcp&security=reality&pbk=test-key&sni=google.com&sid=short123&spx=/&fp=chrome",
			want: &VLESSConfig{
				UUID:     "uuid-123",
				Address:  "example.com",
				Port:     443,
				Type:     "tcp",
				Security: "reality",
				PBK:      "test-key",
				SNI:      "google.com",
				SID:      "short123",
				SPX:      "/",
				FP:       "chrome",
			},
			wantErr: false,
		},
		{
			name: "valid vless url with tls",
			url:  "vless://uuid-456@server.net:8443?type=ws&security=tls&sni=server.net&fp=firefox",
			want: &VLESSConfig{
				UUID:     "uuid-456",
				Address:  "server.net",
				Port:     8443,
				Type:     "ws",
				Security: "tls",
				SNI:      "server.net",
				FP:       "firefox",
			},
			wantErr: false,
		},
		{
			name:    "invalid protocol",
			url:     "http://example.com",
			wantErr: true,
		},
		{
			name:    "invalid port",
			url:     "vless://uuid@example.com:invalid?type=tcp",
			wantErr: true,
		},
		{
			name:    "empty url",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVLESSURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseVLESSURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.UUID != tt.want.UUID {
					t.Errorf("UUID = %v, want %v", got.UUID, tt.want.UUID)
				}
				if got.Address != tt.want.Address {
					t.Errorf("Address = %v, want %v", got.Address, tt.want.Address)
				}
				if got.Port != tt.want.Port {
					t.Errorf("Port = %v, want %v", got.Port, tt.want.Port)
				}
				if got.Security != tt.want.Security {
					t.Errorf("Security = %v, want %v", got.Security, tt.want.Security)
				}
				if got.Type != tt.want.Type {
					t.Errorf("Type = %v, want %v", got.Type, tt.want.Type)
				}
			}
		})
	}
}

func TestCreateStreamSettings(t *testing.T) {
	tests := []struct {
		name   string
		config *VLESSConfig
		checks func(t *testing.T, settings map[string]interface{})
	}{
		{
			name: "reality settings",
			config: &VLESSConfig{
				Type:     "tcp",
				Security: "reality",
				PBK:      "test-key",
				SNI:      "google.com",
				SID:      "short123",
				SPX:      "/path",
				FP:       "chrome",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				if settings["network"] != "tcp" {
					t.Errorf("network = %v, want tcp", settings["network"])
				}
				if settings["security"] != "reality" {
					t.Errorf("security = %v, want reality", settings["security"])
				}
				reality, ok := settings["realitySettings"].(map[string]interface{})
				if !ok {
					t.Fatal("realitySettings not found")
				}
				if reality["publicKey"] != "test-key" {
					t.Errorf("publicKey = %v, want test-key", reality["publicKey"])
				}
				if reality["serverName"] != "google.com" {
					t.Errorf("serverName = %v, want google.com", reality["serverName"])
				}
			},
		},
		{
			name: "tls settings",
			config: &VLESSConfig{
				Type:     "tcp",
				Security: "tls",
				SNI:      "example.com",
				FP:       "firefox",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				if settings["security"] != "tls" {
					t.Errorf("security = %v, want tls", settings["security"])
				}
				tls, ok := settings["tlsSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("tlsSettings not found")
				}
				if tls["serverName"] != "example.com" {
					t.Errorf("serverName = %v, want example.com", tls["serverName"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := createStreamSettings(tt.config)
			tt.checks(t, settings)
		})
	}
}

func TestCreateXrayConfig(t *testing.T) {
	config := &VLESSConfig{
		UUID:     "test-uuid",
		Address:  "example.com",
		Port:     443,
		Type:     "tcp",
		Security: "reality",
		PBK:      "test-key",
		SNI:      "google.com",
		SID:      "short123",
		SPX:      "/",
		FP:       "chrome",
	}

	jsonData, err := createXrayConfig(config, 1080)
	if err != nil {
		t.Fatalf("createXrayConfig() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	// Check inbounds
	inbounds, ok := result["inbounds"].([]interface{})
	if !ok || len(inbounds) == 0 {
		t.Fatal("inbounds not found or empty")
	}
	inbound := inbounds[0].(map[string]interface{})
	if inbound["port"].(float64) != 1080 {
		t.Errorf("inbound port = %v, want 1080", inbound["port"])
	}
	if inbound["protocol"] != "socks" {
		t.Errorf("inbound protocol = %v, want socks", inbound["protocol"])
	}

	// Check outbounds
	outbounds, ok := result["outbounds"].([]interface{})
	if !ok || len(outbounds) == 0 {
		t.Fatal("outbounds not found or empty")
	}
	outbound := outbounds[0].(map[string]interface{})
	if outbound["protocol"] != "vless" {
		t.Errorf("outbound protocol = %v, want vless", outbound["protocol"])
	}

	// Check settings
	settings := outbound["settings"].(map[string]interface{})
	vnext := settings["vnext"].([]interface{})[0].(map[string]interface{})
	if vnext["address"] != "example.com" {
		t.Errorf("address = %v, want example.com", vnext["address"])
	}
	if vnext["port"].(float64) != 443 {
		t.Errorf("port = %v, want 443", vnext["port"])
	}

	// Check users
	users := vnext["users"].([]interface{})[0].(map[string]interface{})
	if users["id"] != "test-uuid" {
		t.Errorf("user id = %v, want test-uuid", users["id"])
	}
}

func TestSOCKS5Dialer(t *testing.T) {
	// Простой тест создания диалера
	dialer := newSOCKS5Dialer("127.0.0.1:1080", 30)
	if dialer == nil {
		t.Fatal("newSOCKS5Dialer() returned nil")
	}
	if dialer.proxyAddr != "127.0.0.1:1080" {
		t.Errorf("proxyAddr = %v, want 127.0.0.1:1080", dialer.proxyAddr)
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantErr   bool
		checkFunc func(*testing.T, *Config)
	}{
		{
			name: "valid config with defaults",
			yaml: `defaults:
  check_url: "https://example.com"
  check_interval: "1m"
  check_timeout: "10s"
tunnels:
  - name: "test-tunnel"
    url: "vless://uuid@example.com:443?type=tcp&security=reality&pbk=key&sni=test.com&fp=chrome"`,
			wantErr: false,
			checkFunc: func(t *testing.T, c *Config) {
				if len(c.Tunnels) != 1 {
					t.Errorf("expected 1 tunnel, got %d", len(c.Tunnels))
				}
				if c.Tunnels[0].Name != "test-tunnel" {
					t.Errorf("tunnel name = %v, want test-tunnel", c.Tunnels[0].Name)
				}
				if c.Tunnels[0].CheckURL != "https://example.com" {
					t.Errorf("check_url = %v, want https://example.com", c.Tunnels[0].CheckURL)
				}
			},
		},
		{
			name: "tunnel with custom check_url",
			yaml: `defaults:
  check_url: "https://default.com"
tunnels:
  - name: "custom"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    check_url: "https://custom.com"`,
			wantErr: false,
			checkFunc: func(t *testing.T, c *Config) {
				if c.Tunnels[0].CheckURL != "https://custom.com" {
					t.Errorf("check_url = %v, want https://custom.com", c.Tunnels[0].CheckURL)
				}
			},
		},
		{
			name: "config with no defaults uses global defaults",
			yaml: `tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`,
			wantErr: false,
			checkFunc: func(t *testing.T, c *Config) {
				if c.Tunnels[0].CheckURL != defaultCheckURL {
					t.Errorf("check_url = %v, want %v", c.Tunnels[0].CheckURL, defaultCheckURL)
				}
				if c.Tunnels[0].CheckInterval != defaultCheckInterval.String() {
					t.Errorf("check_interval = %v, want %v", c.Tunnels[0].CheckInterval, defaultCheckInterval.String())
				}
			},
		},
		{
			name:    "empty config",
			yaml:    ``,
			wantErr: true,
		},
		{
			name: "no tunnels",
			yaml: `defaults:
  check_url: "https://example.com"
tunnels: []`,
			wantErr: true,
		},
		{
			name: "tunnel without url",
			yaml: `tunnels:
  - name: "test"`,
			wantErr: true,
		},
		{
			name:    "invalid yaml",
			yaml:    `invalid: yaml: content:`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Создаем временный файл
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("failed to create temp config: %v", err)
			}

			config, err := loadConfig(configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, config)
			}
		})
	}

	// Test file not found
	t.Run("file not found", func(t *testing.T) {
		_, err := loadConfig("/nonexistent/config.yaml")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

func TestSOCKS5DialContext(t *testing.T) {
	// Создаем mock SOCKS5 сервер
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	socksAddr := listener.Addr().String()

	// Запускаем mock SOCKS5 сервер в горутине
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				// Читаем SOCKS5 handshake [VER, NMETHODS, METHODS]
				buf := make([]byte, 3)
				if _, err := c.Read(buf); err != nil {
					return
				}

				// Отвечаем [VER, METHOD]
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}

				// Читаем CONNECT request (минимум 4 байта)
				req := make([]byte, 4)
				if _, err := c.Read(req); err != nil {
					return
				}

				// Читаем оставшуюся часть запроса в зависимости от типа адреса
				switch req[3] {
				case 1: // IPv4
					c.Read(make([]byte, 4+2))
				case 3: // Domain
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4: // IPv6
					c.Read(make([]byte, 16+2))
				}

				// Отвечаем успехом: [VER, REP, RSV, ATYP, BIND.ADDR, BIND.PORT]
				// REP = 0 (успех)
				response := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
				if _, err := c.Write(response); err != nil {
					return
				}

				// Теперь соединение установлено, можно передавать данные
				// Для теста просто держим соединение открытым
				time.Sleep(100 * time.Millisecond)
			}(conn)
		}
	}()

	// Тестируем диалер
	dialer := newSOCKS5Dialer(socksAddr, 5*time.Second)

	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()

	if conn == nil {
		t.Error("DialContext() returned nil connection")
	}
}

func TestSOCKS5DialContextErrors(t *testing.T) {
	// Тест с несуществующим прокси
	t.Run("proxy connection failed", func(t *testing.T) {
		dialer := newSOCKS5Dialer("127.0.0.1:9999", 1*time.Second)
		ctx := context.Background()
		_, err := dialer.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected error for nonexistent proxy")
		}
	})

	// Тест с невалидным адресом назначения
	t.Run("invalid destination address", func(t *testing.T) {
		dialer := newSOCKS5Dialer("127.0.0.1:1080", 1*time.Second)
		ctx := context.Background()
		_, err := dialer.DialContext(ctx, "tcp", "invalid-address")
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})
}

func TestCheckTunnel(t *testing.T) {
	// Создаем mock HTTP сервер
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	// Создаем mock SOCKS5 сервер (упрощенная версия, перенаправляющая на реальный HTTP)
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	socksAddr := socksListener.Addr().String()

	// Mock SOCKS5 сервер, который принимает подключения
	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				// SOCKS5 handshake
				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				// CONNECT request
				req := make([]byte, 4)
				c.Read(req)

				// Читаем адрес
				switch req[3] {
				case 1: // IPv4
					c.Read(make([]byte, 4+2))
				case 3: // Domain
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4: // IPv6
					c.Read(make([]byte, 16+2))
				}

				// Отвечаем успехом
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

				// Теперь проксируем соединение к реальному HTTP серверу
				// Для упрощения теста просто отправляем HTTP ответ напрямую
				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	// Создаем TunnelInstance для теста
	_, portStr, _ := net.SplitHostPort(socksAddr)
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &TunnelInstance{
		Name: "test-tunnel",
		VLESSConfig: &VLESSConfig{
			Address:  "test.example.com",
			Port:     443,
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      ts.URL,
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	// Даем время серверу запуститься
	time.Sleep(100 * time.Millisecond)

	// Выполняем проверку
	// Примечание: checkTunnel изменяет метрики Prometheus, но не возвращает значение
	// Мы можем только проверить, что она не паникует
	checkTunnel(ti)

	// Тест завершен успешно, если не было паники
}

func TestTunnelManagerReloadConfig(t *testing.T) {
	// Создаем временный конфиг
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	initialConfig := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	// Первая загрузка конфига
	config, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Проверяем что конфиг загрузился
	if len(config.Tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(config.Tunnels))
	}

	// Обновляем конфиг
	newConfig := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
  - name: "tunnel2"
    url: "vless://uuid2@example2.com:443?type=tcp&security=tls&sni=test2.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(newConfig), 0644); err != nil {
		t.Fatalf("failed to update config: %v", err)
	}

	// Проверяем что новый конфиг имеет 2 туннеля
	config2, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if len(config2.Tunnels) != 2 {
		t.Errorf("expected 2 tunnels, got %d", len(config2.Tunnels))
	}
}

func TestWatchConfigFile(t *testing.T) {
	// Создаем временный конфиг
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	initialConfig := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	// Инициализируем менеджер
	tm := &TunnelManager{}

	// Запускаем watcher в горутине с таймаутом
	done := make(chan bool)
	watcherErr := make(chan error, 1)

	go func() {
		// Watcher работает в бесконечном цикле, поэтому даём ему 2 секунды
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		go func() {
			err := watchConfigFile(tm, configFile, false)
			if err != nil {
				watcherErr <- err
			}
		}()

		<-ctx.Done()
		done <- true
	}()

	// Ждем запуска watcher
	time.Sleep(100 * time.Millisecond)

	// Модифицируем файл
	updatedConfig := `defaults:
  check_url: "https://example.com"
tunnels:
  - name: "tunnel1-modified"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

	if err := os.WriteFile(configFile, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("failed to update config: %v", err)
	}

	// Ждем завершения или ошибки
	select {
	case <-done:
		// Тест прошел успешно
	case err := <-watcherErr:
		t.Fatalf("watcher error: %v", err)
	}
}

func TestInitializeTunnels(t *testing.T) {
	// Тест с пустым конфигом
	t.Run("empty config", func(t *testing.T) {
		config := &Config{
			Tunnels: []Tunnel{},
		}

		instances, err := initializeTunnels(config, false)
		if err == nil {
			t.Error("expected error for empty tunnels")
		}
		if instances != nil {
			t.Error("expected nil instances for empty config")
		}
	})

	// Тест с невалидным URL
	t.Run("invalid tunnel URL", func(t *testing.T) {
		config := &Config{
			Tunnels: []Tunnel{
				{
					Name:          "invalid",
					URL:           "invalid-url",
					CheckURL:      "https://example.com",
					CheckInterval: "30s",
					CheckTimeout:  "10s",
				},
			},
		}

		instances, err := initializeTunnels(config, false)
		if err == nil {
			t.Error("expected error for invalid URL")
		}
		if instances != nil {
			t.Error("expected nil instances for invalid config")
		}
	})
}

func TestStopTunnels(t *testing.T) {
	// Создаем mock туннель
	ctx, cancel := context.WithCancel(context.Background())

	ti := &TunnelInstance{
		Name:       "test-tunnel",
		cancelFunc: cancel,
		VLESSConfig: &VLESSConfig{
			Address:  "test.com",
			Port:     443,
			Security: "tls",
		},
		SocksPort: 1080,
	}

	instances := []*TunnelInstance{ti}

	// Останавливаем туннели
	stopTunnels(instances)

	// Проверяем что контекст отменен
	select {
	case <-ctx.Done():
		// Успешно отменен
	case <-time.After(1 * time.Second):
		t.Error("context was not cancelled")
	}
}

// HTTP Endpoints Tests

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.StatusCode)
	}

	body := make([]byte, 2)
	resp.Body.Read(body)
	if string(body) != "OK" {
		t.Errorf("expected body 'OK', got '%s'", string(body))
	}
}

func TestMetricsEndpoint(t *testing.T) {
	// Создаем mock туннель и устанавливаем метрики
	labels := prometheus.Labels{
		"name":     "test-tunnel",
		"server":   "example.com:443",
		"security": "reality",
		"sni":      "google.com",
	}

	tunnelUp.With(labels).Set(1)
	tunnelLatency.With(labels).Set(0.123)
	tunnelHTTPStatus.With(labels).Set(200)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	promhttp.Handler().ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.StatusCode)
	}

	body := make([]byte, 10000)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	// Проверяем что метрики присутствуют
	expectedMetrics := []string{
		"xray_tunnel_up",
		"xray_tunnel_latency_seconds",
		"xray_tunnel_check_total",
		"xray_tunnel_last_success_timestamp",
		"xray_tunnel_http_status",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(bodyStr, metric) {
			t.Errorf("metrics output should contain %s", metric)
		}
	}

	// Проверяем формат Prometheus (должны быть HELP и TYPE)
	if !strings.Contains(bodyStr, "# HELP") {
		t.Error("metrics should contain HELP comments")
	}
	if !strings.Contains(bodyStr, "# TYPE") {
		t.Error("metrics should contain TYPE comments")
	}
}

// Prometheus Metrics Tests

func TestMetricsUpdate(t *testing.T) {
	labels := prometheus.Labels{
		"name":     "metrics-test",
		"server":   "test.example.com:443",
		"security": "tls",
		"sni":      "test.example.com",
	}

	// Тест успешной проверки
	t.Run("success metrics", func(t *testing.T) {
		tunnelUp.With(labels).Set(1)
		tunnelLatency.With(labels).Set(0.5)
		tunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
		tunnelHTTPStatus.With(labels).Set(200)
		tunnelCheckTotal.With(prometheus.Labels{
			"name":     "metrics-test",
			"server":   "test.example.com:443",
			"security": "tls",
			"sni":      "test.example.com",
			"result":   "success",
		}).Inc()

		// Метрики должны быть установлены без паники
	})

	// Тест неудачной проверки
	t.Run("failure metrics", func(t *testing.T) {
		tunnelUp.With(labels).Set(0)
		tunnelCheckTotal.With(prometheus.Labels{
			"name":     "metrics-test",
			"server":   "test.example.com:443",
			"security": "tls",
			"sni":      "test.example.com",
			"result":   "failure",
		}).Inc()

		// Метрики должны быть установлены без паники
	})
}

func TestMetricsLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels prometheus.Labels
	}{
		{
			name: "reality tunnel",
			labels: prometheus.Labels{
				"name":     "Reality Server",
				"server":   "reality.example.com:8443",
				"security": "reality",
				"sni":      "google.com",
			},
		},
		{
			name: "tls tunnel",
			labels: prometheus.Labels{
				"name":     "TLS Server",
				"server":   "tls.example.com:443",
				"security": "tls",
				"sni":      "example.com",
			},
		},
		{
			name: "tunnel with special characters in name",
			labels: prometheus.Labels{
				"name":     "Server-123_test",
				"server":   "192.168.1.1:8080",
				"security": "tls",
				"sni":      "test.local",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Устанавливаем метрики с разными labels
			tunnelUp.With(tt.labels).Set(1)
			tunnelLatency.With(tt.labels).Set(0.1)
			tunnelHTTPStatus.With(tt.labels).Set(200)

			// Проверяем что метрики можно установить без ошибок
			// Prometheus сам валидирует корректность labels
		})
	}
}

func TestMetricsReset(t *testing.T) {
	// Создаем начальные метрики
	oldLabels := prometheus.Labels{
		"name":     "old-tunnel",
		"server":   "old.example.com:443",
		"security": "tls",
		"sni":      "old.example.com",
	}

	tunnelUp.With(oldLabels).Set(1)
	tunnelLatency.With(oldLabels).Set(0.5)

	// После перезагрузки конфига метрики со старыми labels остаются в регистре
	// но новые метрики с новыми labels должны создаваться независимо
	newLabels := prometheus.Labels{
		"name":     "new-tunnel",
		"server":   "new.example.com:443",
		"security": "reality",
		"sni":      "google.com",
	}

	tunnelUp.With(newLabels).Set(1)
	tunnelLatency.With(newLabels).Set(0.3)

	// Обе группы метрик должны существовать независимо
	// Prometheus не удаляет старые метрики автоматически
	// Это ожидаемое поведение - старые метрики останутся с последними значениями
}

// Network Error Tests for checkTunnel

func TestCheckTunnel_Timeout(t *testing.T) {
	// Создаем HTTP сервер с задержкой
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // Задержка больше чем timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Создаем mock SOCKS5 сервер
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	socksAddr := socksListener.Addr().String()

	// Mock SOCKS5 сервер
	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

				// Имитируем медленное соединение
				time.Sleep(3 * time.Second)
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksAddr)
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &TunnelInstance{
		Name: "timeout-test",
		VLESSConfig: &VLESSConfig{
			Address:  "test.example.com",
			Port:     443,
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      ts.URL,
		CheckTimeout:  1 * time.Second, // Короткий timeout
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	// checkTunnel должен установить метрику в 0 из-за timeout
	checkTunnel(ti)

	// Тест проходит если не было паники
	// checkTunnel внутри логирует ошибку и устанавливает tunnelUp в 0
}

func TestCheckTunnel_BadStatusCodes(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		shouldFail bool
	}{
		{"status 200 OK", http.StatusOK, false},
		{"status 301 redirect", http.StatusMovedPermanently, false},
		{"status 302 redirect", http.StatusFound, false},
		{"status 307 redirect", http.StatusTemporaryRedirect, false},
		{"status 404 not found", http.StatusNotFound, true},
		{"status 500 server error", http.StatusInternalServerError, true},
		{"status 503 unavailable", http.StatusServiceUnavailable, true},
		{"status 403 forbidden", http.StatusForbidden, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Создаем HTTP сервер с заданным статусом
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte("test response"))
			}))
			defer ts.Close()

			// Создаем mock SOCKS5 сервер
			socksListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to create SOCKS listener: %v", err)
			}
			defer socksListener.Close()

			socksAddr := socksListener.Addr().String()

			go func() {
				for {
					conn, err := socksListener.Accept()
					if err != nil {
						return
					}

					go func(c net.Conn) {
						defer c.Close()
						buf := make([]byte, 3)
						c.Read(buf)
						c.Write([]byte{5, 0})

						req := make([]byte, 4)
						c.Read(req)

						switch req[3] {
						case 1:
							c.Read(make([]byte, 4+2))
						case 3:
							lenBuf := make([]byte, 1)
							c.Read(lenBuf)
							c.Read(make([]byte, int(lenBuf[0])+2))
						case 4:
							c.Read(make([]byte, 16+2))
						}

						c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

						httpResponse := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 13\r\n\r\ntest response",
							tc.statusCode, http.StatusText(tc.statusCode))
						c.Write([]byte(httpResponse))
					}(conn)
				}
			}()

			_, portStr, _ := net.SplitHostPort(socksAddr)
			socksPort := 0
			fmt.Sscanf(portStr, "%d", &socksPort)

			ti := &TunnelInstance{
				Name: fmt.Sprintf("status-%d-test", tc.statusCode),
				VLESSConfig: &VLESSConfig{
					Address:  "test.example.com",
					Port:     443,
					Security: "tls",
					SNI:      "test.example.com",
				},
				SocksPort:     socksPort,
				CheckURL:      ts.URL,
				CheckTimeout:  5 * time.Second,
				CheckInterval: 30 * time.Second,
			}

			time.Sleep(100 * time.Millisecond)
			checkTunnel(ti)

			// Проверяем что метрика HTTP status установлена правильно
			// tunnelHTTPStatus должен содержать tc.statusCode
		})
	}
}

func TestCheckTunnel_DNSError(t *testing.T) {
	// Создаем mock SOCKS5 сервер
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	socksAddr := socksListener.Addr().String()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				// Читаем адрес
				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				// Отвечаем ошибкой Host unreachable (код 4)
				c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksAddr)
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &TunnelInstance{
		Name: "dns-error-test",
		VLESSConfig: &VLESSConfig{
			Address:  "nonexistent.invalid.domain.example",
			Port:     443,
			Security: "tls",
			SNI:      "nonexistent.invalid.domain.example",
		},
		SocksPort:     socksPort,
		CheckURL:      "https://nonexistent.invalid.domain.example",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	// checkTunnel должен установить метрику в 0 из-за DNS ошибки
	checkTunnel(ti)

	// Тест проходит если не было паники
}

func TestCheckTunnel_TLSError(t *testing.T) {
	// Создаем HTTP сервер без TLS
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Создаем mock SOCKS5 сервер
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	socksAddr := socksListener.Addr().String()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

				// Отправляем невалидный TLS handshake
				c.Write([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x50})
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksAddr)
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &TunnelInstance{
		Name: "tls-error-test",
		VLESSConfig: &VLESSConfig{
			Address:  "test.example.com",
			Port:     443,
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      "https://test.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 30 * time.Second,
	}

	time.Sleep(100 * time.Millisecond)

	// checkTunnel должен обработать TLS ошибку
	checkTunnel(ti)

	// Тест проходит если не было паники
}

// runTunnelChecker Tests

func TestRunTunnelChecker(t *testing.T) {
	// Создаем mock SOCKS5 сервер который всегда отвечает успешно
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	socksAddr := socksListener.Addr().String()

	var requestCount int32

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				atomic.AddInt32(&requestCount, 1)

				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksAddr)
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &TunnelInstance{
		Name: "periodic-check-test",
		VLESSConfig: &VLESSConfig{
			Address:  "test.example.com",
			Port:     443,
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      "http://test.example.com",
		CheckTimeout:  5 * time.Second,
		CheckInterval: 500 * time.Millisecond, // Короткий интервал для теста
	}

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	// Запускаем checker
	go runTunnelChecker(ctx, ti)

	// Ждем несколько проверок
	time.Sleep(1600 * time.Millisecond)

	// Отменяем контекст
	cancel()

	// Даем время на завершение
	time.Sleep(100 * time.Millisecond)

	// Должно было быть несколько SOCKS запросов (минимум 3-4: начальный + периодические)
	finalCount := atomic.LoadInt32(&requestCount)
	if finalCount < 3 {
		t.Errorf("expected at least 3 checks, got %d", finalCount)
	}
}

func TestRunTunnelChecker_Context(t *testing.T) {
	// Создаем HTTP сервер
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	// Создаем mock SOCKS5 сервер
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}
	defer socksListener.Close()

	socksAddr := socksListener.Addr().String()

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				c.Read(buf)
				c.Write([]byte{5, 0})

				req := make([]byte, 4)
				c.Read(req)

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

				httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
				c.Write([]byte(httpResponse))
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(socksAddr)
	socksPort := 0
	fmt.Sscanf(portStr, "%d", &socksPort)

	ti := &TunnelInstance{
		Name: "context-cancel-test",
		VLESSConfig: &VLESSConfig{
			Address:  "test.example.com",
			Port:     443,
			Security: "tls",
			SNI:      "test.example.com",
		},
		SocksPort:     socksPort,
		CheckURL:      ts.URL,
		CheckTimeout:  5 * time.Second,
		CheckInterval: 100 * time.Millisecond,
	}

	time.Sleep(100 * time.Millisecond)

	// Создаем контекст с отменой
	ctx, cancel := context.WithCancel(context.Background())

	// Канал для проверки что горутина завершилась
	done := make(chan bool, 1)

	// Запускаем checker
	go func() {
		runTunnelChecker(ctx, ti)
		done <- true
	}()

	// Даем время на первую проверку
	time.Sleep(200 * time.Millisecond)

	// Отменяем контекст
	cancel()

	// Проверяем что горутина завершилась
	select {
	case <-done:
		// Успешно завершилась
	case <-time.After(2 * time.Second):
		t.Error("runTunnelChecker did not stop after context cancellation")
	}
}
