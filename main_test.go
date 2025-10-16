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
	"testing"
	"time"
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
