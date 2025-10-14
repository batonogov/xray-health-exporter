package main

import (
	"encoding/json"
	"testing"
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
