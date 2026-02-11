package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
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
				if c.Tunnels[0].CheckURL != DefaultCheckURL {
					t.Errorf("check_url = %v, want %v", c.Tunnels[0].CheckURL, DefaultCheckURL)
				}
				if c.Tunnels[0].CheckInterval != DefaultCheckInterval.String() {
					t.Errorf("check_interval = %v, want %v", c.Tunnels[0].CheckInterval, DefaultCheckInterval.String())
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
		{
			name: "custom socks_base_port",
			yaml: `socks_base_port: 2080
tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`,
			wantErr: false,
			checkFunc: func(t *testing.T, c *Config) {
				if c.SocksBasePort != 2080 {
					t.Errorf("socks_base_port = %d, want 2080", c.SocksBasePort)
				}
			},
		},
		{
			name: "default socks_base_port when not set",
			yaml: `tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`,
			wantErr: false,
			checkFunc: func(t *testing.T, c *Config) {
				if c.SocksBasePort != DefaultSocksPort {
					t.Errorf("socks_base_port = %d, want %d", c.SocksBasePort, DefaultSocksPort)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("failed to create temp config: %v", err)
			}

			config, err := Load(configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, config)
			}
		})
	}

	t.Run("file not found", func(t *testing.T) {
		_, err := Load("/nonexistent/config.yaml")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Tunnels: []Tunnel{
					{
						Name:          "test",
						URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
						CheckURL:      "https://example.com",
						CheckInterval: "30s",
						CheckTimeout:  "10s",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid vless URL prefix",
			config: &Config{
				Tunnels: []Tunnel{
					{
						Name:          "test",
						URL:           "http://example.com",
						CheckURL:      "https://example.com",
						CheckInterval: "30s",
						CheckTimeout:  "10s",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			config: &Config{
				Tunnels: []Tunnel{
					{
						Name:          "test",
						URL:           "vless://uuid@example.com:invalid?type=tcp",
						CheckURL:      "https://example.com",
						CheckInterval: "30s",
						CheckTimeout:  "10s",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid check_interval",
			config: &Config{
				Tunnels: []Tunnel{
					{
						Name:          "test",
						URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
						CheckURL:      "https://example.com",
						CheckInterval: "invalid",
						CheckTimeout:  "10s",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid check_timeout",
			config: &Config{
				Tunnels: []Tunnel{
					{
						Name:          "test",
						URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
						CheckURL:      "https://example.com",
						CheckInterval: "30s",
						CheckTimeout:  "invalid",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
