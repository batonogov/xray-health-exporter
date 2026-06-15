package config

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
)

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
				if c.Tunnels[0].CheckURL != metrics.DefaultCheckURL {
					t.Errorf("check_url = %v, want %v", c.Tunnels[0].CheckURL, metrics.DefaultCheckURL)
				}
				if c.Tunnels[0].CheckInterval != metrics.DefaultCheckInterval.String() {
					t.Errorf("check_interval = %v, want %v", c.Tunnels[0].CheckInterval, metrics.DefaultCheckInterval.String())
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
			name: "tunnel with both url and xray_config_file",
			yaml: `tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    xray_config_file: "/tmp/some.json"`,
			wantErr: true,
		},
		{
			name: "tunnel without url and xray_config_file",
			yaml: `tunnels:
  - name: "test"
    check_url: "https://example.com"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("failed to create temp config: %v", err)
			}

			config, err := LoadConfig(configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, config)
			}
		})
	}

	// Test file not found
	t.Run("file not found", func(t *testing.T) {
		_, err := LoadConfig("/nonexistent/config.yaml")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	// Test tunnel with xray_config_file (needs a real temp file)
	t.Run("tunnel with xray_config_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		xrayConfigPath := filepath.Join(tmpDir, "xray.json")
		if err := os.WriteFile(xrayConfigPath, []byte(`{}`), 0644); err != nil {
			t.Fatalf("failed to create temp xray config: %v", err)
		}

		yamlContent := fmt.Sprintf(`tunnels:
  - name: "xray-tunnel"
    xray_config_file: %q`, xrayConfigPath)

		configFile := filepath.Join(tmpDir, "config.yaml")
		if err := os.WriteFile(configFile, []byte(yamlContent), 0644); err != nil {
			t.Fatalf("failed to create temp config: %v", err)
		}

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() unexpected error: %v", err)
		}
		if config.Tunnels[0].XrayConfigFile != xrayConfigPath {
			t.Errorf("XrayConfigFile = %v, want %v", config.Tunnels[0].XrayConfigFile, xrayConfigPath)
		}
	})
}

func TestLoadConfig_SocksPort(t *testing.T) {
	t.Run("tunnel with socks_port", func(t *testing.T) {
		yaml := `tunnels:
  - name: "custom-port"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    socks_port: 2080`

		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.Tunnels[0].SocksPort != 2080 {
			t.Errorf("SocksPort = %v, want 2080", config.Tunnels[0].SocksPort)
		}
	})

	t.Run("tunnel without socks_port defaults to 0", func(t *testing.T) {
		yaml := `tunnels:
  - name: "auto-port"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.Tunnels[0].SocksPort != 0 {
			t.Errorf("SocksPort = %v, want 0 (auto)", config.Tunnels[0].SocksPort)
		}
	})
}

func TestValidateTunnels_SocksPort(t *testing.T) {
	baseTunnel := func() Tunnel {
		return Tunnel{
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
		}
	}

	t.Run("valid custom socks_port", func(t *testing.T) {
		tunnel := baseTunnel()
		tunnel.Name = "t1"
		tunnel.SocksPort = 2080
		config := &Config{Tunnels: []Tunnel{tunnel}}
		if err := ValidateTunnels(config); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("socks_port=0 means auto-assign and is valid", func(t *testing.T) {
		tunnel := baseTunnel()
		tunnel.Name = "t1"
		tunnel.SocksPort = 0
		config := &Config{Tunnels: []Tunnel{tunnel}}
		if err := ValidateTunnels(config); err != nil {
			t.Errorf("expected no error for socks_port=0 (auto), got: %v", err)
		}
	})

	t.Run("socks_port out of range negative", func(t *testing.T) {
		tunnel := baseTunnel()
		tunnel.Name = "t1"
		tunnel.SocksPort = -1
		config := &Config{Tunnels: []Tunnel{tunnel}}
		err := ValidateTunnels(config)
		if err == nil {
			t.Fatal("expected error for negative socks_port")
		}
		if !strings.Contains(err.Error(), "out of valid range") {
			t.Errorf("expected range error, got: %v", err)
		}
	})

	t.Run("socks_port out of range too high", func(t *testing.T) {
		tunnel := baseTunnel()
		tunnel.Name = "t1"
		tunnel.SocksPort = 70000
		config := &Config{Tunnels: []Tunnel{tunnel}}
		err := ValidateTunnels(config)
		if err == nil {
			t.Fatal("expected error for socks_port > 65535")
		}
		if !strings.Contains(err.Error(), "out of valid range") {
			t.Errorf("expected range error, got: %v", err)
		}
	})

	t.Run("duplicate socks_port", func(t *testing.T) {
		t1 := baseTunnel()
		t1.Name = "first"
		t1.SocksPort = 2080
		t2 := baseTunnel()
		t2.Name = "second"
		t2.SocksPort = 2080
		config := &Config{Tunnels: []Tunnel{t1, t2}}
		err := ValidateTunnels(config)
		if err == nil {
			t.Fatal("expected error for duplicate socks_port")
		}
		if !strings.Contains(err.Error(), "already used") {
			t.Errorf("expected duplicate error, got: %v", err)
		}
	})

	t.Run("different socks_ports are fine", func(t *testing.T) {
		t1 := baseTunnel()
		t1.Name = "first"
		t1.SocksPort = 2080
		t2 := baseTunnel()
		t2.Name = "second"
		t2.SocksPort = 2081
		config := &Config{Tunnels: []Tunnel{t1, t2}}
		if err := ValidateTunnels(config); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("mix of custom and auto ports is fine", func(t *testing.T) {
		t1 := baseTunnel()
		t1.Name = "custom"
		t1.SocksPort = 2080
		t2 := baseTunnel()
		t2.Name = "auto"
		t2.SocksPort = 0
		config := &Config{Tunnels: []Tunnel{t1, t2}}
		if err := ValidateTunnels(config); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})
}

func TestApplyTunnelDefaults(t *testing.T) {
	t.Run("fallback to global defaults when Defaults empty", func(t *testing.T) {
		tunnel := &Tunnel{}
		ApplyTunnelDefaults(tunnel, Defaults{})

		if tunnel.CheckURL != metrics.DefaultCheckURL {
			t.Errorf("CheckURL = %v, want %v", tunnel.CheckURL, metrics.DefaultCheckURL)
		}
		if tunnel.CheckInterval != metrics.DefaultCheckInterval.String() {
			t.Errorf("CheckInterval = %v, want %v", tunnel.CheckInterval, metrics.DefaultCheckInterval.String())
		}
		if tunnel.CheckTimeout != metrics.DefaultTimeout.String() {
			t.Errorf("CheckTimeout = %v, want %v", tunnel.CheckTimeout, metrics.DefaultTimeout.String())
		}
	})

	t.Run("config defaults take priority over globals", func(t *testing.T) {
		tunnel := &Tunnel{}
		ApplyTunnelDefaults(tunnel, Defaults{
			CheckURL:      "https://custom.com",
			CheckInterval: "2m",
			CheckTimeout:  "15s",
		})

		if tunnel.CheckURL != "https://custom.com" {
			t.Errorf("CheckURL = %v, want https://custom.com", tunnel.CheckURL)
		}
		if tunnel.CheckInterval != "2m" {
			t.Errorf("CheckInterval = %v, want 2m", tunnel.CheckInterval)
		}
		if tunnel.CheckTimeout != "15s" {
			t.Errorf("CheckTimeout = %v, want 15s", tunnel.CheckTimeout)
		}
	})

	t.Run("tunnel values not overwritten", func(t *testing.T) {
		tunnel := &Tunnel{
			CheckURL:      "https://mine.com",
			CheckInterval: "5m",
			CheckTimeout:  "20s",
		}
		ApplyTunnelDefaults(tunnel, Defaults{
			CheckURL:      "https://default.com",
			CheckInterval: "1m",
			CheckTimeout:  "10s",
		})

		if tunnel.CheckURL != "https://mine.com" {
			t.Errorf("CheckURL = %v, want https://mine.com", tunnel.CheckURL)
		}
		if tunnel.CheckInterval != "5m" {
			t.Errorf("CheckInterval = %v, want 5m", tunnel.CheckInterval)
		}
		if tunnel.CheckTimeout != "20s" {
			t.Errorf("CheckTimeout = %v, want 20s", tunnel.CheckTimeout)
		}
	})
}

func TestApplyTunnelDefaults_BackoffFields(t *testing.T) {
	t.Run("backoff defaults applied from empty", func(t *testing.T) {
		tunnel := &Tunnel{}
		ApplyTunnelDefaults(tunnel, Defaults{})

		if tunnel.MaxBackoff != metrics.DefaultMaxBackoff.String() {
			t.Errorf("MaxBackoff = %v, want %v", tunnel.MaxBackoff, metrics.DefaultMaxBackoff.String())
		}
		if tunnel.BackoffMultiplier == nil || *tunnel.BackoffMultiplier != metrics.DefaultBackoffMult {
			t.Errorf("BackoffMultiplier = %v, want %v", tunnel.BackoffMultiplier, metrics.DefaultBackoffMult)
		}
	})

	t.Run("backoff defaults from config defaults", func(t *testing.T) {
		customMult := 3.0
		tunnel := &Tunnel{}
		ApplyTunnelDefaults(tunnel, Defaults{
			MaxBackoff:        "10m",
			BackoffMultiplier: &customMult,
		})

		if tunnel.MaxBackoff != "10m" {
			t.Errorf("MaxBackoff = %v, want 10m", tunnel.MaxBackoff)
		}
		if tunnel.BackoffMultiplier == nil || *tunnel.BackoffMultiplier != 3.0 {
			t.Errorf("BackoffMultiplier = %v, want 3.0", tunnel.BackoffMultiplier)
		}
	})

	t.Run("tunnel backoff values not overwritten", func(t *testing.T) {
		customMult := 1.5
		tunnel := &Tunnel{
			MaxBackoff:        "2m",
			BackoffMultiplier: &customMult,
		}
		defaultMult := 2.0
		ApplyTunnelDefaults(tunnel, Defaults{
			MaxBackoff:        "10m",
			BackoffMultiplier: &defaultMult,
		})

		if tunnel.MaxBackoff != "2m" {
			t.Errorf("MaxBackoff = %v, want 2m", tunnel.MaxBackoff)
		}
		if tunnel.BackoffMultiplier == nil || *tunnel.BackoffMultiplier != 1.5 {
			t.Errorf("BackoffMultiplier = %v, want 1.5", tunnel.BackoffMultiplier)
		}
	})
}

func TestLoadConfig_BackoffFields(t *testing.T) {
	t.Run("defaults with backoff config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `defaults:
  check_url: "https://example.com"
  max_backoff: "3m"
  backoff_multiplier: 1.5
tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}

		if config.Defaults.MaxBackoff != "3m" {
			t.Errorf("MaxBackoff = %v, want 3m", config.Defaults.MaxBackoff)
		}
		if config.Defaults.BackoffMultiplier == nil || *config.Defaults.BackoffMultiplier != 1.5 {
			t.Errorf("BackoffMultiplier = %v, want 1.5", config.Defaults.BackoffMultiplier)
		}

		if config.Tunnels[0].MaxBackoff != "3m" {
			t.Errorf("tunnel MaxBackoff = %v, want 3m", config.Tunnels[0].MaxBackoff)
		}
		if config.Tunnels[0].BackoffMultiplier == nil || *config.Tunnels[0].BackoffMultiplier != 1.5 {
			t.Errorf("tunnel BackoffMultiplier = %v, want 1.5", config.Tunnels[0].BackoffMultiplier)
		}
	})

	t.Run("tunnel overrides defaults backoff", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `defaults:
  check_url: "https://example.com"
  max_backoff: "3m"
tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    max_backoff: "1m"
    backoff_multiplier: 2.5`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}

		if config.Tunnels[0].MaxBackoff != "1m" {
			t.Errorf("tunnel MaxBackoff = %v, want 1m", config.Tunnels[0].MaxBackoff)
		}
		if config.Tunnels[0].BackoffMultiplier == nil || *config.Tunnels[0].BackoffMultiplier != 2.5 {
			t.Errorf("tunnel BackoffMultiplier = %v, want 2.5", config.Tunnels[0].BackoffMultiplier)
		}
	})

	t.Run("default backoff when not specified", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}

		if config.Tunnels[0].MaxBackoff != metrics.DefaultMaxBackoff.String() {
			t.Errorf("tunnel MaxBackoff = %v, want %v", config.Tunnels[0].MaxBackoff, metrics.DefaultMaxBackoff.String())
		}
		if config.Tunnels[0].BackoffMultiplier == nil || *config.Tunnels[0].BackoffMultiplier != metrics.DefaultBackoffMult {
			t.Errorf("tunnel BackoffMultiplier = %v, want %v", config.Tunnels[0].BackoffMultiplier, metrics.DefaultBackoffMult)
		}
	})
}

func TestTunnelValidate(t *testing.T) {
	t.Run("valid tunnel", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "valid",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
		}
		if err := tunnel.Validate(); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("invalid VLESS URL", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "bad-url",
			URL:           "vless://bad-url-no-port",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
		}
		// Note: structural validation only — parseVLESSURL errors happen at init time
		// in the tunnel package. vless://bad-url-no-port is structurally valid for url.Parse.
		if err := tunnel.Validate(); err != nil {
			t.Errorf("structural validation should pass for vless://bad-url-no-port, got: %v", err)
		}
	})

	t.Run("non-VLESS URL is accepted", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "ss-url",
			URL:           "ss://some-data@example.com:8388",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
		}
		if err := tunnel.Validate(); err != nil {
			t.Errorf("expected no error for non-VLESS URL, got: %v", err)
		}
	})

	t.Run("invalid check_interval", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "bad-interval",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "https://example.com",
			CheckInterval: "not-a-duration",
			CheckTimeout:  "10s",
		}
		err := tunnel.Validate()
		if err == nil {
			t.Fatal("expected error for invalid check_interval")
		}
		if !strings.Contains(err.Error(), "invalid check_interval") {
			t.Errorf("expected check_interval error, got: %v", err)
		}
	})

	t.Run("invalid check_timeout", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "bad-timeout",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "not-a-duration",
		}
		err := tunnel.Validate()
		if err == nil {
			t.Fatal("expected error for invalid check_timeout")
		}
		if !strings.Contains(err.Error(), "invalid check_timeout") {
			t.Errorf("expected check_timeout error, got: %v", err)
		}
	})

	t.Run("invalid check_url", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "bad-check-url",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "ftp://not-http.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
		}
		err := tunnel.Validate()
		if err == nil {
			t.Fatal("expected error for invalid check_url")
		}
		if !strings.Contains(err.Error(), "invalid check_url") {
			t.Errorf("expected check_url error, got: %v", err)
		}
	})

	t.Run("multiple errors at once", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "all-bad",
			URL:           "vless://bad-url-no-port",
			CheckURL:      "ftp://bad",
			CheckInterval: "bad-interval",
			CheckTimeout:  "bad-timeout",
		}
		err := tunnel.Validate()
		if err == nil {
			t.Fatal("expected errors")
		}
		errStr := err.Error()
		// VLESS URL is structurally valid — only check_url/interval/timeout fail
		if !strings.Contains(errStr, "invalid check_interval") {
			t.Errorf("expected check_interval error in: %v", errStr)
		}
		if !strings.Contains(errStr, "invalid check_timeout") {
			t.Errorf("expected check_timeout error in: %v", errStr)
		}
		if !strings.Contains(errStr, "invalid check_url") {
			t.Errorf("expected check_url error in: %v", errStr)
		}
	})

	t.Run("http check_url is valid", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "http-url",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "http://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
		}
		if err := tunnel.Validate(); err != nil {
			t.Errorf("expected no error for http check_url, got: %v", err)
		}
	})
}

func TestTunnelValidate_XrayConfigFile(t *testing.T) {
	t.Run("valid xray_config_file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "xray.json")
		if err := os.WriteFile(tmpFile, []byte(`{}`), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		tunnel := Tunnel{
			Name:           "xray-tunnel",
			XrayConfigFile: tmpFile,
			CheckURL:       "https://example.com",
			CheckInterval:  "30s",
			CheckTimeout:   "10s",
		}
		if err := tunnel.Validate(); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("nonexistent xray_config_file", func(t *testing.T) {
		tunnel := Tunnel{
			Name:           "bad-xray",
			XrayConfigFile: "/nonexistent/xray.json",
			CheckURL:       "https://example.com",
			CheckInterval:  "30s",
			CheckTimeout:   "10s",
		}
		err := tunnel.Validate()
		if err == nil {
			t.Fatal("expected error for nonexistent xray_config_file")
		}
		if !strings.Contains(err.Error(), "xray_config_file not accessible") {
			t.Errorf("expected xray_config_file error, got: %v", err)
		}
	})

	t.Run("both url and xray_config_file", func(t *testing.T) {
		tunnel := Tunnel{
			Name:           "both",
			URL:            "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			XrayConfigFile: "/tmp/some.json",
			CheckURL:       "https://example.com",
			CheckInterval:  "30s",
			CheckTimeout:   "10s",
		}
		err := tunnel.Validate()
		if err == nil {
			t.Fatal("expected error for both url and xray_config_file")
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("expected mutually exclusive error, got: %v", err)
		}
	})

	t.Run("neither url nor xray_config_file", func(t *testing.T) {
		tunnel := Tunnel{
			Name:          "neither",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
		}
		err := tunnel.Validate()
		if err == nil {
			t.Fatal("expected error for missing url and xray_config_file")
		}
		if !strings.Contains(err.Error(), "url or xray_config_file is required") {
			t.Errorf("expected required error, got: %v", err)
		}
	})
}

func TestTunnelValidate_CheckMethod(t *testing.T) {
	baseTunnel := func(method string) *Tunnel {
		return &Tunnel{
			Name:          "method-test",
			URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:      "https://example.com",
			CheckInterval: "30s",
			CheckTimeout:  "10s",
			CheckMethod:   method,
		}
	}

	validMethods := []string{"", "http", "ip", "download"}
	for _, m := range validMethods {
		t.Run("valid method "+m, func(t *testing.T) {
			if err := baseTunnel(m).Validate(); err != nil {
				t.Errorf("expected no error for check_method=%q, got: %v", m, err)
			}
		})
	}

	invalidMethods := []string{"foo", "HTTP", "tcp", "icmp"}
	for _, m := range invalidMethods {
		t.Run("invalid method "+m, func(t *testing.T) {
			err := baseTunnel(m).Validate()
			if err == nil {
				t.Fatalf("expected error for check_method=%q", m)
			}
			if !strings.Contains(err.Error(), "invalid check_method") {
				t.Errorf("expected check_method error, got: %v", err)
			}
		})
	}
}

func TestTunnelValidate_DownloadTimeout(t *testing.T) {
	baseTunnel := func(timeout string) *Tunnel {
		return &Tunnel{
			Name:            "download-timeout-test",
			URL:             "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
			CheckURL:        "https://example.com",
			CheckInterval:   "30s",
			CheckTimeout:    "10s",
			DownloadTimeout: timeout,
		}
	}

	t.Run("empty download_timeout is valid", func(t *testing.T) {
		if err := baseTunnel("").Validate(); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("valid download_timeout", func(t *testing.T) {
		if err := baseTunnel("60s").Validate(); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("invalid download_timeout", func(t *testing.T) {
		err := baseTunnel("not-a-duration").Validate()
		if err == nil {
			t.Fatal("expected error for invalid download_timeout")
		}
		if !strings.Contains(err.Error(), "invalid download_timeout") {
			t.Errorf("expected download_timeout error, got: %v", err)
		}
	})
}

func TestApplyTunnelDefaults_CheckMethod(t *testing.T) {
	t.Run("fallback to global defaults when Defaults empty", func(t *testing.T) {
		tun := &Tunnel{}
		ApplyTunnelDefaults(tun, Defaults{})

		if tun.CheckMethod != metrics.DefaultCheckMethod {
			t.Errorf("CheckMethod = %v, want %v", tun.CheckMethod, metrics.DefaultCheckMethod)
		}
		if tun.IPCheckURL != metrics.DefaultIPCheckURL {
			t.Errorf("IPCheckURL = %v, want %v", tun.IPCheckURL, metrics.DefaultIPCheckURL)
		}
		if tun.DownloadURL != metrics.DefaultDownloadURL {
			t.Errorf("DownloadURL = %v, want %v", tun.DownloadURL, metrics.DefaultDownloadURL)
		}
		if tun.DownloadTimeout != metrics.DefaultDownloadTimeout.String() {
			t.Errorf("DownloadTimeout = %v, want %v", tun.DownloadTimeout, metrics.DefaultDownloadTimeout.String())
		}
		if tun.DownloadMinSize != metrics.DefaultDownloadMinSize {
			t.Errorf("DownloadMinSize = %v, want %v", tun.DownloadMinSize, metrics.DefaultDownloadMinSize)
		}
	})

	t.Run("config defaults take priority over globals", func(t *testing.T) {
		tun := &Tunnel{}
		ApplyTunnelDefaults(tun, Defaults{
			CheckMethod:     "ip",
			IPCheckURL:      "https://custom-ip.example.com",
			DownloadURL:     "https://custom-download.example.com",
			DownloadTimeout: "120s",
			DownloadMinSize: 102400,
		})

		if tun.CheckMethod != "ip" {
			t.Errorf("CheckMethod = %v, want ip", tun.CheckMethod)
		}
		if tun.IPCheckURL != "https://custom-ip.example.com" {
			t.Errorf("IPCheckURL = %v, want https://custom-ip.example.com", tun.IPCheckURL)
		}
		if tun.DownloadURL != "https://custom-download.example.com" {
			t.Errorf("DownloadURL = %v, want https://custom-download.example.com", tun.DownloadURL)
		}
		if tun.DownloadTimeout != "120s" {
			t.Errorf("DownloadTimeout = %v, want 120s", tun.DownloadTimeout)
		}
		if tun.DownloadMinSize != 102400 {
			t.Errorf("DownloadMinSize = %v, want 102400", tun.DownloadMinSize)
		}
	})

	t.Run("tunnel values not overwritten", func(t *testing.T) {
		tun := &Tunnel{
			CheckMethod:     "download",
			IPCheckURL:      "https://mine-ip.example.com",
			DownloadURL:     "https://mine-download.example.com",
			DownloadTimeout: "90s",
			DownloadMinSize: 204800,
		}
		ApplyTunnelDefaults(tun, Defaults{
			CheckMethod:     "ip",
			IPCheckURL:      "https://default-ip.example.com",
			DownloadURL:     "https://default-download.example.com",
			DownloadTimeout: "60s",
			DownloadMinSize: 51200,
		})

		if tun.CheckMethod != "download" {
			t.Errorf("CheckMethod = %v, want download", tun.CheckMethod)
		}
		if tun.IPCheckURL != "https://mine-ip.example.com" {
			t.Errorf("IPCheckURL = %v, want https://mine-ip.example.com", tun.IPCheckURL)
		}
		if tun.DownloadURL != "https://mine-download.example.com" {
			t.Errorf("DownloadURL = %v, want https://mine-download.example.com", tun.DownloadURL)
		}
		if tun.DownloadTimeout != "90s" {
			t.Errorf("DownloadTimeout = %v, want 90s", tun.DownloadTimeout)
		}
		if tun.DownloadMinSize != 204800 {
			t.Errorf("DownloadMinSize = %v, want 204800", tun.DownloadMinSize)
		}
	})
}

func TestApplyEnvDefaults(t *testing.T) {
	t.Run("env vars fill empty defaults", func(t *testing.T) {
		t.Setenv("CHECK_METHOD", "ip")
		t.Setenv("IP_CHECK_URL", "https://env-ip.example.com")
		t.Setenv("DOWNLOAD_URL", "https://env-download.example.com")
		t.Setenv("DOWNLOAD_TIMEOUT", "45s")
		t.Setenv("DOWNLOAD_MIN_SIZE", "99999")

		d := &Defaults{}
		ApplyEnvDefaults(d)

		if d.CheckMethod != "ip" {
			t.Errorf("CheckMethod = %v, want ip", d.CheckMethod)
		}
		if d.IPCheckURL != "https://env-ip.example.com" {
			t.Errorf("IPCheckURL = %v, want https://env-ip.example.com", d.IPCheckURL)
		}
		if d.DownloadURL != "https://env-download.example.com" {
			t.Errorf("DownloadURL = %v, want https://env-download.example.com", d.DownloadURL)
		}
		if d.DownloadTimeout != "45s" {
			t.Errorf("DownloadTimeout = %v, want 45s", d.DownloadTimeout)
		}
		if d.DownloadMinSize != 99999 {
			t.Errorf("DownloadMinSize = %v, want 99999", d.DownloadMinSize)
		}
	})

	t.Run("YAML values take priority over env", func(t *testing.T) {
		t.Setenv("CHECK_METHOD", "ip")

		d := &Defaults{CheckMethod: "download"}
		ApplyEnvDefaults(d)

		if d.CheckMethod != "download" {
			t.Errorf("CheckMethod = %v, want download (YAML should win)", d.CheckMethod)
		}
	})

	t.Run("no env vars leaves defaults empty", func(t *testing.T) {
		d := &Defaults{}
		ApplyEnvDefaults(d)

		if d.CheckMethod != "" {
			t.Errorf("CheckMethod = %v, want empty", d.CheckMethod)
		}
	})

	t.Run("invalid DOWNLOAD_MIN_SIZE is ignored", func(t *testing.T) {
		t.Setenv("DOWNLOAD_MIN_SIZE", "not-a-number")

		d := &Defaults{}
		ApplyEnvDefaults(d)

		if d.DownloadMinSize != 0 {
			t.Errorf("DownloadMinSize = %v, want 0", d.DownloadMinSize)
		}
	})
}

func TestLoadConfig_CheckMethod(t *testing.T) {
	t.Run("defaults with check_method", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `defaults:
  check_url: "https://example.com"
  check_method: "ip"
  ip_check_url: "https://api.ipify.org?format=text"
tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}

		if config.Tunnels[0].CheckMethod != "ip" {
			t.Errorf("tunnel CheckMethod = %v, want ip", config.Tunnels[0].CheckMethod)
		}
		if config.Tunnels[0].IPCheckURL != "https://api.ipify.org?format=text" {
			t.Errorf("tunnel IPCheckURL = %v", config.Tunnels[0].IPCheckURL)
		}
	})

	t.Run("tunnel overrides defaults check_method", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `defaults:
  check_url: "https://example.com"
  check_method: "ip"
tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"
    check_method: "download"
    download_url: "https://download.example.com"
    download_min_size: 102400`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}

		if config.Tunnels[0].CheckMethod != "download" {
			t.Errorf("tunnel CheckMethod = %v, want download", config.Tunnels[0].CheckMethod)
		}
		if config.Tunnels[0].DownloadURL != "https://download.example.com" {
			t.Errorf("tunnel DownloadURL = %v", config.Tunnels[0].DownloadURL)
		}
		if config.Tunnels[0].DownloadMinSize != 102400 {
			t.Errorf("tunnel DownloadMinSize = %v, want 102400", config.Tunnels[0].DownloadMinSize)
		}
	})

	t.Run("default check_method is http when not specified", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		yaml := `tunnels:
  - name: "test"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`

		os.WriteFile(configFile, []byte(yaml), 0644)

		config, err := LoadConfig(configFile)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}

		if config.Tunnels[0].CheckMethod != metrics.DefaultCheckMethod {
			t.Errorf("tunnel CheckMethod = %v, want %v", config.Tunnels[0].CheckMethod, metrics.DefaultCheckMethod)
		}
	})
}

func TestValidateTunnels(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := &Config{
			Tunnels: []Tunnel{
				{
					Name:          "valid",
					URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
					CheckURL:      "https://example.com",
					CheckInterval: "30s",
					CheckTimeout:  "10s",
				},
			},
		}
		if err := ValidateTunnels(config); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("collects errors from all tunnels", func(t *testing.T) {
		config := &Config{
			Tunnels: []Tunnel{
				{
					Name:          "bad1",
					URL:           "vless://bad-url-no-port",
					CheckURL:      "ftp://bad",
					CheckInterval: "30s",
					CheckTimeout:  "10s",
				},
				{
					Name:          "bad2",
					URL:           "vless://also-bad-no-port",
					CheckURL:      "ftp://bad2",
					CheckInterval: "30s",
					CheckTimeout:  "10s",
				},
			},
		}
		err := ValidateTunnels(config)
		if err == nil {
			t.Fatal("expected errors for both tunnels")
		}
		errStr := err.Error()
		if !strings.Contains(errStr, "tunnel 1") {
			t.Errorf("expected error about tunnel 1, got: %v", errStr)
		}
		if !strings.Contains(errStr, "tunnel 2") {
			t.Errorf("expected error about tunnel 2, got: %v", errStr)
		}
	})

	t.Run("first valid second invalid", func(t *testing.T) {
		config := &Config{
			Tunnels: []Tunnel{
				{
					Name:          "good",
					URL:           "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome",
					CheckURL:      "https://example.com",
					CheckInterval: "30s",
					CheckTimeout:  "10s",
				},
				{
					Name:          "bad",
					URL:           "vless://bad-url-no-port",
					CheckURL:      "ftp://bad",
					CheckInterval: "30s",
					CheckTimeout:  "10s",
				},
			},
		}
		err := ValidateTunnels(config)
		if err == nil {
			t.Fatal("expected error for second tunnel")
		}
		errStr := err.Error()
		if !strings.Contains(errStr, "tunnel 2") {
			t.Errorf("expected error about tunnel 2, got: %v", errStr)
		}
		if strings.Contains(errStr, "tunnel 1") {
			t.Errorf("should not have error about tunnel 1, got: %v", errStr)
		}
	})
}

func TestLoadConfig_Subscriptions(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantErr   bool
		checkFunc func(*testing.T, *Config)
	}{
		{
			name: "config with subscription",
			yaml: `subscriptions:
  - url: "https://provider.example.com/sub"
    update_interval: "1h"
tunnels:
  - name: "manual"
    url: "vless://uuid@example.com:443?type=tcp&security=tls&sni=test.com&fp=chrome"`,
			wantErr: false,
			checkFunc: func(t *testing.T, c *Config) {
				if len(c.Subscriptions) != 1 {
					t.Fatalf("expected 1 subscription, got %d", len(c.Subscriptions))
				}
				if c.Subscriptions[0].URL != "https://provider.example.com/sub" {
					t.Errorf("subscription url = %v", c.Subscriptions[0].URL)
				}
				if c.Subscriptions[0].UpdateInterval != "1h" {
					t.Errorf("update_interval = %v", c.Subscriptions[0].UpdateInterval)
				}
			},
		},
		{
			name: "subscription only (no manual tunnels)",
			yaml: `subscriptions:
  - url: "https://provider.example.com/sub"
    update_interval: "1h"`,
			wantErr: false,
			checkFunc: func(t *testing.T, c *Config) {
				if len(c.Subscriptions) != 1 {
					t.Fatalf("expected 1 subscription, got %d", len(c.Subscriptions))
				}
				if len(c.Tunnels) != 0 {
					t.Errorf("expected 0 tunnels, got %d", len(c.Tunnels))
				}
			},
		},
		{
			name: "subscription with default update_interval",
			yaml: `subscriptions:
  - url: "https://provider.example.com/sub"`,
			wantErr: false,
			checkFunc: func(t *testing.T, c *Config) {
				if c.Subscriptions[0].UpdateInterval != "1h" {
					t.Errorf("expected default update_interval '1h', got %v", c.Subscriptions[0].UpdateInterval)
				}
			},
		},
		{
			name: "subscription with invalid update_interval",
			yaml: `subscriptions:
  - url: "https://provider.example.com/sub"
    update_interval: "invalid"`,
			wantErr: true,
		},
		{
			name: "subscription without url",
			yaml: `subscriptions:
  - update_interval: "1h"`,
			wantErr: true,
		},
		{
			name: "no tunnels and no subscriptions",
			yaml: `defaults:
  check_url: "https://example.com"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			os.WriteFile(configFile, []byte(tt.yaml), 0644)

			config, err := LoadConfig(configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, config)
			}
		})
	}
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestFetchSubscription(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		wantCount int
		wantErr   bool
		wantNames []string
	}{
		{
			name:      "base64 encoded vless urls",
			response:  base64Encode("vless://uuid1@host1.com:443?type=tcp&security=reality&pbk=key&sni=google.com&fp=chrome#Server1\nvless://uuid2@host2.com:443?type=tcp&security=tls&sni=host2.com&fp=chrome#Server2"),
			wantCount: 2,
			wantErr:   false,
			wantNames: []string{"Server1", "Server2"},
		},
		{
			name:      "plain text urls (not base64)",
			response:  "vless://uuid1@host1.com:443?type=tcp&security=reality&pbk=key&sni=google.com&fp=chrome#Server1\nvless://uuid2@host2.com:443?type=tcp&security=tls&sni=host2.com&fp=chrome#Server2",
			wantCount: 2,
			wantErr:   false,
			wantNames: []string{"Server1", "Server2"},
		},
		{
			name:      "empty lines skipped",
			response:  base64Encode("vless://uuid1@host1.com:443?type=tcp&security=tls&sni=h.com&fp=chrome#S1\n\n\nvless://uuid2@host2.com:443?type=tcp&security=tls&sni=h2.com&fp=chrome#S2\n"),
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "empty response",
			response:  "",
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.response))
			}))
			defer ts.Close()

			tunnels, err := FetchSubscription(ts.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchSubscription() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(tunnels) != tt.wantCount {
				t.Errorf("got %d tunnels, want %d", len(tunnels), tt.wantCount)
			}
			for i, wantName := range tt.wantNames {
				if i < len(tunnels) && tunnels[i].Name != wantName {
					t.Errorf("tunnel[%d].Name = %v, want %v", i, tunnels[i].Name, wantName)
				}
			}
		})
	}
}

func TestFetchSubscription_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, err := FetchSubscription(ts.URL)
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestFetchSubscription_InvalidURL(t *testing.T) {
	_, err := FetchSubscription("http://127.0.0.1:0/nonexistent")
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

func TestFetchSubscription_Base64RawEncoding(t *testing.T) {
	content := "vless://uuid@host.com:443?type=tcp&security=tls&sni=host.com&fp=chrome#RawServer"
	encoded := base64.RawStdEncoding.EncodeToString([]byte(content))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(encoded))
	}))
	defer ts.Close()

	tunnels, err := FetchSubscription(ts.URL)
	if err != nil {
		t.Fatalf("FetchSubscription() error = %v", err)
	}
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}
	if tunnels[0].Name != "RawServer" {
		t.Errorf("Name = %v, want RawServer", tunnels[0].Name)
	}
}

func TestFetchSubscription_NameFromHostWhenNoFragment(t *testing.T) {
	content := "vless://uuid@myserver.com:8443?type=tcp&security=tls&sni=myserver.com&fp=chrome"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer ts.Close()

	tunnels, err := FetchSubscription(ts.URL)
	if err != nil {
		t.Fatalf("FetchSubscription() error = %v", err)
	}
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}
	if tunnels[0].Name == "" {
		t.Error("expected non-empty name from host:port")
	}
}

func TestFetchSubscription_URLEncoding(t *testing.T) {
	content := "vless://uuid@host.com:443?type=tcp&security=tls&sni=host.com&fp=chrome#URLServer"
	encoded := base64.URLEncoding.EncodeToString([]byte(content))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(encoded))
	}))
	defer ts.Close()

	tunnels, err := FetchSubscription(ts.URL)
	if err != nil {
		t.Fatalf("FetchSubscription() error = %v", err)
	}
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}
	if tunnels[0].Name != "URLServer" {
		t.Errorf("Name = %v, want URLServer", tunnels[0].Name)
	}
}

func TestFetchSubscription_RawURLEncoding(t *testing.T) {
	content := "vless://uuid@host.com:443?type=tcp&security=tls&sni=host.com&fp=chrome#RawURLServer"
	encoded := base64.RawURLEncoding.EncodeToString([]byte(content))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(encoded))
	}))
	defer ts.Close()

	tunnels, err := FetchSubscription(ts.URL)
	if err != nil {
		t.Fatalf("FetchSubscription() error = %v", err)
	}
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}
	if tunnels[0].Name != "RawURLServer" {
		t.Errorf("Name = %v, want RawURLServer", tunnels[0].Name)
	}
}

func TestResolveSubscriptions(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := "vless://uuid1@host1.com:443?type=tcp&security=tls&sni=host1.com&fp=chrome#Sub-Server1\nvless://uuid2@host2.com:443?type=tcp&security=tls&sni=host2.com&fp=chrome#Sub-Server2"
		w.Write([]byte(base64Encode(content)))
	}))
	defer ts.Close()

	config := &Config{
		Defaults: Defaults{
			CheckURL:      "https://example.com",
			CheckInterval: "1m",
			CheckTimeout:  "10s",
		},
		Subscriptions: []Subscription{
			{URL: ts.URL, UpdateInterval: "1h"},
		},
	}

	tunnels := ResolveSubscriptions(config)

	if len(tunnels) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(tunnels))
	}
	if tunnels[0].Name != "Sub-Server1" {
		t.Errorf("tunnel[0].Name = %v, want Sub-Server1", tunnels[0].Name)
	}
	if tunnels[0].CheckURL != "https://example.com" {
		t.Errorf("tunnel[0].CheckURL = %v, want https://example.com", tunnels[0].CheckURL)
	}
	if tunnels[0].CheckInterval != "1m" {
		t.Errorf("tunnel[0].CheckInterval = %v, want 1m", tunnels[0].CheckInterval)
	}
	if tunnels[0].CheckTimeout != "10s" {
		t.Errorf("tunnel[0].CheckTimeout = %v, want 10s", tunnels[0].CheckTimeout)
	}
}

func TestResolveSubscriptions_FailedSubscription(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	config := &Config{
		Subscriptions: []Subscription{
			{URL: ts.URL, UpdateInterval: "1h"},
		},
	}

	tunnels := ResolveSubscriptions(config)
	if len(tunnels) != 0 {
		t.Errorf("expected 0 tunnels from failed subscription, got %d", len(tunnels))
	}
}

func TestResolveSubscriptions_NoSubscriptions(t *testing.T) {
	config := &Config{}
	tunnels := ResolveSubscriptions(config)
	if len(tunnels) != 0 {
		t.Errorf("expected 0 tunnels, got %d", len(tunnels))
	}
}

func TestResolveSubscriptions_FiltersNonVLESS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := "vless://uuid@host.com:443?type=tcp&security=tls&sni=host.com&fp=chrome#VLESS-Server\nss://data@host2.com:8388#SS-Server\ntrojan://pwd@host3.com:443#Trojan-Server\nvmess://base64data#VMess-Server"
		w.Write([]byte(base64Encode(content)))
	}))
	defer ts.Close()

	config := &Config{
		Subscriptions: []Subscription{{URL: ts.URL, UpdateInterval: "1h"}},
	}

	tunnels := ResolveSubscriptions(config)
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 VLESS tunnel, got %d", len(tunnels))
	}
	if tunnels[0].Name != "VLESS-Server" {
		t.Errorf("tunnel[0].Name = %v, want VLESS-Server", tunnels[0].Name)
	}
}

func TestResolveSubscriptions_MultipleWithPartialFailure(t *testing.T) {
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(base64Encode("vless://uuid@host.com:443?type=tcp&security=tls&sni=h.com&fp=chrome#Good")))
	}))
	defer goodServer.Close()

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badServer.Close()

	config := &Config{
		Subscriptions: []Subscription{
			{URL: goodServer.URL, UpdateInterval: "1h"},
			{URL: badServer.URL, UpdateInterval: "1h"},
			{URL: goodServer.URL, UpdateInterval: "1h"},
		},
	}

	tunnels := ResolveSubscriptions(config)
	if len(tunnels) != 2 {
		t.Errorf("expected 2 tunnels from 2 good subscriptions, got %d", len(tunnels))
	}
}
