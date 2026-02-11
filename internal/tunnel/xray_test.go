package tunnel

import (
	"encoding/json"
	"strings"
	"testing"
)

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
				tlsSettings, ok := settings["tlsSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("tlsSettings not found")
				}
				if tlsSettings["serverName"] != "example.com" {
					t.Errorf("serverName = %v, want example.com", tlsSettings["serverName"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := CreateStreamSettings(tt.config)
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

	jsonData, err := CreateXrayConfig(config, 1080)
	if err != nil {
		t.Fatalf("CreateXrayConfig() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

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

	outbounds, ok := result["outbounds"].([]interface{})
	if !ok || len(outbounds) == 0 {
		t.Fatal("outbounds not found or empty")
	}
	outbound := outbounds[0].(map[string]interface{})
	if outbound["protocol"] != "vless" {
		t.Errorf("outbound protocol = %v, want vless", outbound["protocol"])
	}

	settings := outbound["settings"].(map[string]interface{})
	vnext := settings["vnext"].([]interface{})[0].(map[string]interface{})
	if vnext["address"] != "example.com" {
		t.Errorf("address = %v, want example.com", vnext["address"])
	}
	if vnext["port"].(float64) != 443 {
		t.Errorf("port = %v, want 443", vnext["port"])
	}

	users := vnext["users"].([]interface{})[0].(map[string]interface{})
	if users["id"] != "test-uuid" {
		t.Errorf("user id = %v, want test-uuid", users["id"])
	}
}

func TestStartXray_InvalidConfig(t *testing.T) {
	t.Run("invalid JSON", func(t *testing.T) {
		invalidJSON := []byte(`{invalid json}`)
		_, err := StartXray(invalidJSON)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "failed to parse config") {
			t.Errorf("expected parse error, got: %v", err)
		}
	})

	t.Run("invalid config structure", func(t *testing.T) {
		invalidConfig := []byte(`{
			"inbounds": [
				{
					"port": "invalid-port-type",
					"protocol": "socks"
				}
			]
		}`)
		_, err := StartXray(invalidConfig)
		if err == nil {
			t.Error("expected error for invalid config structure")
		}
	})
}
