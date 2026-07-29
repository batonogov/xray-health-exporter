package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
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
				UUID:       "uuid-123",
				Address:    "example.com",
				Port:       443,
				Encryption: "none",
				Type:       "tcp",
				Security:   "reality",
				PBK:        "test-key",
				SNI:        "google.com",
				SID:        "short123",
				SPX:        "/",
				FP:         "chrome",
			},
			wantErr: false,
		},
		{
			name: "valid vless url with tls",
			url:  "vless://uuid-456@server.net:8443?type=ws&security=tls&sni=server.net&fp=firefox&host=server.net&path=%2Fws",
			want: &VLESSConfig{
				UUID:       "uuid-456",
				Address:    "server.net",
				Port:       8443,
				Encryption: "none",
				Type:       "ws",
				Security:   "tls",
				SNI:        "server.net",
				FP:         "firefox",
				Host:       "server.net",
				Path:       "/ws",
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
		{
			name: "valid vless url with grpc transport",
			url:  "vless://uuid-789@grpc.example.com:443/?type=grpc&serviceName=grpc-service&authority=grpc-host&mode=multi&security=reality&pbk=test-pbk&fp=chrome&sni=grpc.example.com&sid=ab12cd34",
			want: &VLESSConfig{
				UUID:        "uuid-789",
				Address:     "grpc.example.com",
				Port:        443,
				Encryption:  "none",
				Type:        "grpc",
				ServiceName: "grpc-service",
				Authority:   "grpc-host",
				Mode:        "multi",
				MultiMode:   true,
				Security:    "reality",
				PBK:         "test-pbk",
				SNI:         "grpc.example.com",
				FP:          "chrome",
				SID:         "ab12cd34",
			},
			wantErr: false,
		},
		{
			name: "current xhttp reality link",
			url: "vless://11111111-1111-4111-8111-111111111111@edge.example.com:443?" +
				"type=xhttp&security=reality&encryption=none&flow=xtls-rprx-vision" +
				"&pbk=test-key&sni=www.example.com&sid=0123456789abcdef&pqv=test-pq-key" +
				"&spx=%2Fcrawler&fp=chrome&host=cdn.example.com&path=%2Fapi%2Fv1" +
				"&mode=stream-up&extra=" + url.QueryEscape(`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"1-4"}}`) +
				"&fm=" + url.QueryEscape(`{"tcp":[{"type":"salamander","settings":{"password":"mask"}}]}`),
			want: &VLESSConfig{
				UUID:       "11111111-1111-4111-8111-111111111111",
				Address:    "edge.example.com",
				Port:       443,
				Encryption: "none",
				Flow:       "xtls-rprx-vision",
				Type:       "xhttp",
				Security:   "reality",
				PBK:        "test-key",
				SNI:        "www.example.com",
				FP:         "chrome",
				SID:        "0123456789abcdef",
				PQV:        "test-pq-key",
				SPX:        "/crawler",
				Host:       "cdn.example.com",
				Path:       "/api/v1",
				Mode:       "stream-up",
				Extra:      json.RawMessage(`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"1-4"}}`),
				FinalMask:  json.RawMessage(`{"tcp":[{"type":"salamander","settings":{"password":"mask"}}]}`),
			},
		},
		{
			name: "current tls options",
			url: "vless://22222222-2222-4222-8222-222222222222@tls.example.com:443?" +
				"type=httpupgrade&security=tls&host=cdn.example.com&path=%2Fupgrade" +
				"&alpn=h2%2Chttp%2F1.1&ech=ech-config&pcs=cert-pin&vcn=verify.example.com",
			want: &VLESSConfig{
				UUID:                 "22222222-2222-4222-8222-222222222222",
				Address:              "tls.example.com",
				Port:                 443,
				Encryption:           "none",
				Type:                 "httpupgrade",
				Security:             "tls",
				SNI:                  "tls.example.com",
				FP:                   "chrome",
				ALPN:                 []string{"h2", "http/1.1"},
				ECHConfigList:        "ech-config",
				PinnedPeerCertSHA256: "cert-pin",
				VerifyPeerCertByName: "verify.example.com",
				Host:                 "cdn.example.com",
				Path:                 "/upgrade",
			},
		},
		{
			name:    "grpc without serviceName",
			url:     "vless://uuid@grpc.example.com:443/?type=grpc&security=reality&pbk=key&fp=chrome&sni=grpc.example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVLESSURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVLESSURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseVLESSURL() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestVLESSURL_NoSecurity(t *testing.T) {
	url := "vless://uuid@example.com:443"
	config, err := ParseVLESSURL(url)
	if err != nil {
		t.Fatalf("ParseVLESSURL() error = %v", err)
	}
	if config.Security != "none" {
		t.Errorf("Security = %v, want none", config.Security)
	}
	if config.Type != "tcp" {
		t.Errorf("Type = %v, want tcp", config.Type)
	}
	if config.Encryption != "none" {
		t.Errorf("Encryption = %v, want none", config.Encryption)
	}
}

func TestParseVLESSURL_TransportCompatibility(t *testing.T) {
	t.Run("legacy HTTP becomes XHTTP stream-one", func(t *testing.T) {
		config, err := ParseVLESSURL("vless://uuid@example.com:443?type=http&security=tls&path=%2Fh2&host=cdn.example.com")
		if err != nil {
			t.Fatalf("ParseVLESSURL() error = %v", err)
		}
		if config.Type != "xhttp" || config.Mode != "stream-one" {
			t.Errorf("transport = %s/%s, want xhttp/stream-one", config.Type, config.Mode)
		}
	})

	t.Run("current mKCP parameters", func(t *testing.T) {
		config, err := ParseVLESSURL("vless://uuid@example.com:443?type=kcp&mtu=1350&tti=50")
		if err != nil {
			t.Fatalf("ParseVLESSURL() error = %v", err)
		}
		if config.KCPMTU == nil || *config.KCPMTU != 1350 {
			t.Errorf("KCPMTU = %v, want 1350", config.KCPMTU)
		}
		if config.KCPTTI == nil || *config.KCPTTI != 50 {
			t.Errorf("KCPTTI = %v, want 50", config.KCPTTI)
		}
	})
}

func TestParseVLESSURL_Validation(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "missing UUID", url: "vless://example.com:443?type=tcp"},
		{name: "missing address", url: "vless://uuid@:443?type=tcp"},
		{name: "port out of range", url: "vless://uuid@example.com:65536?type=tcp"},
		{name: "duplicate parameter", url: "vless://uuid@example.com:443?type=tcp&type=ws"},
		{name: "unsupported transport", url: "vless://uuid@example.com:443?type=quic"},
		{name: "unsupported security", url: "vless://uuid@example.com:443?security=xtls"},
		{name: "reality without password", url: "vless://uuid@example.com:443?security=reality&fp=chrome"},
		{name: "invalid xhttp mode", url: "vless://uuid@example.com:443?type=xhttp&mode=invalid"},
		{name: "invalid xhttp extra", url: "vless://uuid@example.com:443?type=xhttp&extra=%7Bbroken"},
		{name: "invalid finalmask", url: "vless://uuid@example.com:443?type=tcp&fm=%5B%5D"},
		{name: "invalid kcp mtu", url: "vless://uuid@example.com:443?type=kcp&mtu=invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseVLESSURL(tt.url); err == nil {
				t.Fatal("ParseVLESSURL() expected an error")
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
				if reality["serverName"] != "google.com" {
					t.Errorf("serverName = %v, want google.com", reality["serverName"])
				}
				if reality["password"] != "test-key" {
					t.Errorf("password = %v, want test-key", reality["password"])
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
		{
			name: "grpc settings with reality",
			config: &VLESSConfig{
				Type:        "grpc",
				Security:    "reality",
				ServiceName: "grpc-service",
				Authority:   "grpc-host",
				MultiMode:   true,
				PBK:         "test-key",
				SNI:         "grpc.example.com",
				FP:          "chrome",
				SID:         "ab12cd34",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				if settings["network"] != "grpc" {
					t.Errorf("network = %v, want grpc", settings["network"])
				}
				if settings["security"] != "reality" {
					t.Errorf("security = %v, want reality", settings["security"])
				}
				grpc, ok := settings["grpcSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("grpcSettings not found")
				}
				if grpc["serviceName"] != "grpc-service" {
					t.Errorf("serviceName = %v, want grpc-service", grpc["serviceName"])
				}
				if grpc["authority"] != "grpc-host" {
					t.Errorf("authority = %v, want grpc-host", grpc["authority"])
				}
				if grpc["multiMode"] != true {
					t.Errorf("multiMode = %v, want true", grpc["multiMode"])
				}
			},
		},
		{
			name: "grpc settings minimal (authority falls back to SNI)",
			config: &VLESSConfig{
				Type:        "grpc",
				Security:    "tls",
				ServiceName: "minimal-service",
				SNI:         "minimal.example.com",
				FP:          "chrome",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				if settings["network"] != "grpc" {
					t.Errorf("network = %v, want grpc", settings["network"])
				}
				grpc, ok := settings["grpcSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("grpcSettings not found")
				}
				if grpc["serviceName"] != "minimal-service" {
					t.Errorf("serviceName = %v, want minimal-service", grpc["serviceName"])
				}
				if grpc["authority"] != "minimal.example.com" {
					t.Errorf("authority = %v, want minimal.example.com (SNI fallback)", grpc["authority"])
				}
				if _, exists := grpc["multiMode"]; exists {
					t.Error("multiMode should not be set when false")
				}
			},
		},
		{
			name: "grpc settings authority falls back to address without SNI",
			config: &VLESSConfig{
				Type:        "grpc",
				Security:    "reality",
				ServiceName: "my-service",
				Address:     "10.0.0.1",
				FP:          "chrome",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				grpc, ok := settings["grpcSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("grpcSettings not found")
				}
				if grpc["authority"] != "10.0.0.1" {
					t.Errorf("authority = %v, want 10.0.0.1 (address fallback)", grpc["authority"])
				}
			},
		},
		{
			name: "ws settings with host and path",
			config: &VLESSConfig{
				Type:     "ws",
				Security: "tls",
				Host:     "ws.example.com",
				Path:     "/ws-path",
				SNI:      "ws.example.com",
				FP:       "chrome",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				if settings["network"] != "ws" {
					t.Errorf("network = %v, want ws", settings["network"])
				}
				ws, ok := settings["wsSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("wsSettings not found")
				}
				if ws["path"] != "/ws-path" {
					t.Errorf("path = %v, want /ws-path", ws["path"])
				}
				if ws["host"] != "ws.example.com" {
					t.Errorf("host = %v, want ws.example.com", ws["host"])
				}
			},
		},
		{
			name: "ws settings without host and path",
			config: &VLESSConfig{
				Type:     "ws",
				Security: "tls",
				SNI:      "ws.example.com",
				FP:       "chrome",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				if settings["network"] != "ws" {
					t.Errorf("network = %v, want ws", settings["network"])
				}
				ws, ok := settings["wsSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("wsSettings not found")
				}
				if _, exists := ws["path"]; exists {
					t.Error("path should not be set when empty")
				}
				if _, exists := ws["headers"]; exists {
					t.Error("headers should not be set when host is empty")
				}
			},
		},
		{
			name: "xhttp settings with current options",
			config: &VLESSConfig{
				Type:      "xhttp",
				Security:  "reality",
				Host:      "cdn.example.com",
				Path:      "/api",
				Mode:      "stream-up",
				Extra:     json.RawMessage(`{"xPaddingBytes":"100-1000"}`),
				FinalMask: json.RawMessage(`{"tcp":[{"type":"salamander","settings":{"password":"mask"}}]}`),
				PBK:       "test-key",
				SNI:       "www.example.com",
				FP:        "chrome",
				SID:       "0123456789abcdef",
				PQV:       "test-pq-key",
				SPX:       "/crawler",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				if settings["network"] != "xhttp" {
					t.Errorf("network = %v, want xhttp", settings["network"])
				}
				xhttp, ok := settings["xhttpSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("xhttpSettings not found")
				}
				if xhttp["host"] != "cdn.example.com" {
					t.Errorf("host = %v, want cdn.example.com", xhttp["host"])
				}
				if xhttp["path"] != "/api" {
					t.Errorf("path = %v, want /api", xhttp["path"])
				}
				if xhttp["mode"] != "stream-up" {
					t.Errorf("mode = %v, want stream-up", xhttp["mode"])
				}
				if string(xhttp["extra"].(json.RawMessage)) != `{"xPaddingBytes":"100-1000"}` {
					t.Errorf("extra = %s", xhttp["extra"])
				}
				if string(settings["finalmask"].(json.RawMessage)) == "" {
					t.Error("finalmask not found")
				}
				reality := settings["realitySettings"].(map[string]interface{})
				if reality["password"] != "test-key" {
					t.Errorf("password = %v, want test-key", reality["password"])
				}
				if reality["mldsa65Verify"] != "test-pq-key" {
					t.Errorf("mldsa65Verify = %v, want test-pq-key", reality["mldsa65Verify"])
				}
			},
		},
		{
			name: "httpupgrade settings",
			config: &VLESSConfig{
				Type: "httpupgrade",
				Host: "cdn.example.com",
				Path: "/upgrade",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				httpUpgrade, ok := settings["httpupgradeSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("httpupgradeSettings not found")
				}
				if httpUpgrade["host"] != "cdn.example.com" {
					t.Errorf("host = %v, want cdn.example.com", httpUpgrade["host"])
				}
				if httpUpgrade["path"] != "/upgrade" {
					t.Errorf("path = %v, want /upgrade", httpUpgrade["path"])
				}
			},
		},
		{
			name: "kcp settings",
			config: func() *VLESSConfig {
				mtu := uint32(1350)
				tti := uint32(50)
				return &VLESSConfig{Type: "kcp", KCPMTU: &mtu, KCPTTI: &tti}
			}(),
			checks: func(t *testing.T, settings map[string]interface{}) {
				kcp, ok := settings["kcpSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("kcpSettings not found")
				}
				if kcp["mtu"] != uint32(1350) {
					t.Errorf("mtu = %v, want 1350", kcp["mtu"])
				}
				if kcp["tti"] != uint32(50) {
					t.Errorf("tti = %v, want 50", kcp["tti"])
				}
			},
		},
		{
			name: "current tls settings",
			config: &VLESSConfig{
				Type:                 "xhttp",
				Security:             "tls",
				SNI:                  "tls.example.com",
				FP:                   "chrome",
				ALPN:                 []string{"h2", "http/1.1"},
				ECHConfigList:        "ech-config",
				PinnedPeerCertSHA256: "cert-pin",
				VerifyPeerCertByName: "verify.example.com",
			},
			checks: func(t *testing.T, settings map[string]interface{}) {
				tlsSettings, ok := settings["tlsSettings"].(map[string]interface{})
				if !ok {
					t.Fatal("tlsSettings not found")
				}
				if !reflect.DeepEqual(tlsSettings["alpn"], []string{"h2", "http/1.1"}) {
					t.Errorf("alpn = %#v", tlsSettings["alpn"])
				}
				if tlsSettings["echConfigList"] != "ech-config" {
					t.Errorf("echConfigList = %v", tlsSettings["echConfigList"])
				}
				if tlsSettings["pinnedPeerCertSha256"] != "cert-pin" {
					t.Errorf("pinnedPeerCertSha256 = %v", tlsSettings["pinnedPeerCertSha256"])
				}
				if tlsSettings["verifyPeerCertByName"] != "verify.example.com" {
					t.Errorf("verifyPeerCertByName = %v", tlsSettings["verifyPeerCertByName"])
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
		UUID:       "test-uuid",
		Address:    "example.com",
		Port:       443,
		Encryption: "none",
		Flow:       "xtls-rprx-vision",
		Type:       "tcp",
		Security:   "reality",
		PBK:        "test-key",
		SNI:        "google.com",
		SID:        "short123",
		SPX:        "/",
		FP:         "chrome",
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
	if users["encryption"] != "none" {
		t.Errorf("encryption = %v, want none", users["encryption"])
	}
	if users["flow"] != "xtls-rprx-vision" {
		t.Errorf("flow = %v, want xtls-rprx-vision", users["flow"])
	}
}

func TestCreateXrayConfig_gRPC(t *testing.T) {
	config := &VLESSConfig{
		UUID:        "grpc-uuid",
		Address:     "grpc.example.com",
		Port:        443,
		Type:        "grpc",
		Security:    "reality",
		ServiceName: "grpc-service",
		Authority:   "grpc-host",
		MultiMode:   true,
		PBK:         "test-key",
		SNI:         "grpc.example.com",
		FP:          "chrome",
		SID:         "ab12cd34",
	}

	jsonData, err := CreateXrayConfig(config, 1081)
	if err != nil {
		t.Fatalf("CreateXrayConfig() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	outbounds := result["outbounds"].([]interface{})
	outbound := outbounds[0].(map[string]interface{})
	ss := outbound["streamSettings"].(map[string]interface{})

	if ss["network"] != "grpc" {
		t.Errorf("network = %v, want grpc", ss["network"])
	}
	if ss["security"] != "reality" {
		t.Errorf("security = %v, want reality", ss["security"])
	}

	grpc, ok := ss["grpcSettings"].(map[string]interface{})
	if !ok {
		t.Fatal("grpcSettings not found in streamSettings")
	}
	if grpc["serviceName"] != "grpc-service" {
		t.Errorf("serviceName = %v, want grpc-service", grpc["serviceName"])
	}
	if grpc["authority"] != "grpc-host" {
		t.Errorf("authority = %v, want grpc-host", grpc["authority"])
	}
	if grpc["multiMode"] != true {
		t.Errorf("multiMode = %v, want true", grpc["multiMode"])
	}

	inbounds := result["inbounds"].([]interface{})
	inbound := inbounds[0].(map[string]interface{})
	if inbound["port"].(float64) != 1081 {
		t.Errorf("inbound port = %v, want 1081", inbound["port"])
	}
}

func TestCreateXrayConfig_XHTTPBuildsWithCurrentXray(t *testing.T) {
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	config := &VLESSConfig{
		UUID:       "11111111-1111-4111-8111-111111111111",
		Address:    "edge.example.com",
		Port:       443,
		Encryption: "none",
		Flow:       "xtls-rprx-vision",
		Type:       "xhttp",
		Security:   "reality",
		PBK:        publicKey,
		SNI:        "www.example.com",
		FP:         "chrome",
		SID:        "0123456789abcdef",
		Host:       "cdn.example.com",
		Path:       "/api",
		Mode:       "stream-up",
		Extra:      json.RawMessage(`{"xPaddingBytes":"100-1000"}`),
	}

	jsonData, err := CreateXrayConfig(config, 1082)
	if err != nil {
		t.Fatalf("CreateXrayConfig() error = %v", err)
	}

	var parsed conf.Config
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("failed to parse generated config: %v", err)
	}
	if _, err := parsed.Build(); err != nil {
		t.Fatalf("current Xray rejected generated XHTTP config: %v", err)
	}
}

func TestCreateXrayConfig_WithXRAYLogLevel(t *testing.T) {
	config := &VLESSConfig{
		UUID:     "test-uuid",
		Address:  "example.com",
		Port:     443,
		Type:     "tcp",
		Security: "tls",
		SNI:      "example.com",
		FP:       "chrome",
	}

	origVal := os.Getenv("XRAY_LOG_LEVEL")
	os.Setenv("XRAY_LOG_LEVEL", "debug")
	defer os.Setenv("XRAY_LOG_LEVEL", origVal)

	jsonData, err := CreateXrayConfig(config, 1080)
	if err != nil {
		t.Fatalf("CreateXrayConfig() error = %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(jsonData, &result)

	log := result["log"].(map[string]interface{})
	if log["loglevel"] != "debug" {
		t.Errorf("loglevel = %v, want debug", log["loglevel"])
	}
}

func TestLoadXrayConfigFile(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "xray.json")
		os.WriteFile(path, []byte(`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"srv.com","port":443}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"srv.com"}}}]}`), 0644)

		data, labels, err := LoadXrayConfigFile(path, 2080)
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		var result map[string]interface{}
		json.Unmarshal(data, &result)
		inbounds := result["inbounds"].([]interface{})
		inbound := inbounds[0].(map[string]interface{})
		if inbound["port"].(float64) != 2080 {
			t.Errorf("socks port = %v, want 2080", inbound["port"])
		}
		if inbound["protocol"] != "socks" {
			t.Errorf("protocol = %v, want socks", inbound["protocol"])
		}

		if labels.Server != "srv.com:443" {
			t.Errorf("Server = %v, want srv.com:443", labels.Server)
		}
		if labels.Security != "tls" {
			t.Errorf("Security = %v, want tls", labels.Security)
		}
		if labels.SNI != "srv.com" {
			t.Errorf("SNI = %v, want srv.com", labels.SNI)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, _, err := LoadXrayConfigFile("/nonexistent/xray.json", 2080)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "bad.json")
		os.WriteFile(path, []byte(`not json`), 0644)

		_, _, err := LoadXrayConfigFile(path, 2080)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestLoadXrayConfigFile_OverwritesUserInbounds(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "xray.json")
	config := `{"inbounds":[{"port":12345,"protocol":"http"}],"outbounds":[{"protocol":"freedom"}]}`
	os.WriteFile(path, []byte(config), 0644)

	data, _, err := LoadXrayConfigFile(path, 3080)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)

	inbounds := result["inbounds"].([]interface{})
	if len(inbounds) != 1 {
		t.Fatalf("expected 1 inbound (SOCKS), got %d", len(inbounds))
	}
	inbound := inbounds[0].(map[string]interface{})
	if inbound["protocol"] != "socks" {
		t.Errorf("protocol = %v, want socks (user inbounds should be replaced)", inbound["protocol"])
	}
	if inbound["port"].(float64) != 3080 {
		t.Errorf("port = %v, want 3080", inbound["port"])
	}
}

func TestLoadXrayConfigFile_WithXRAYLogLevel(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "xray.json")
	os.WriteFile(path, []byte(`{"outbounds":[{"protocol":"freedom"}]}`), 0644)

	origVal := os.Getenv("XRAY_LOG_LEVEL")
	os.Setenv("XRAY_LOG_LEVEL", "debug")
	defer os.Setenv("XRAY_LOG_LEVEL", origVal)

	data, _, err := LoadXrayConfigFile(path, 2080)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)

	log := result["log"].(map[string]interface{})
	if log["loglevel"] != "debug" {
		t.Errorf("loglevel = %v, want debug", log["loglevel"])
	}
}

func TestExtractMetricLabelsFromXrayConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
		want MetricLabels
	}{
		{
			name: "vless outbound with reality",
			json: `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443}]},"streamSettings":{"security":"reality","realitySettings":{"serverName":"google.com"}}}]}`,
			want: MetricLabels{Server: "example.com:443", Security: "reality", SNI: "google.com"},
		},
		{
			name: "trojan outbound with tls",
			json: `{"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"trojan.example.com","port":8443}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"trojan.example.com"}}}]}`,
			want: MetricLabels{Server: "trojan.example.com:8443", Security: "tls", SNI: "trojan.example.com"},
		},
		{
			name: "empty outbounds",
			json: `{"outbounds":[]}`,
			want: MetricLabels{},
		},
		{
			name: "no outbounds",
			json: `{}`,
			want: MetricLabels{},
		},
		{
			name: "outbound without settings",
			json: `{"outbounds":[{"protocol":"freedom"}]}`,
			want: MetricLabels{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw map[string]interface{}
			json.Unmarshal([]byte(tt.json), &raw)

			got := ExtractMetricLabelsFromXrayConfig(raw)
			if got != tt.want {
				t.Errorf("ExtractMetricLabelsFromXrayConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtractMetricLabelsFromXrayConfig_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		json string
		want MetricLabels
	}{
		{
			name: "outbounds is not a slice",
			json: `{"outbounds":"not-a-slice"}`,
			want: MetricLabels{},
		},
		{
			name: "first outbound is not a map",
			json: `{"outbounds":["not-a-map"]}`,
			want: MetricLabels{},
		},
		{
			name: "settings vnext entry is not a map",
			json: `{"outbounds":[{"protocol":"vless","settings":{"vnext":["not-a-map"]}}]}`,
			want: MetricLabels{},
		},
		{
			name: "settings servers entry is not a map",
			json: `{"outbounds":[{"protocol":"trojan","settings":{"servers":["not-a-map"]}}]}`,
			want: MetricLabels{},
		},
		{
			name: "streamSettings without security",
			json: `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.com","port":443}]},"streamSettings":{}}]}`,
			want: MetricLabels{Server: "a.com:443"},
		},
		{
			name: "streamSettings with non-map realitySettings",
			json: `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.com","port":443}]},"streamSettings":{"security":"reality","realitySettings":"not-a-map"}}]}`,
			want: MetricLabels{Server: "a.com:443", Security: "reality"},
		},
		{
			name: "streamSettings with non-map tlsSettings",
			json: `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.com","port":443}]},"streamSettings":{"security":"tls","tlsSettings":"not-a-map"}}]}`,
			want: MetricLabels{Server: "a.com:443", Security: "tls"},
		},
		{
			name: "servers with valid address and port",
			json: `{"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"trojan.com","port":8443}]}}]}`,
			want: MetricLabels{Server: "trojan.com:8443"},
		},
		{
			name: "vnext with zero port",
			json: `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"a.com","port":0}]}}]}`,
			want: MetricLabels{},
		},
		{
			name: "servers with zero port",
			json: `{"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"a.com","port":0}]}}]}`,
			want: MetricLabels{},
		},
		{
			name: "vnext with empty address",
			json: `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"","port":443}]}}]}`,
			want: MetricLabels{},
		},
		{
			name: "servers with empty address",
			json: `{"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"","port":443}]}}]}`,
			want: MetricLabels{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw map[string]interface{}
			json.Unmarshal([]byte(tt.json), &raw)

			got := ExtractMetricLabelsFromXrayConfig(raw)
			if got != tt.want {
				t.Errorf("ExtractMetricLabelsFromXrayConfig() = %+v, want %+v", got, tt.want)
			}
		})
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

// Benchmarks

func BenchmarkParseVLESSURL(b *testing.B) {
	b.ReportAllocs()
	urls := []string{
		"vless://uuid-123@example.com:443?type=tcp&security=reality&pbk=test-key&sni=google.com&sid=short123&spx=/&fp=chrome",
		"vless://uuid-456@server.net:8443?type=ws&security=tls&sni=server.net&fp=firefox&host=server.net&path=%2Fws",
		"vless://uuid-789@grpc.example.com:443/?type=grpc&serviceName=grpc-service&authority=grpc-host&multiMode=true&security=reality&pbk=test-pbk&fp=chrome&sni=grpc.example.com&sid=ab12cd34",
		"vless://uuid@minimal.com:443?type=tcp&security=none",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseVLESSURL(urls[i%len(urls)])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateXrayConfig(b *testing.B) {
	b.ReportAllocs()
	configs := []*VLESSConfig{
		{UUID: "test-uuid-1", Address: "example.com", Port: 443, Type: "tcp", Security: "reality", PBK: "test-key", SNI: "google.com", SID: "short123", SPX: "/", FP: "chrome"},
		{UUID: "test-uuid-2", Address: "server.net", Port: 8443, Type: "ws", Security: "tls", SNI: "server.net", FP: "firefox", Host: "server.net", Path: "/ws"},
		{UUID: "test-uuid-3", Address: "grpc.example.com", Port: 443, Type: "grpc", Security: "reality", ServiceName: "grpc-service", Authority: "grpc-host", MultiMode: true, PBK: "test-pbk", SNI: "grpc.example.com", FP: "chrome", SID: "ab12cd34"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CreateXrayConfig(configs[i%len(configs)], 1080+i%10)
		if err != nil {
			b.Fatal(err)
		}
	}
}
