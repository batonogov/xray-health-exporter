package config

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessoutbound "github.com/xtls/xray-core/proxy/vmess/outbound"
)

func TestClashVMessBuiltCipherPreserved(t *testing.T) {
	for _, tc := range []struct {
		cipher string
		want   protocol.SecurityType
	}{
		{"", protocol.SecurityType_AUTO}, {"auto", protocol.SecurityType_AUTO},
		{"aes-128-gcm", protocol.SecurityType_AES128_GCM},
		{"chacha20-poly1305", protocol.SecurityType_CHACHA20_POLY1305},
	} {
		tunnel, err := clashProxy(map[string]any{"name": "test", "type": "vmess", "server": "example.com", "port": 443, "uuid": "00000000-0000-4000-8000-000000000001", "cipher": tc.cipher})
		if err != nil {
			t.Fatal(err)
		}
		var cfg conf.Config
		if err := json.Unmarshal(tunnel.XrayConfigJSON, &cfg); err != nil {
			t.Fatal(err)
		}
		built, err := cfg.Build()
		if err != nil {
			t.Fatal(err)
		}
		message, err := built.Outbound[0].ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		accountMessage, err := message.(*vmessoutbound.Config).Receiver.User.Account.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		got := accountMessage.(*vmess.Account).SecuritySettings.Type
		if got != tc.want {
			t.Fatalf("cipher %q built as %v, want %v", tc.cipher, got, tc.want)
		}
	}
}

func TestClashVMessRejectsUnsupportedCiphers(t *testing.T) {
	for _, cipher := range []string{"none", "zero", "unknown"} {
		_, err := clashProxy(map[string]any{"name": "test", "type": "vmess", "server": "example.com", "port": 443, "uuid": "00000000-0000-4000-8000-000000000001", "cipher": cipher})
		if err == nil {
			t.Fatalf("accepted unsupported cipher %s", cipher)
		}
	}
}
