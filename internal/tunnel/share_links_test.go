package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessoutbound "github.com/xtls/xray-core/proxy/vmess/outbound"
)

func vmessTestLink(payload string) string {
	return "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(payload))
}

func TestCreateShareLinkConfig(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000001"
	tests := []struct{ name, link, protocol, server, security, sni string }{
		{"trojan", "trojan://secret@example.com:443#node", "trojan", "example.com:443", "tls", "example.com"},
		{"trojan_ws", "trojan://secret@example.com:443?type=ws&path=%2Fsocket&host=cdn.example.com&sni=tls.example.com", "trojan", "example.com:443", "tls", "tls.example.com"},
		{"trojan_encoded_password", "trojan://p%40ss%3Aword@example.com:443?peer=peer.example.com", "trojan", "example.com:443", "tls", "peer.example.com"},
		{"ss_plain", "ss://aes-128-gcm:secret@example.com:8388", "shadowsocks", "example.com:8388", "", ""},
		{"ss_2022", "ss://2022-blake3-aes-128-gcm:" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))) + "@example.com:8388", "shadowsocks", "example.com:8388", "", ""},
		{"ss_encoded", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret")) + "@example.com:8388/#node", "shadowsocks", "example.com:8388", "", ""},
		{"ss_legacy", "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p@ss/:word@example.com:8388")) + "#node", "shadowsocks", "example.com:8388", "", ""},
		{"vmess_json", vmessTestLink(`{"v":"2","ps":"node","add":"example.com","port":"443","id":"` + uuid + `","aid":"0","net":"ws","path":"/socket","tls":"tls","sni":"tls.example.com"}`), "vmess", "example.com:443", "tls", "tls.example.com"},
		{"vmess_numeric", vmessTestLink(`{"v":2,"add":"example.com","port":443,"id":"` + uuid + `","aid":0,"net":"tcp","tls":""}`), "vmess", "example.com:443", "", ""},
		{"vmess_url", "vmess://" + uuid + "@example.com:443?type=ws&security=tls&encryption=auto", "vmess", "example.com:443", "tls", "example.com"},
		{"vmess_cipher_url", "vmess://auto:" + uuid + "@example.com:443?type=ws&security=tls", "vmess", "example.com:443", "tls", "example.com"},
		{"vmess_grpc", vmessTestLink(`{"add":"example.com","port":443,"id":"` + uuid + `","aid":0,"net":"grpc","path":"service","tls":"tls"}`), "vmess", "example.com:443", "tls", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, labels, err := CreateShareLinkConfig(tt.link, 1080)
			if err != nil {
				t.Fatal(err)
			}
			if labels.Server != tt.server || labels.Security != tt.security || labels.SNI != tt.sni {
				t.Fatalf("unexpected labels: %+v", labels)
			}
			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			out := raw["outbounds"].([]interface{})[0].(map[string]interface{})
			if out["protocol"] != tt.protocol {
				t.Fatalf("protocol=%v", out["protocol"])
			}
			var cfg conf.Config
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			pb, err := cfg.Build()
			if err != nil {
				t.Fatalf("Xray build: %v", err)
			}
			// Construction verifies side-effect registration of each outbound protocol
			// without binding sockets or contacting the remote server.
			instance, err := core.New(pb)
			if err != nil {
				t.Fatalf("Xray core: %v", err)
			}
			if err := instance.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestShareLinkPreservesTransportAndCredentials(t *testing.T) {
	link := "trojan://p%40ss%3Aword@example.com:443?type=ws&path=%2Fsocket&host=cdn.example.com&sni=tls.example.com&alpn=h2%2Chttp%2F1.1&fp=firefox"
	data, _, err := CreateShareLinkConfig(link, 1080)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []struct {
			Settings       struct{ Servers []struct{ Password string } }
			StreamSettings struct {
				WSSettings  struct{ Path, Host string }
				TLSSettings struct {
					ServerName, Fingerprint string
					ALPN                    []string
				}
			}
		}
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	out := cfg.Outbounds[0]
	if out.Settings.Servers[0].Password != "p@ss:word" || out.StreamSettings.WSSettings.Path != "/socket" || out.StreamSettings.WSSettings.Host != "cdn.example.com" || out.StreamSettings.TLSSettings.Fingerprint != "firefox" || len(out.StreamSettings.TLSSettings.ALPN) != 2 {
		t.Fatalf("lost transport or credentials: %s", data)
	}
}

func TestShareLinkRejectsUnsupportedOrMalformedInput(t *testing.T) {
	tests := []string{
		"https://example.com", "trojan://example.com:443", "trojan://secret@example.com:0", "trojan://secret@example.com:65536",
		"trojan://secret@example.com:443?security=madeup", "trojan://secret@example.com:443?type=ws&type=tcp", "trojan://secret@example.com:443?allowInsecure=true", "trojan://secret@example.com:443?insecure=invalid", "trojan://secret@example.com:443?unknown=1", "trojan://secret@example.com:443?type=grpc", "trojan://secret@example.com:443?security=reality", "trojan://a:b@example.com:443", "trojan://secret@example.com:443/path", "trojan://secret@example.com:443?path=%zz",
		"ss://aes-128-gcm:secret@example.com:8388?plugin=obfs-local", "ss://aes-128-gcm:@example.com:8388", "ss://not-base64@example.com:8388", "ss://not-base64", "ss://" + base64.StdEncoding.EncodeToString([]byte("missing-fields")),
		"vmess://not-base64", vmessTestLink(`null`), vmessTestLink(`[]`), vmessTestLink(`{"add":"example.com","port":443}`), vmessTestLink(`{"add":"example.com","port":443,"id":"id","aid":64}`), vmessTestLink(`{"add":"example.com","port":443,"id":"id","type":"http"}`), vmessTestLink(`{"add":"example.com","port":443,"id":"id","net":"kcp","path":"seed"}`), vmessTestLink(`{"add":"example.com","port":443,"id":"id","unexpected":true}`), vmessTestLink(`{"add":"example.com","port":443,"id":"id","unknown":"value"}`),
		"vmess://id@example.com:443?scy=madeup", "vmess://id:password@example.com:443",
	}
	for _, link := range tests {
		t.Run(strings.SplitN(link, ":", 2)[0], func(t *testing.T) {
			if _, _, err := CreateShareLinkConfig(link, 1080); err == nil {
				t.Fatalf("accepted unsupported link %q", link)
			}
		})
	}
}

func TestLoadXrayConfigJSONValidation(t *testing.T) {
	for _, data := range []string{"null", "[]", "{}", `{"outbounds":null}`, `{"outbounds":[]}`, `{"outbounds":[null]}`, `{"outbounds":[{}]}`, "invalid"} {
		if _, _, err := LoadXrayConfigJSON([]byte(data), 1080); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if _, _, err := LoadXrayConfigJSON([]byte(`{"outbounds":[{"protocol":"freedom"}]}`), port); err == nil {
			t.Fatalf("accepted port %d", port)
		}
	}
	input := `{"dns":{"servers":["1.1.1.1"]},"routing":{"domainStrategy":"AsIs"},"outbounds":[{"protocol":"freedom"}],"inbounds":[{"port":9999}],"log":{"loglevel":"debug"}}`
	data, _, err := LoadXrayConfigJSON([]byte(input), 1080)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["dns"] == nil || raw["routing"] == nil {
		t.Fatal("lost original sections")
	}
	in := raw["inbounds"].([]interface{})[0].(map[string]interface{})
	if in["listen"] != "127.0.0.1" || in["port"] != float64(1080) || in["protocol"] != "socks" {
		t.Fatal("incorrect inbound")
	}
}

func TestShadowsocksIPv6(t *testing.T) {
	u := url.URL{Scheme: "ss", Host: net.JoinHostPort("2001:db8::1", "8388"), User: url.UserPassword("aes-128-gcm", "pass")}
	data, labels, err := CreateShareLinkConfig(u.String(), 1080)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"address": "2001:db8::1"`) {
		t.Fatalf("lost IPv6 address: %s", data)
	}
	if labels.Server != "[2001:db8::1]:8388" {
		t.Fatalf("ambiguous IPv6 label: %s", labels.Server)
	}
}

func TestNativeXrayConfigRuntimeFeatures(t *testing.T) {
	input := []byte(`{
  "dns":{"servers":["localhost"]},
  "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},
  "stats":{},
  "routing":{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["full:blocked.example.com"],"outboundTag":"block"}]},
  "outbounds":[
   {"tag":"proxy","protocol":"http","settings":{"servers":[{"address":"127.0.0.1","port":8080}]}},
   {"tag":"block","protocol":"blackhole","settings":{}},
   {"tag":"direct","protocol":"freedom","settings":{}},
   {"tag":"dns","protocol":"dns","settings":{}},
   {"tag":"loop","protocol":"loopback","settings":{"inboundTag":"loop-in"}}
  ]
 }`)
	data, _, err := LoadXrayConfigJSON(input, 1080)
	if err != nil {
		t.Fatal(err)
	}
	var cfg conf.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	pb, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(pb)
	if err != nil {
		t.Fatalf("native feature registration: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVMessBuiltCipherPreserved(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000001"
	for _, tc := range []struct {
		cipher string
		want   protocol.SecurityType
	}{
		{"", protocol.SecurityType_AUTO}, {"auto", protocol.SecurityType_AUTO},
		{"aes-128-gcm", protocol.SecurityType_AES128_GCM},
		{"chacha20-poly1305", protocol.SecurityType_CHACHA20_POLY1305},
	} {
		links := []string{
			"vmess://" + uuid + "@example.com:443?scy=" + tc.cipher,
			"vmess://" + uuid + "@example.com:443?encryption=" + tc.cipher,
			vmessTestLink(`{"add":"example.com","port":443,"id":"` + uuid + `","scy":"` + tc.cipher + `"}`),
		}
		if tc.cipher != "" {
			links = append(links, "vmess://"+tc.cipher+":"+uuid+"@example.com:443")
		}
		for _, link := range links {
			data, _, err := CreateShareLinkConfig(link, 1080)
			if err != nil {
				t.Fatal(err)
			}
			var cfg conf.Config
			if err := json.Unmarshal(data, &cfg); err != nil {
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
}

func TestVMessRejectsUnsupportedCipherForms(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000001"
	for _, cipher := range []string{"none", "zero", "unknown"} {
		for _, link := range []string{
			"vmess://" + uuid + "@example.com:443?scy=" + cipher,
			"vmess://" + uuid + "@example.com:443?encryption=" + cipher,
			"vmess://" + cipher + ":" + uuid + "@example.com:443",
			vmessTestLink(`{"add":"example.com","port":443,"id":"` + uuid + `","scy":"` + cipher + `"}`),
		} {
			if _, _, err := CreateShareLinkConfig(link, 1080); err == nil {
				t.Fatalf("accepted unsupported cipher %s", cipher)
			}
		}
	}
	if _, _, err := CreateShareLinkConfig("vmess://"+uuid+"@example.com:443?scy=auto&encryption=aes-128-gcm", 1080); err == nil {
		t.Fatal("accepted conflicting ciphers")
	}
}

func TestVMessKCPAliasesRejectSeed(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000001"
	for _, network := range []string{"kcp", "mkcp"} {
		for _, link := range []string{
			"vmess://" + uuid + "@example.com:443?type=" + network + "&path=required-seed",
			vmessTestLink(`{"add":"example.com","port":443,"id":"` + uuid + `","net":"` + network + `","path":"required-seed"}`),
		} {
			if _, _, err := CreateShareLinkConfig(link, 1080); err == nil {
				t.Fatalf("accepted %s seed", network)
			}
		}
		for _, link := range []string{
			"vmess://" + uuid + "@example.com:443?type=" + network,
			vmessTestLink(`{"add":"example.com","port":443,"id":"` + uuid + `","net":"` + network + `"}`),
		} {
			if _, _, err := CreateShareLinkConfig(link, 1080); err != nil {
				t.Fatalf("unseeded %s rejected: %v", network, err)
			}
		}
	}
}
