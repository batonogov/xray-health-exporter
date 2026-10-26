package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf"
)

func TestSubscriptionValidation(t *testing.T) {
	for _, sub := range []Subscription{
		{URL: "ftp://host"}, {URL: "https://"}, {URL: "https://host", UpdateInterval: "0s"},
		{URL: "https://host", UpdateInterval: "-1s"}, {URL: "https://host", Timeout: "0s"},
		{URL: "https://host", Timeout: "oops"}, {URL: "https://host", Format: "unknown"},
	} {
		if err := validateSubscription(sub); err == nil {
			t.Fatalf("accepted invalid subscription %+v", sub)
		}
	}
	if err := validateSubscription(Subscription{URL: "https://host", Timeout: "5s", UpdateInterval: "24h", Format: "clash"}); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionContextHeadersAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" || r.UserAgent() != "test-client" {
			t.Error("request headers missing")
		}
		_, _ = w.Write([]byte("vless://uuid@host:443#Example"))
	}))
	defer server.Close()
	tunnels, err := FetchSubscriptionContext(context.Background(), Subscription{URL: server.URL, UserAgent: "test-client", Headers: map[string]string{"Authorization": "Bearer secret"}})
	if err != nil || len(tunnels) != 1 {
		t.Fatalf("fetch: %v, %v", tunnels, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = FetchSubscriptionContext(ctx, Subscription{URL: server.URL + "/private-token"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if strings.Contains(err.Error(), "private-token") {
		t.Fatal("secret in error")
	}
}

func TestSubscriptionResponseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"empty", "", 200}, {"html", "<html>Login required</html>", 200},
		{"oversized", strings.Repeat(" ", maxSubscriptionBytes+1), 200},
		{"invalid-json", "{broken", 200}, {"empty-json", "[]", 200},
		{"no-outbound", "{\"remarks\":\"a\"}", 200},
		{"unsupported", "hysteria2://password@example.com", 200}, {"http-error", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			_, err := FetchSubscriptionContext(context.Background(), Subscription{URL: server.URL + "/secret?token=private"})
			if err == nil {
				t.Fatal("invalid response accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
				t.Fatalf("secret leaked: %v", err)
			}
		})
	}
}

func TestSubscriptionTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	_, err := FetchSubscriptionContext(context.Background(), Subscription{URL: server.URL + "/secret", Timeout: "10ms"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("bad timeout error: %v", err)
	}
}

func TestSubscriptionRedirectDoesNotForwardSecrets(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials forwarded across origins")
		}
		if r.Referer() != "" {
			t.Error("subscription URL forwarded in Referer across origins")
		}
		_, _ = w.Write([]byte("vless://uuid@host:443"))
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer source.Close()
	_, err := FetchSubscriptionContext(context.Background(), Subscription{URL: source.URL + "/subscription/private-token?token=secret", Headers: map[string]string{"X-Token": "secret", "Authorization": "Bearer secret", "Cookie": "session=secret"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionSameOriginRedirectOmitsReferer(t *testing.T) {
	for _, tc := range []struct{ name, referer string }{
		{"automatic-referer", ""},
		{"explicit-referer", "https://provider.example/private-token?token=secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Token") != "secret" || r.Header.Get("Authorization") != "Bearer secret" {
					t.Error("same-origin authentication headers were lost")
				}
				if r.URL.Path == "/subscription/private-token" {
					http.Redirect(w, r, "/redirect/second-token?token=second-secret", http.StatusFound)
					return
				}
				if r.Referer() != "" {
					t.Error("subscription URL forwarded in Referer on same-origin redirect")
				}
				if r.URL.Path == "/redirect/second-token" {
					http.Redirect(w, r, "/servers", http.StatusFound)
					return
				}
				_, _ = w.Write([]byte("vless://uuid@host:443"))
			}))
			defer server.Close()
			headers := map[string]string{"X-Token": "secret", "Authorization": "Bearer secret"}
			if tc.referer != "" {
				headers["Referer"] = tc.referer
			}
			tunnels, err := FetchSubscriptionContext(context.Background(), Subscription{URL: server.URL + "/subscription/private-token?token=secret", Headers: headers})
			if err != nil || len(tunnels) != 1 {
				t.Fatalf("redirected fetch: got %d tunnels, error %v", len(tunnels), err)
			}
		})
	}
}

func TestParseSubscriptions(t *testing.T) {
	xray := `{"remarks":"Native","routing":{"domainStrategy":"AsIs"},"outbounds":[{"protocol":"freedom"}]}`
	for _, tc := range []struct {
		name, body, format string
		count              int
	}{
		{"native", xray, "auto", 1}, {"native-list", "[" + xray + "," + xray + "]", "auto", 2},
		{"links", "vless://id@host:443#One\ntrojan://pw@host:443#Two\nss://encoded@host:8388#Three\nvmess://encoded#Four", "auto", 4},
		{"dedup", "vless://id@host:443\nvless://id@host:443", "text", 1},
		{"base64", base64.RawURLEncoding.EncodeToString([]byte("vless://id@host:443")), "text", 1},
		{"comments", "# Comment\n\nvless://id@host:443", "text", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSubscription([]byte(tc.body), tc.format)
			if err != nil || len(got) != tc.count {
				t.Fatalf("got %v, %v", got, err)
			}
			if strings.HasPrefix(tc.name, "native") {
				if got[0].Name != "Native" || !strings.Contains(string(got[0].XrayConfigJSON), "domainStrategy") {
					t.Fatalf("native config lost: %+v", got[0])
				}
				ApplyTunnelDefaults(&got[0], Defaults{})
				if err := got[0].Validate(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestResolveSubscriptionsContextPartialFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte("vless://id@host:443#Working"))
	}))
	defer server.Close()
	got, err := ResolveSubscriptionsContext(context.Background(), &Config{Subscriptions: []Subscription{{URL: server.URL}, {URL: server.URL + "/bad"}}, Defaults: Defaults{CheckInterval: "17s"}})
	if len(got) != 1 || err == nil || got[0].CheckInterval != "17s" {
		t.Fatalf("got %v, %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveSubscriptionsContext(ctx, &Config{Subscriptions: []Subscription{{URL: server.URL}}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestClashSubscriptionConversion(t *testing.T) {
	body := `proxies:
  - name: Reality
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    tls: true
    servername: example.com
    reality-opts:
      public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      short-id: "abcd"
  - name: WebSocket
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    network: ws
    tls: true
    alpn: [http/1.1]
    ws-opts:
      path: /ws
      headers:
        Host: front.example.com
  - name: Trojan
    type: trojan
    server: example.com
    port: 443
    password: secret
    network: grpc
    grpc-opts:
      grpc-service-name: service
  - name: Shadowsocks
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
`
	got, err := parseSubscription([]byte(body), "auto")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d", len(got))
	}
	for i, protocol := range []string{"vless", "vmess", "trojan", "shadowsocks"} {
		var cfg struct {
			Outbounds []struct {
				Protocol string         `json:"protocol"`
				Stream   map[string]any `json:"streamSettings"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal(got[i].XrayConfigJSON, &cfg); err != nil {
			t.Fatal(err)
		}
		var coreConfig conf.Config
		if err := json.Unmarshal(got[i].XrayConfigJSON, &coreConfig); err != nil {
			t.Fatal(err)
		}
		if _, err := coreConfig.Build(); err != nil {
			t.Fatalf("core rejected %s conversion: %v", protocol, err)
		}
		if cfg.Outbounds[0].Protocol != protocol {
			t.Errorf("wrong protocol: %s", cfg.Outbounds[0].Protocol)
		}
		if i == 0 && cfg.Outbounds[0].Stream["security"] != "reality" {
			t.Fatal("reality lost")
		}
		if i == 2 && cfg.Outbounds[0].Stream["security"] != "tls" {
			t.Fatal("trojan TLS lost")
		}
	}
}

func TestClashRejectsUnsupportedOptions(t *testing.T) {
	base := "proxies:\n  - name: Test\n    type: vless\n    server: example.com\n    port: 443\n    uuid: uuid\n"
	for _, option := range []string{
		"    network: h2\n", "    packet-encoding: xudp\n", "    plugin: obfs\n",
		"    port: 0\n", "    tls: maybe\n", "    ws-opts: {path: /ws}\n",
		"    network: ws\n    ws-opts: {max-early-data: 2048}\n",
		"    network: grpc\n    grpc-opts: {unknown: true}\n",
		"    tls: true\n    reality-opts: {public-key: pub, unknown: true}\n",
	} {
		if _, err := parseClashSubscription([]byte(base + option)); err == nil {
			t.Fatalf("accepted unsupported config: %s", option)
		}
	}
}

func TestSubscriptionContextDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := FetchSubscriptionContext(ctx, Subscription{URL: "https://example.invalid/private-token"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestSubscriptionNamesDoNotExposeCredentials(t *testing.T) {
	ss := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:secret@host.example:8388"))
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"id":"secret","add":"host.example","ps":"Named"}`))
	got, err := parseTextSubscription([]byte(ss + "\n" + vmess))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "host.example:8388" || got[1].Name != "Named" {
		t.Fatalf("unsafe names: %+v", got)
	}
}
func TestSubscriptionAutoDetectWrappedJSON(t *testing.T) {
	for _, payload := range []string{
		`{"outbounds":[{"protocol":"freedom"}]}`,
		`{"proxies":[{"name":"Test","type":"ss","server":"example.com","port":8388,"cipher":"aes-128-gcm","password":"secret"}]}`,
	} {
		for _, body := range []string{payload, base64.StdEncoding.EncodeToString([]byte(payload))} {
			got, err := parseSubscription([]byte(body), "auto")
			if err != nil || len(got) != 1 || len(got[0].XrayConfigJSON) == 0 {
				t.Fatalf("got %+v, %v", got, err)
			}
		}
	}
}
func TestSubscriptionDuplicateNames(t *testing.T) {
	for _, names := range []string{"    name: same\n", ""} {
		content := "subscriptions:\n  - url: https://example.com/a\n" + names + "  - url: https://example.com/b\n    name: "
		if names == "" {
			content += "subscription-1\n"
		} else {
			content += "same\n"
		}
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("accepted duplicate subscription name")
		}
	}
}
func TestClashRejectsRemovedCoreOptions(t *testing.T) {
	for _, opts := range []string{"    type: vmess\n    alterId: 1\n", "    type: vless\n    tls: true\n    skip-cert-verify: true\n"} {
		_, err := parseClashSubscription([]byte("proxies:\n  - name: Test\n    server: example.com\n    port: 443\n    uuid: uuid\n" + opts))
		if err == nil {
			t.Fatal("accepted removed core option")
		}
	}
}
