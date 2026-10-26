package config

import (
	"encoding/base64"
	"testing"
)

func TestSubscriptionPreservesExplicitVersusGeneratedNames(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		generated  bool
	}{
		{"link-explicit", "vless://id@example.com:443#Chosen", false},
		{"link-generated", "vless://id@example.com:443", true},
		{"vmess-explicit", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"ps":"Chosen","add":"example.com"}`)), false},
		{"vmess-generated", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"example.com"}`)), true},
		{"native-explicit", `{"remarks":"Chosen","outbounds":[{"protocol":"freedom"}]}`, false},
		{"native-generated", `{"outbounds":[{"protocol":"freedom"}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tunnels, err := parseSubscription([]byte(tc.body), "auto")
			if err != nil {
				t.Fatal(err)
			}
			if len(tunnels) != 1 || tunnels[0].NameGenerated != tc.generated {
				t.Fatal("lost name origin needed for cross-source deduplication")
			}
		})
	}
}
