package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAssignsDistinctSubscriptionIdentities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `subscriptions:
  - url: https://provider.example/subscription
    update_interval: 1h
  - url: https://provider.example/subscription
    update_interval: 2h
  - name: primary
    url: https://provider.example/subscription
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"subscription-1", "subscription-2", "primary"} {
		if got := cfg.Subscriptions[i].Name; got != want {
			t.Errorf("subscription %d identity=%q, want %q", i, got, want)
		}
	}
	if cfg.Subscriptions[0].URL != cfg.Subscriptions[1].URL || cfg.Subscriptions[0].UpdateInterval == cfg.Subscriptions[1].UpdateInterval {
		t.Fatal("request URL or independent interval changed")
	}
	// Reloads must derive the same identities rather than generating new names.
	again, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cfg.Subscriptions {
		if again.Subscriptions[i].Name != cfg.Subscriptions[i].Name {
			t.Fatal("subscription identity changed on reload")
		}
	}
}

func TestLoadConfigRejectsExplicitAndGeneratedSubscriptionNameCollision(t *testing.T) {
	for _, names := range []struct{ name, first, second string }{
		{"explicit-before-generated", "    name: subscription-2\n", ""},
		{"generated-before-explicit", "", "    name: subscription-1\n"},
		{"explicit-duplicates", "    name: primary\n", "    name: primary\n"},
	} {
		t.Run(names.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			body := "subscriptions:\n  - url: https://provider.example/first\n" + names.first + "  - url: https://provider.example/second\n" + names.second
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("accepted colliding source identities")
			}
		})
	}
}
