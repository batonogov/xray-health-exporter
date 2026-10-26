package config

import (
	"math"
	"strings"
	"testing"
)

func TestUnsafeProbeSettingsRejected(t *testing.T) {
	for _, field := range []string{"check_interval", "check_timeout", "download_timeout", "max_backoff"} {
		for _, value := range []string{"0s", "-1s", "not-a-duration", "999999999999999999999h"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				tunnel := Tunnel{URL: "vless://id@example.com:443"}
				ApplyTunnelDefaults(&tunnel, Defaults{})
				switch field {
				case "check_interval":
					tunnel.CheckInterval = value
				case "check_timeout":
					tunnel.CheckTimeout = value
				case "download_timeout":
					tunnel.DownloadTimeout = value
				case "max_backoff":
					tunnel.MaxBackoff = value
				}
				err := tunnel.Validate()
				if err == nil || !strings.Contains(err.Error(), field) {
					t.Fatalf("expected %s validation error, got %v", field, err)
				}
			})
		}
	}
	for _, value := range []float64{0, .5, math.NaN(), math.Inf(1), math.Inf(-1)} {
		tunnel := Tunnel{URL: "vless://id@example.com:443", BackoffMultiplier: &value}
		ApplyTunnelDefaults(&tunnel, Defaults{})
		if err := tunnel.Validate(); err == nil || !strings.Contains(err.Error(), "backoff_multiplier") {
			t.Fatalf("accepted unsafe multiplier %v: %v", value, err)
		}
	}
	tunnel := Tunnel{URL: "vless://id@example.com:443", DownloadMinSize: -1}
	ApplyTunnelDefaults(&tunnel, Defaults{})
	if err := tunnel.Validate(); err == nil {
		t.Fatal("accepted negative download size")
	}
}

func TestPositiveProbeDurationsAndDefaults(t *testing.T) {
	for _, value := range []string{"1ns", "30s", "1h30m"} {
		tunnel := Tunnel{URL: "vless://id@example.com:443", CheckInterval: value, CheckTimeout: value, DownloadTimeout: value, MaxBackoff: value}
		ApplyTunnelDefaults(&tunnel, Defaults{})
		if err := tunnel.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	tunnel := Tunnel{URL: "vless://id@example.com:443"}
	ApplyTunnelDefaults(&tunnel, Defaults{})
	if err := tunnel.Validate(); err != nil {
		t.Fatal(err)
	}
}
