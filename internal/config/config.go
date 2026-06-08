// Package config provides configuration types, loading, validation, and
// subscription resolution for xray-health-exporter.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"gopkg.in/yaml.v3"
)

// Default application-level configuration values.
const (
	DefaultConfigFile = "/app/config.yaml"
	DefaultListenAddr = ":9273"
)

// Config is the top-level configuration structure.
type Config struct {
	Defaults      Defaults       `yaml:"defaults"`
	Tunnels       []Tunnel       `yaml:"tunnels"`
	Subscriptions []Subscription `yaml:"subscriptions"`
}

// Defaults holds default values that each Tunnel can override.
type Defaults struct {
	CheckURL          string   `yaml:"check_url"`
	CheckInterval     string   `yaml:"check_interval"`
	CheckTimeout      string   `yaml:"check_timeout"`
	MaxBackoff        string   `yaml:"max_backoff"`
	BackoffMultiplier *float64 `yaml:"backoff_multiplier"`
}

// Subscription describes a remote subscription URL that provides tunnel entries.
type Subscription struct {
	URL            string `yaml:"url"`
	UpdateInterval string `yaml:"update_interval"`
}

// Tunnel describes a single tunnel configuration.
type Tunnel struct {
	Name              string   `yaml:"name"`
	URL               string   `yaml:"url"`
	XrayConfigFile    string   `yaml:"xray_config_file"`
	CheckURL          string   `yaml:"check_url"`
	CheckInterval     string   `yaml:"check_interval"`
	CheckTimeout      string   `yaml:"check_timeout"`
	SocksPort         int      `yaml:"socks_port"`
	MaxBackoff        string   `yaml:"max_backoff"`
	BackoffMultiplier *float64 `yaml:"backoff_multiplier"`
}

// ApplyTunnelDefaults fills zero-value fields on tunnel with values from
// defaults first, then with built-in defaults for anything still empty.
func ApplyTunnelDefaults(tunnel *Tunnel, defaults Defaults) {
	if tunnel.CheckURL == "" {
		tunnel.CheckURL = defaults.CheckURL
	}
	if tunnel.CheckInterval == "" {
		tunnel.CheckInterval = defaults.CheckInterval
	}
	if tunnel.CheckTimeout == "" {
		tunnel.CheckTimeout = defaults.CheckTimeout
	}
	if tunnel.MaxBackoff == "" {
		tunnel.MaxBackoff = defaults.MaxBackoff
	}
	if tunnel.BackoffMultiplier == nil {
		tunnel.BackoffMultiplier = defaults.BackoffMultiplier
	}
	if tunnel.CheckURL == "" {
		tunnel.CheckURL = metrics.DefaultCheckURL
	}
	if tunnel.CheckInterval == "" {
		tunnel.CheckInterval = metrics.DefaultCheckInterval.String()
	}
	if tunnel.CheckTimeout == "" {
		tunnel.CheckTimeout = metrics.DefaultTimeout.String()
	}
	if tunnel.MaxBackoff == "" {
		tunnel.MaxBackoff = metrics.DefaultMaxBackoff.String()
	}
	if tunnel.BackoffMultiplier == nil {
		m := metrics.DefaultBackoffMult
		tunnel.BackoffMultiplier = &m
	}
}

// LoadConfig reads and validates a YAML configuration file at configPath.
// It applies defaults to every tunnel entry and validates the overall config.
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	// Validate
	if len(config.Tunnels) == 0 && len(config.Subscriptions) == 0 {
		return nil, fmt.Errorf("no tunnels or subscriptions defined in config")
	}

	// Validate subscriptions
	for i, sub := range config.Subscriptions {
		if sub.URL == "" {
			return nil, fmt.Errorf("subscription %d: url is required", i)
		}
		if sub.UpdateInterval == "" {
			config.Subscriptions[i].UpdateInterval = "1h"
		}
		if _, err := time.ParseDuration(config.Subscriptions[i].UpdateInterval); err != nil {
			return nil, fmt.Errorf("subscription %d: invalid update_interval: %v", i, err)
		}
	}

	// Apply defaults to tunnels
	for i := range config.Tunnels {
		tunnel := &config.Tunnels[i]

		hasURL := tunnel.URL != ""
		hasXrayConfig := tunnel.XrayConfigFile != ""

		if hasURL && hasXrayConfig {
			return nil, fmt.Errorf("tunnel %d: url and xray_config_file are mutually exclusive", i)
		}
		if !hasURL && !hasXrayConfig {
			return nil, fmt.Errorf("tunnel %d: url or xray_config_file is required", i)
		}

		ApplyTunnelDefaults(tunnel, config.Defaults)
	}

	return &config, nil
}

// FetchSubscription downloads a subscription URL and returns the list of
// tunnels found in the response. Supports base64-encoded and plain-text
// payloads. Each line is treated as a tunnel URL; the tunnel name is
// extracted from the URL fragment or host.
func FetchSubscription(subURL string) ([]Tunnel, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(subURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
	if err != nil {
		return nil, fmt.Errorf("failed to read subscription response: %v", err)
	}

	content := strings.TrimSpace(string(body))
	if content == "" {
		return nil, nil
	}

	// Try to decode as base64 (with and without padding)
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(content)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(content)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(content)
				if err != nil {
					// Not base64 — use as plain text
					decoded = []byte(content)
				}
			}
		}
	}

	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")

	var tunnels []Tunnel
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		tunnel := Tunnel{URL: line}

		// Extract name from fragment (#name)
		if u, err := url.Parse(line); err == nil && u.Fragment != "" {
			tunnel.Name = u.Fragment
		} else if u != nil {
			// Generate name from host:port
			tunnel.Name = u.Host
		}

		tunnels = append(tunnels, tunnel)
	}

	return tunnels, nil
}

// ResolveSubscriptions fetches all subscription URLs from config, filters to
// supported protocols (VLESS), applies defaults, and returns the combined
// list of tunnels.
func ResolveSubscriptions(config *Config) []Tunnel {
	var allTunnels []Tunnel

	for i, sub := range config.Subscriptions {
		tunnels, err := FetchSubscription(sub.URL)
		if err != nil {
			slog.Error("failed to fetch subscription", "index", i, "url", sub.URL, "error", err)
			continue
		}

		// Filter to only supported protocols (VLESS URLs)
		var supported []Tunnel
		for _, t := range tunnels {
			if strings.HasPrefix(t.URL, "vless://") {
				supported = append(supported, t)
			} else {
				slog.Warn("skipping unsupported URL scheme", "subscription_index", i, "tunnel", t.Name)
			}
		}
		tunnels = supported

		// Apply defaults to each tunnel from subscription
		for j := range tunnels {
			ApplyTunnelDefaults(&tunnels[j], config.Defaults)
		}

		slog.Debug("subscription fetched tunnels", "subscription_index", i, "count", len(tunnels))
		allTunnels = append(allTunnels, tunnels...)
	}

	return allTunnels
}

// Validate checks that a tunnel configuration is structurally valid.
// It performs basic URL and file checks without invoking full VLESS parsing
// (semantic validation happens later in the tunnel package).
func (t *Tunnel) Validate() error {
	var errs []error

	hasURL := t.URL != ""
	hasXrayConfig := t.XrayConfigFile != ""

	if hasURL && hasXrayConfig {
		errs = append(errs, fmt.Errorf("url and xray_config_file are mutually exclusive"))
	}
	if !hasURL && !hasXrayConfig {
		errs = append(errs, fmt.Errorf("url or xray_config_file is required"))
	}

	if hasURL {
		// Structural URL validation only — semantic VLESS parsing happens
		// in the tunnel package at init time.
		if strings.HasPrefix(t.URL, "vless://") {
			if _, err := url.Parse(t.URL); err != nil {
				errs = append(errs, fmt.Errorf("invalid VLESS URL: %v", err))
			}
		} else {
			if _, err := url.Parse(t.URL); err != nil {
				errs = append(errs, fmt.Errorf("invalid URL: %v", err))
			}
		}
	}
	if hasXrayConfig {
		if _, err := os.Stat(t.XrayConfigFile); err != nil {
			errs = append(errs, fmt.Errorf("xray_config_file not accessible: %v", err))
		}
	}

	if _, err := time.ParseDuration(t.CheckInterval); err != nil {
		errs = append(errs, fmt.Errorf("invalid check_interval: %v", err))
	}
	if _, err := time.ParseDuration(t.CheckTimeout); err != nil {
		errs = append(errs, fmt.Errorf("invalid check_timeout: %v", err))
	}
	if u, err := url.Parse(t.CheckURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		errs = append(errs, fmt.Errorf("invalid check_url: must be http or https URL"))
	}
	return errors.Join(errs...)
}

// ValidateTunnels checks that all tunnel configs are valid without starting
// Xray instances. This allows catching errors before stopping existing
// tunnels during reload.
func ValidateTunnels(config *Config) error {
	var errs []error
	seenPorts := make(map[int]string)
	for i, tunnel := range config.Tunnels {
		if err := tunnel.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("tunnel %d (%s): %w", i+1, tunnel.Name, err))
		}
		if tunnel.SocksPort != 0 {
			if tunnel.SocksPort < 1 || tunnel.SocksPort > 65535 {
				errs = append(errs, fmt.Errorf("tunnel %d (%s): socks_port %d is out of valid range [1-65535]", i+1, tunnel.Name, tunnel.SocksPort))
			} else if existing, ok := seenPorts[tunnel.SocksPort]; ok {
				errs = append(errs, fmt.Errorf("tunnel %d (%s): socks_port %d is already used by tunnel %q", i+1, tunnel.Name, tunnel.SocksPort, existing))
			} else {
				seenPorts[tunnel.SocksPort] = tunnel.Name
			}
		}
	}
	return errors.Join(errs...)
}
