// Package config provides configuration types, loading, validation, and
// subscription resolution for xray-health-exporter.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
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
	CheckMethod       string   `yaml:"check_method"`
	IPCheckURL        string   `yaml:"ip_check_url"`
	DownloadURL       string   `yaml:"download_url"`
	DownloadTimeout   string   `yaml:"download_timeout"`
	DownloadMinSize   int64    `yaml:"download_min_size"`
}

// Subscription describes a remote subscription URL that provides tunnel entries.
type Subscription struct {
	Name           string            `yaml:"name"`
	URL            string            `yaml:"url"`
	UpdateInterval string            `yaml:"update_interval"`
	Headers        map[string]string `yaml:"headers"`
	UserAgent      string            `yaml:"user_agent"`
	Timeout        string            `yaml:"timeout"`
	Format         string            `yaml:"format"`
}

// Tunnel describes a single tunnel configuration.
type Tunnel struct {
	Name              string          `yaml:"name"`
	URL               string          `yaml:"url"`
	XrayConfigFile    string          `yaml:"xray_config_file"`
	XrayConfigJSON    json.RawMessage `yaml:"-"`
	CheckURL          string          `yaml:"check_url"`
	CheckInterval     string          `yaml:"check_interval"`
	CheckTimeout      string          `yaml:"check_timeout"`
	SocksPort         int             `yaml:"socks_port"`
	MaxBackoff        string          `yaml:"max_backoff"`
	BackoffMultiplier *float64        `yaml:"backoff_multiplier"`
	CheckMethod       string          `yaml:"check_method"`
	IPCheckURL        string          `yaml:"ip_check_url"`
	DownloadURL       string          `yaml:"download_url"`
	DownloadTimeout   string          `yaml:"download_timeout"`
	DownloadMinSize   int64           `yaml:"download_min_size"`
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
	if tunnel.CheckMethod == "" {
		tunnel.CheckMethod = defaults.CheckMethod
	}
	if tunnel.IPCheckURL == "" {
		tunnel.IPCheckURL = defaults.IPCheckURL
	}
	if tunnel.DownloadURL == "" {
		tunnel.DownloadURL = defaults.DownloadURL
	}
	if tunnel.DownloadTimeout == "" {
		tunnel.DownloadTimeout = defaults.DownloadTimeout
	}
	if tunnel.DownloadMinSize == 0 {
		tunnel.DownloadMinSize = defaults.DownloadMinSize
	}

	// Built-in defaults (lowest priority).
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
	if tunnel.CheckMethod == "" {
		tunnel.CheckMethod = metrics.DefaultCheckMethod
	}
	if tunnel.IPCheckURL == "" {
		tunnel.IPCheckURL = metrics.DefaultIPCheckURL
	}
	if tunnel.DownloadURL == "" {
		tunnel.DownloadURL = metrics.DefaultDownloadURL
	}
	if tunnel.DownloadTimeout == "" {
		tunnel.DownloadTimeout = metrics.DefaultDownloadTimeout.String()
	}
	if tunnel.DownloadMinSize == 0 {
		tunnel.DownloadMinSize = metrics.DefaultDownloadMinSize
	}
}

// ApplyEnvDefaults fills empty fields on defaults from environment variables.
// This provides a secondary source of defaults between YAML and built-in
// constants: YAML `defaults:` take priority, then env vars, then built-ins.
func ApplyEnvDefaults(d *Defaults) {
	if d.CheckMethod == "" {
		d.CheckMethod = os.Getenv("CHECK_METHOD")
	}
	if d.IPCheckURL == "" {
		d.IPCheckURL = os.Getenv("IP_CHECK_URL")
	}
	if d.DownloadURL == "" {
		d.DownloadURL = os.Getenv("DOWNLOAD_URL")
	}
	if d.DownloadTimeout == "" {
		d.DownloadTimeout = os.Getenv("DOWNLOAD_TIMEOUT")
	}
	if d.DownloadMinSize == 0 {
		if v := os.Getenv("DOWNLOAD_MIN_SIZE"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				d.DownloadMinSize = n
			}
		}
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

	// Apply environment variable overrides to defaults (secondary to YAML).
	ApplyEnvDefaults(&config.Defaults)

	// Validate
	if len(config.Tunnels) == 0 && len(config.Subscriptions) == 0 {
		return nil, fmt.Errorf("no tunnels or subscriptions defined in config")
	}

	// Validate subscriptions before any network requests.
	subscriptionNames := make(map[string]bool)
	for i := range config.Subscriptions {
		sub := &config.Subscriptions[i]
		if sub.UpdateInterval == "" {
			sub.UpdateInterval = "1h"
		}
		name := sub.Name
		if name == "" {
			name = fmt.Sprintf("subscription-%d", i+1)
		}
		if subscriptionNames[name] {
			return nil, fmt.Errorf("duplicate subscription name at index %d", i)
		}
		subscriptionNames[name] = true
		// Persist the effective name so cache and scheduling identities distinguish
		// unnamed sources even when their URL and request options are identical.
		sub.Name = name
		if err := validateSubscription(*sub); err != nil {
			return nil, fmt.Errorf("subscription %d: %w", i, err)
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

// Validate checks that a tunnel configuration is structurally valid.
// It performs basic URL and file checks without invoking full share-link parsing
// (semantic validation happens later in the tunnel package).
func (t *Tunnel) Validate() error {
	var errs []error

	hasURL := t.URL != ""
	hasXrayConfig := t.XrayConfigFile != "" || len(t.XrayConfigJSON) != 0

	if hasURL && hasXrayConfig {
		errs = append(errs, fmt.Errorf("url and xray_config_file are mutually exclusive"))
	}
	if !hasURL && !hasXrayConfig {
		errs = append(errs, fmt.Errorf("url or xray_config_file is required"))
	}

	if hasURL {
		// Structural URL validation only — semantic share-link parsing happens
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
	if t.XrayConfigFile != "" {
		if _, err := os.Stat(t.XrayConfigFile); err != nil {
			errs = append(errs, fmt.Errorf("xray_config_file not accessible: %v", err))
		}
	}

	if len(t.XrayConfigJSON) != 0 {
		if t.XrayConfigFile != "" {
			errs = append(errs, errors.New("xray_config_file and inline Xray config are mutually exclusive"))
		}
		if _, err := parseXraySubscription(t.XrayConfigJSON); err != nil {
			errs = append(errs, err)
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

	// Validate check_method if explicitly set.
	if t.CheckMethod != "" {
		switch t.CheckMethod {
		case "ip", "http", "download":
			// valid
		default:
			errs = append(errs, fmt.Errorf("invalid check_method %q: must be one of ip, http, download", t.CheckMethod))
		}
	}

	// Validate download_timeout if explicitly set.
	if t.DownloadTimeout != "" {
		if _, err := time.ParseDuration(t.DownloadTimeout); err != nil {
			errs = append(errs, fmt.Errorf("invalid download_timeout: %v", err))
		}
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
