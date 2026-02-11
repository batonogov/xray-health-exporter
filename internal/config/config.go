package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultListenAddr    = ":9273"
	DefaultCheckURL      = "https://www.google.com"
	DefaultTimeout       = 30 * time.Second
	DefaultSocksPort     = 1080
	DefaultCheckInterval = 30 * time.Second
	DefaultConfigFile    = "/app/config.yaml"
)

type Config struct {
	Defaults      Defaults `yaml:"defaults"`
	Tunnels       []Tunnel `yaml:"tunnels"`
	SocksBasePort int      `yaml:"socks_base_port"`
}

type Defaults struct {
	CheckURL      string `yaml:"check_url"`
	CheckInterval string `yaml:"check_interval"`
	CheckTimeout  string `yaml:"check_timeout"`
}

type Tunnel struct {
	Name          string `yaml:"name"`
	URL           string `yaml:"url"`
	CheckURL      string `yaml:"check_url"`
	CheckInterval string `yaml:"check_interval"`
	CheckTimeout  string `yaml:"check_timeout"`
}

// Load reads and parses the configuration file, applying defaults.
func Load(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath) //nolint:gosec // configPath is from env/flag, not user input
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if len(config.Tunnels) == 0 {
		return nil, fmt.Errorf("no tunnels defined in config")
	}

	if config.SocksBasePort == 0 {
		config.SocksBasePort = DefaultSocksPort
	}

	for i := range config.Tunnels {
		tunnel := &config.Tunnels[i]

		if tunnel.URL == "" {
			return nil, fmt.Errorf("tunnel %d: url is required", i)
		}

		if tunnel.CheckURL == "" {
			tunnel.CheckURL = config.Defaults.CheckURL
		}
		if tunnel.CheckInterval == "" {
			tunnel.CheckInterval = config.Defaults.CheckInterval
		}
		if tunnel.CheckTimeout == "" {
			tunnel.CheckTimeout = config.Defaults.CheckTimeout
		}

		if tunnel.CheckURL == "" {
			tunnel.CheckURL = DefaultCheckURL
		}
		if tunnel.CheckInterval == "" {
			tunnel.CheckInterval = DefaultCheckInterval.String()
		}
		if tunnel.CheckTimeout == "" {
			tunnel.CheckTimeout = DefaultTimeout.String()
		}
	}

	return &config, nil
}

// Validate parses all VLESS URLs and durations without side-effects.
func (c *Config) Validate() error {
	for i, tunnel := range c.Tunnels {
		if !strings.HasPrefix(tunnel.URL, "vless://") {
			return fmt.Errorf("tunnel %d (%s): invalid vless URL", i, tunnel.Name)
		}

		u, err := url.Parse(tunnel.URL)
		if err != nil {
			return fmt.Errorf("tunnel %d (%s): invalid URL: %w", i, tunnel.Name, err)
		}

		if _, err := strconv.Atoi(u.Port()); err != nil {
			return fmt.Errorf("tunnel %d (%s): invalid port: %w", i, tunnel.Name, err)
		}

		if _, err := time.ParseDuration(tunnel.CheckInterval); err != nil {
			return fmt.Errorf("tunnel %d (%s): invalid check_interval: %w", i, tunnel.Name, err)
		}

		if _, err := time.ParseDuration(tunnel.CheckTimeout); err != nil {
			return fmt.Errorf("tunnel %d (%s): invalid check_timeout: %w", i, tunnel.Name, err)
		}
	}

	return nil
}
