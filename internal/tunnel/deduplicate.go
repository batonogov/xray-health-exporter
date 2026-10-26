package tunnel

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/config"
	"github.com/batonogov/xray-health-exporter/internal/metrics"
)

// buildTunnelConfig prepares the same configuration for identity checks and
// startup, without constructing an Xray instance or opening a socket.
func buildTunnelConfig(t *config.Tunnel, port int) ([]byte, *VLESSConfig, MetricLabels, error) {
	var data []byte
	var labels MetricLabels
	var err error
	switch {
	case len(t.XrayConfigJSON) != 0:
		data, labels, err = LoadXrayConfigJSON(t.XrayConfigJSON, port)
	case t.XrayConfigFile != "":
		data, labels, err = LoadXrayConfigFile(t.XrayConfigFile, port)
	case !strings.HasPrefix(t.URL, "vless://"):
		data, labels, err = CreateShareLinkConfig(t.URL, port)
	default:
		vless, err := ParseVLESSURL(t.URL)
		if err != nil {
			return nil, nil, labels, fmt.Errorf("failed to parse VLESS URL: %w", err)
		}
		labels = MetricLabels{Server: net.JoinHostPort(vless.Address, strconv.Itoa(vless.Port)), Security: vless.Security, SNI: vless.SNI}
		data, err = CreateXrayConfig(vless, port)
		return data, vless, labels, err
	}
	return data, nil, labels, err
}

type tunnelDescription struct {
	tunnel    config.Tunnel
	labels    MetricLabels
	route     string // Hash of effective transport, credentials, routing, and checks.
	generated bool
	index     int
}

func describeTunnel(t config.Tunnel) (tunnelDescription, error) {
	// Work on a value copy. Source caches keep their original accepted responses.
	config.ApplyTunnelDefaults(&t, config.Defaults{})
	if t.XrayConfigFile != "" {
		data, err := os.ReadFile(t.XrayConfigFile)
		if err != nil {
			return tunnelDescription{}, fmt.Errorf("cannot read native Xray configuration")
		}
		// Freeze the exact bytes that will be fingerprinted and eventually started.
		t.XrayConfigFile = ""
		t.XrayConfigJSON = data
	}
	data, _, labels, err := buildTunnelConfig(&t, metrics.DefaultSocksPort)
	if err != nil {
		return tunnelDescription{}, fmt.Errorf("cannot prepare tunnel configuration")
	}
	var native map[string]json.RawMessage
	if err := json.Unmarshal(data, &native); err != nil {
		return tunnelDescription{}, fmt.Errorf("cannot normalize tunnel configuration")
	}
	// These display-only keys do not affect the Xray route. Exporter-controlled
	// log and inbound settings have already been replaced by buildTunnelConfig.
	delete(native, "remarks")
	delete(native, "name")
	canonical, err := json.Marshal(native)
	if err != nil {
		return tunnelDescription{}, err
	}
	// Marshal through interface values to canonicalize object key ordering inside
	// raw native JSON too. UseNumber preserves JSON number precision.
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(canonical)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return tunnelDescription{}, err
	}
	canonical, err = json.Marshal(value)
	if err != nil {
		return tunnelDescription{}, err
	}
	checks := t
	checks.Name = ""
	checks.NameGenerated = false
	checks.URL = ""
	checks.XrayConfigFile = ""
	checks.XrayConfigJSON = canonical
	checks.SocksPort = 0
	// Equal Go durations should not create duplicate checks (e.g. 60s and 1m).
	for _, duration := range []*string{&checks.CheckInterval, &checks.CheckTimeout, &checks.MaxBackoff, &checks.DownloadTimeout} {
		parsed, err := time.ParseDuration(*duration)
		if err != nil {
			return tunnelDescription{}, fmt.Errorf("invalid probe duration")
		}
		*duration = parsed.String()
	}
	encoded, err := json.Marshal(struct {
		Checks config.Tunnel
		Labels MetricLabels
	}{checks, labels})
	if err != nil {
		return tunnelDescription{}, fmt.Errorf("cannot normalize probe settings")
	}
	route := fmt.Sprintf("%x", sha256.Sum256(encoded))
	generated := t.Name == "" || t.NameGenerated
	if generated {
		t.Name = labels.Server
		if t.Name == "" {
			t.Name = "tunnel-" + route[:12]
		}
		t.NameGenerated = true
	}
	return tunnelDescription{tunnel: t, labels: labels, route: route, generated: generated}, nil
}

// prepareTunnelConfig deduplicates only equivalent monitors and rejects label
// collisions before any core is started. Different explicit names deliberately
// request separate monitors, even when they reach the same endpoint.
func prepareTunnelConfig(cfg *config.Config) error {
	var unique []tunnelDescription
	routes := make(map[string][]int)
	for i, t := range cfg.Tunnels {
		// Validate individual inputs before deduplication; repeated explicit ports
		// are validated after identical definitions have been merged.
		if err := t.Validate(); err != nil {
			return fmt.Errorf("tunnel %d has invalid configuration", i+1)
		}
		if t.SocksPort < 0 || t.SocksPort > 65535 {
			return fmt.Errorf("tunnel %d has invalid socks_port", i+1)
		}
		description, err := describeTunnel(t)
		if err != nil {
			return fmt.Errorf("tunnel %d: %w", i+1, err)
		}
		description.index = i + 1
		merged := false
		for _, position := range routes[description.route] {
			previous := &unique[position]
			if previous.tunnel.Name != description.tunnel.Name && !previous.generated && !description.generated {
				continue
			}
			a, b := previous.tunnel.SocksPort, description.tunnel.SocksPort
			if a != 0 && b != 0 && a != b {
				return fmt.Errorf("tunnels %d and %d duplicate a monitor with different explicit SOCKS ports; use distinct names", previous.index, i+1)
			}
			if previous.generated && !description.generated {
				previous.tunnel.Name = description.tunnel.Name
				previous.tunnel.NameGenerated = false
				previous.generated = false
			}
			if a == 0 {
				previous.tunnel.SocksPort = b
			}
			merged = true
			break
		}
		if !merged {
			routes[description.route] = append(routes[description.route], len(unique))
			unique = append(unique, description)
		}
	}
	labels := make(map[[4]string]int)
	normalized := make([]config.Tunnel, 0, len(unique))
	for _, description := range unique {
		key := [4]string{description.tunnel.Name, description.labels.Server, description.labels.Security, description.labels.SNI}
		if previous, exists := labels[key]; exists {
			return fmt.Errorf("tunnels %d and %d share Prometheus labels but have different connection or check settings; assign distinct names", previous, description.index)
		}
		labels[key] = description.index
		normalized = append(normalized, description.tunnel)
	}
	candidate := *cfg
	candidate.Tunnels = normalized
	if err := config.ValidateTunnels(&candidate); err != nil {
		return fmt.Errorf("deduplicated tunnels have conflicting SOCKS ports or invalid configuration")
	}
	cfg.Tunnels = normalized
	return nil
}
