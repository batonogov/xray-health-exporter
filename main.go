package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	_ "github.com/xtls/xray-core/main/distro/all"
)

const (
	defaultListenAddr    = ":9273"
	defaultCheckURL      = "https://www.google.com"
	defaultTimeout       = 30 * time.Second
	defaultSocksPort     = 1080
	defaultCheckInterval = 30 * time.Second
	defaultConfigFile    = "/app/config.yaml"
	socksDialTimeout     = 5 * time.Second
	socksStartupTimeout  = 10 * time.Second
)

// Version is set at build time via -ldflags="-X main.Version=..."
var Version = "dev"

var (
	tunnelUp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_tunnel_up",
			Help: "1 if tunnel is working, 0 otherwise",
		},
		[]string{"name", "server", "security", "sni"},
	)

	tunnelLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_tunnel_latency_seconds",
			Help: "Latency of the tunnel check in seconds",
		},
		[]string{"name", "server", "security", "sni"},
	)

	tunnelCheckTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xray_tunnel_check_total",
			Help: "Total number of tunnel checks by result",
		},
		[]string{"name", "server", "security", "sni", "result"},
	)

	tunnelLastSuccess = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_tunnel_last_success_timestamp",
			Help: "Timestamp of last successful tunnel check",
		},
		[]string{"name", "server", "security", "sni"},
	)

	tunnelHTTPStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "xray_tunnel_http_status",
			Help: "HTTP status code from tunnel check",
		},
		[]string{"name", "server", "security", "sni"},
	)

	tunnelErrorTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "xray_tunnel_error_total",
			Help: "Total number of tunnel errors categorized by reason",
		},
		[]string{"name", "server", "security", "sni", "reason"},
	)

	exporterLeader = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "xray_exporter_leader",
			Help: "1 if this exporter instance is actively probing tunnels (leader, or leader election disabled), 0 otherwise",
		},
	)
)

func init() {
	prometheus.MustRegister(tunnelUp)
	prometheus.MustRegister(tunnelLatency)
	prometheus.MustRegister(tunnelCheckTotal)
	prometheus.MustRegister(tunnelLastSuccess)
	prometheus.MustRegister(tunnelHTTPStatus)
	prometheus.MustRegister(tunnelErrorTotal)
	prometheus.MustRegister(exporterLeader)
}

// Config structures
type Config struct {
	Defaults      Defaults       `yaml:"defaults"`
	Tunnels       []Tunnel       `yaml:"tunnels"`
	Subscriptions []Subscription `yaml:"subscriptions"`
}

type Defaults struct {
	CheckURL      string `yaml:"check_url"`
	CheckInterval string `yaml:"check_interval"`
	CheckTimeout  string `yaml:"check_timeout"`
}

type Subscription struct {
	URL            string `yaml:"url"`
	UpdateInterval string `yaml:"update_interval"`
}

type Tunnel struct {
	Name           string `yaml:"name"`
	URL            string `yaml:"url"`
	XrayConfigFile string `yaml:"xray_config_file"`
	CheckURL       string `yaml:"check_url"`
	CheckInterval  string `yaml:"check_interval"`
	CheckTimeout   string `yaml:"check_timeout"`
}

type VLESSConfig struct {
	UUID        string
	Address     string
	Port        int
	Security    string
	PBK         string
	SNI         string
	FP          string
	SID         string
	SPX         string
	Type        string
	ServiceName string
	Authority   string
	MultiMode   bool
	Host        string
	Path        string
}

// MetricLabels holds protocol-agnostic labels for Prometheus metrics.
// Populated from VLESSConfig for VLESS tunnels; will be populated
// from xray_config_file metadata for raw-config tunnels.
type MetricLabels struct {
	Server   string
	Security string
	SNI      string
}

type TunnelInstance struct {
	Name          string
	VLESSConfig   *VLESSConfig // nil for xray_config_file tunnels
	MetricLabels  MetricLabels
	XrayInstance  *core.Instance
	SocksPort     int
	CheckURL      string
	CheckInterval time.Duration
	CheckTimeout  time.Duration
	cancelFunc    context.CancelFunc
}

// TunnelManager manages tunnel instances with thread-safe access
type TunnelManager struct {
	mu            sync.RWMutex
	instances     []*TunnelInstance
	nextSocksPort int
	config        *Config
}

func applyTunnelDefaults(tunnel *Tunnel, defaults Defaults) {
	if tunnel.CheckURL == "" {
		tunnel.CheckURL = defaults.CheckURL
	}
	if tunnel.CheckInterval == "" {
		tunnel.CheckInterval = defaults.CheckInterval
	}
	if tunnel.CheckTimeout == "" {
		tunnel.CheckTimeout = defaults.CheckTimeout
	}
	if tunnel.CheckURL == "" {
		tunnel.CheckURL = defaultCheckURL
	}
	if tunnel.CheckInterval == "" {
		tunnel.CheckInterval = defaultCheckInterval.String()
	}
	if tunnel.CheckTimeout == "" {
		tunnel.CheckTimeout = defaultTimeout.String()
	}
}

func loadConfig(configPath string) (*Config, error) {
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

		applyTunnelDefaults(tunnel, config.Defaults)
	}

	return &config, nil
}

func fetchSubscription(subURL string) ([]Tunnel, error) {
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

func resolveSubscriptions(config *Config) []Tunnel {
	var allTunnels []Tunnel

	for i, sub := range config.Subscriptions {
		tunnels, err := fetchSubscription(sub.URL)
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
			applyTunnelDefaults(&tunnels[j], config.Defaults)
		}

		slog.Debug("subscription fetched tunnels", "subscription_index", i, "count", len(tunnels))
		allTunnels = append(allTunnels, tunnels...)
	}

	return allTunnels
}

func parseVLESSURL(vlessURL string) (*VLESSConfig, error) {
	if !strings.HasPrefix(vlessURL, "vless://") {
		return nil, fmt.Errorf("invalid vless URL")
	}

	u, err := url.Parse(vlessURL)
	if err != nil {
		return nil, err
	}

	config := &VLESSConfig{
		UUID:    u.User.Username(),
		Address: u.Hostname(),
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}
	config.Port = port

	query := u.Query()
	config.Type = query.Get("type")
	config.Security = query.Get("security")
	config.PBK = query.Get("pbk")
	config.SNI = query.Get("sni")
	config.FP = query.Get("fp")
	config.SID = query.Get("sid")
	config.SPX = query.Get("spx")
	config.ServiceName = query.Get("serviceName")
	config.Authority = query.Get("authority")
	config.MultiMode = query.Get("multiMode") == "true"
	config.Host = query.Get("host")
	config.Path = query.Get("path")

	if config.Type == "grpc" && config.ServiceName == "" {
		return nil, fmt.Errorf("serviceName is required for grpc transport")
	}

	return config, nil
}

func createXrayConfig(vlessConfig *VLESSConfig, socksPort int) ([]byte, error) {
	logLevel := os.Getenv("XRAY_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "warning"
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": logLevel,
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     socksPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []map[string]interface{}{
						{
							"address": vlessConfig.Address,
							"port":    vlessConfig.Port,
							"users": []map[string]interface{}{
								{
									"id":         vlessConfig.UUID,
									"encryption": "none",
								},
							},
						},
					},
				},
				"streamSettings": createStreamSettings(vlessConfig),
			},
		},
	}

	return json.MarshalIndent(config, "", "  ")
}

func createStreamSettings(vlessConfig *VLESSConfig) map[string]interface{} {
	streamSettings := map[string]interface{}{
		"network": vlessConfig.Type,
	}

	// Add tcpSettings for TCP transport
	if vlessConfig.Type == "tcp" {
		streamSettings["tcpSettings"] = map[string]interface{}{
			"header": map[string]interface{}{
				"type": "none",
			},
		}
	}

	// Add grpcSettings for gRPC transport
	if vlessConfig.Type == "grpc" {
		grpcSettings := map[string]interface{}{
			"serviceName": vlessConfig.ServiceName,
		}
		if vlessConfig.Authority != "" {
			grpcSettings["authority"] = vlessConfig.Authority
		} else if vlessConfig.SNI != "" {
			grpcSettings["authority"] = vlessConfig.SNI
		} else if vlessConfig.Address != "" {
			grpcSettings["authority"] = vlessConfig.Address
		}
		if vlessConfig.MultiMode {
			grpcSettings["multiMode"] = true
		}
		streamSettings["grpcSettings"] = grpcSettings
	}

	// Add wsSettings for WebSocket transport
	if vlessConfig.Type == "ws" {
		wsSettings := map[string]interface{}{}
		if vlessConfig.Path != "" {
			wsSettings["path"] = vlessConfig.Path
		}
		if vlessConfig.Host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": vlessConfig.Host,
			}
		}
		streamSettings["wsSettings"] = wsSettings
	}

	if vlessConfig.Security == "reality" {
		streamSettings["security"] = "reality"

		realitySettings := map[string]interface{}{
			"show":        false,
			"fingerprint": vlessConfig.FP,
			"serverName":  vlessConfig.SNI,
			"publicKey":   vlessConfig.PBK,
		}

		// ShortId может быть пустым или массивом
		if vlessConfig.SID != "" {
			realitySettings["shortId"] = vlessConfig.SID
		}

		// SpiderX - путь для маскировки
		if vlessConfig.SPX != "" {
			realitySettings["spiderX"] = vlessConfig.SPX
		}

		streamSettings["realitySettings"] = realitySettings
	} else if vlessConfig.Security == "tls" {
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName":    vlessConfig.SNI,
			"allowInsecure": false,
			"fingerprint":   vlessConfig.FP,
		}
	}

	return streamSettings
}

func startXray(configJSON []byte) (*core.Instance, error) {
	// Парсим JSON в conf.Config структуру
	var config conf.Config
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	// Конвертируем в protobuf конфигурацию
	pbConfig, err := config.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build config: %v", err)
	}

	// Создаем и запускаем инстанс
	instance, err := core.New(pbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create xray instance: %v", err)
	}

	if err := instance.Start(); err != nil {
		return nil, fmt.Errorf("failed to start xray: %v", err)
	}

	return instance, nil
}

func loadXrayConfigFile(path string, socksPort int) ([]byte, MetricLabels, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, MetricLabels{}, fmt.Errorf("failed to read xray config file: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, MetricLabels{}, fmt.Errorf("failed to parse xray config JSON: %v", err)
	}

	labels := extractMetricLabelsFromXrayConfig(raw)

	logLevel := os.Getenv("XRAY_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "warning"
	}

	// Inject log and SOCKS5 inbound, keep user's outbounds
	raw["log"] = map[string]interface{}{
		"loglevel": logLevel,
	}
	raw["inbounds"] = []map[string]interface{}{
		{
			"port":     socksPort,
			"listen":   "127.0.0.1",
			"protocol": "socks",
			"settings": map[string]interface{}{
				"auth": "noauth",
				"udp":  true,
			},
		},
	}

	result, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, MetricLabels{}, fmt.Errorf("failed to marshal xray config: %v", err)
	}

	return result, labels, nil
}

func extractMetricLabelsFromXrayConfig(raw map[string]interface{}) MetricLabels {
	labels := MetricLabels{}

	outbounds, ok := raw["outbounds"].([]interface{})
	if !ok || len(outbounds) == 0 {
		return labels
	}

	ob, ok := outbounds[0].(map[string]interface{})
	if !ok {
		return labels
	}

	// Try to extract server address from settings
	if settings, ok := ob["settings"].(map[string]interface{}); ok {
		// VLESS/VMess: vnext[0].address:port
		if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if server, ok := vnext[0].(map[string]interface{}); ok {
				addr, _ := server["address"].(string)
				port, _ := server["port"].(float64)
				if addr != "" && port > 0 {
					labels.Server = fmt.Sprintf("%s:%d", addr, int(port))
				}
			}
		}
		// Trojan/Shadowsocks: servers[0].address:port
		if labels.Server == "" {
			if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
				if server, ok := servers[0].(map[string]interface{}); ok {
					addr, _ := server["address"].(string)
					port, _ := server["port"].(float64)
					if addr != "" && port > 0 {
						labels.Server = fmt.Sprintf("%s:%d", addr, int(port))
					}
				}
			}
		}
	}

	// Extract security and SNI from streamSettings
	if ss, ok := ob["streamSettings"].(map[string]interface{}); ok {
		if sec, ok := ss["security"].(string); ok {
			labels.Security = sec
		}
		if rs, ok := ss["realitySettings"].(map[string]interface{}); ok {
			if sni, ok := rs["serverName"].(string); ok {
				labels.SNI = sni
			}
		}
		if ts, ok := ss["tlsSettings"].(map[string]interface{}); ok {
			if sni, ok := ts["serverName"].(string); ok {
				labels.SNI = sni
			}
		}
	}

	return labels
}

func initTunnel(tunnel *Tunnel, socksPort int) (*TunnelInstance, error) {
	checkInterval, err := time.ParseDuration(tunnel.CheckInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid check_interval: %v", err)
	}

	checkTimeout, err := time.ParseDuration(tunnel.CheckTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid check_timeout: %v", err)
	}

	var xrayConfigJSON []byte
	var vlessConfig *VLESSConfig
	var metricLabels MetricLabels

	if tunnel.XrayConfigFile != "" {
		// xray_config_file mode
		xrayConfigJSON, metricLabels, err = loadXrayConfigFile(tunnel.XrayConfigFile, socksPort)
		if err != nil {
			return nil, fmt.Errorf("failed to load xray config file: %v", err)
		}
	} else {
		// VLESS URL mode
		vlessConfig, err = parseVLESSURL(tunnel.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VLESS URL: %v", err)
		}

		metricLabels = MetricLabels{
			Server:   fmt.Sprintf("%s:%d", vlessConfig.Address, vlessConfig.Port),
			Security: vlessConfig.Security,
			SNI:      vlessConfig.SNI,
		}

		xrayConfigJSON, err = createXrayConfig(vlessConfig, socksPort)
		if err != nil {
			return nil, fmt.Errorf("failed to create Xray config: %v", err)
		}
	}

	slog.Debug("xray config", "tunnel", tunnel.Name, "config", slog.String("config_json", string(xrayConfigJSON)))

	xrayInstance, err := startXray(xrayConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to start Xray: %v", err)
	}

	name := tunnel.Name
	if name == "" {
		if metricLabels.Server != "" {
			name = metricLabels.Server
		} else {
			name = fmt.Sprintf("tunnel-port-%d", socksPort)
		}
	}

	return &TunnelInstance{
		Name:          name,
		VLESSConfig:   vlessConfig,
		MetricLabels:  metricLabels,
		XrayInstance:  xrayInstance,
		SocksPort:     socksPort,
		CheckURL:      tunnel.CheckURL,
		CheckInterval: checkInterval,
		CheckTimeout:  checkTimeout,
	}, nil
}

// SOCKS5 dialer
type socks5Dialer struct {
	proxyAddr string
	timeout   time.Duration
}

func newSOCKS5Dialer(proxyAddr string, timeout time.Duration) *socks5Dialer {
	return &socks5Dialer{
		proxyAddr: proxyAddr,
		timeout:   timeout,
	}
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Подключаемся к SOCKS5 прокси
	conn, err := net.DialTimeout("tcp", d.proxyAddr, d.timeout)
	if err != nil {
		return nil, err
	}

	// SOCKS5 handshake: [VER, NMETHODS, METHODS]
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}

	// Читаем ответ: [VER, METHOD]
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		conn.Close()
		return nil, err
	}

	if buf[0] != 5 || buf[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed")
	}

	// Парсим адрес
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Отправляем CONNECT запрос
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Читаем ответ
	resp := make([]byte, 4)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: %d", resp[1])
	}

	// Читаем оставшуюся часть ответа (адрес и порт)
	switch resp[3] {
	case 1: // IPv4
		if _, err := conn.Read(make([]byte, 4+2)); err != nil {
			conn.Close()
			return nil, err
		}
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := conn.Read(lenBuf); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := conn.Read(make([]byte, int(lenBuf[0])+2)); err != nil {
			conn.Close()
			return nil, err
		}
	case 4: // IPv6
		if _, err := conn.Read(make([]byte, 16+2)); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

// classifyError determines the category of an error for the xray_tunnel_error_total metric.
func classifyError(err error) string {
	if err == nil {
		return "unknown"
	}

	msg := err.Error()

	// Timeout errors
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "context deadline") {
		return "timeout"
	}
	if strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "request canceled") {
		return "timeout"
	}

	// TLS errors
	if strings.Contains(msg, "tls:") || strings.Contains(msg, "TLS:") ||
		strings.Contains(msg, "certificate") || strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "handshake failure") {
		return "tls"
	}

	// DNS errors
	if strings.Contains(msg, "lookup ") || strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "dns:") || strings.Contains(msg, "name resolution") ||
		strings.Contains(msg, "Name or service not known") {
		return "dns"
	}

	// Connection refused
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "Connection refused") {
		return "connection_refused"
	}

	// SOCKS5 proxy errors
	if strings.Contains(msg, "SOCKS5") || strings.Contains(msg, "socks5") ||
		strings.Contains(msg, "SOCKS") {
		return "socks_error"
	}

	return "unknown"
}

func checkTunnel(ti *TunnelInstance) {
	start := time.Now()

	// Labels для метрик
	labels := prometheus.Labels{
		"name":     ti.Name,
		"server":   ti.MetricLabels.Server,
		"security": ti.MetricLabels.Security,
		"sni":      ti.MetricLabels.SNI,
	}

	resultLabels := func(result string) prometheus.Labels {
		return prometheus.Labels{
			"name":     ti.Name,
			"server":   ti.MetricLabels.Server,
			"security": ti.MetricLabels.Security,
			"sni":      ti.MetricLabels.SNI,
			"result":   result,
		}
	}

	errorLabels := func(reason string) prometheus.Labels {
		return prometheus.Labels{
			"name":     ti.Name,
			"server":   ti.MetricLabels.Server,
			"security": ti.MetricLabels.Security,
			"sni":      ti.MetricLabels.SNI,
			"reason":   reason,
		}
	}

	socksProxy := fmt.Sprintf("127.0.0.1:%d", ti.SocksPort)

	// Сначала проверим что SOCKS5 прокси вообще работает
	conn, err := net.DialTimeout("tcp", socksProxy, min(socksDialTimeout, ti.CheckTimeout))
	if err != nil {
		slog.Error("tunnel DOWN", "tunnel", ti.Name, "error", err)
		tunnelUp.With(labels).Set(0)
		tunnelCheckTotal.With(resultLabels("failure")).Inc()
		tunnelErrorTotal.With(errorLabels(classifyError(err))).Inc()
		return
	}
	conn.Close()

	dialer := newSOCKS5Dialer(socksProxy, ti.CheckTimeout)

	client := &http.Client{
		Timeout: ti.CheckTimeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get(ti.CheckURL)
	if err != nil {
		slog.Error("tunnel DOWN", "tunnel", ti.Name, "error", err)
		tunnelUp.With(labels).Set(0)
		tunnelCheckTotal.With(resultLabels("failure")).Inc()
		tunnelErrorTotal.With(errorLabels(classifyError(err))).Inc()
		return
	}
	defer resp.Body.Close()

	// Сохраняем HTTP статус
	tunnelHTTPStatus.With(labels).Set(float64(resp.StatusCode))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusTemporaryRedirect {
		slog.Error("tunnel DOWN", "tunnel", ti.Name, "status_code", resp.StatusCode)
		tunnelUp.With(labels).Set(0)
		tunnelCheckTotal.With(resultLabels("failure")).Inc()
		tunnelErrorTotal.With(errorLabels("bad_status")).Inc()
		return
	}

	// Читаем немного тела ответа чтобы убедиться что соединение работает.
	// Полный drain не нужен: транспорт использует DisableKeepAlives: true,
	// поэтому соединение не переиспользуется и будет закрыто вместе с resp.Body.
	_, bodyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if bodyErr != nil {
		slog.Warn("failed to read response body", "tunnel", ti.Name, "error", bodyErr)
	}

	duration := time.Since(start)
	slog.Info("tunnel UP", "tunnel", ti.Name, "latency", duration.Round(time.Millisecond))
	tunnelUp.With(labels).Set(1)
	// Latency обновляем только при успешном чтении body,
	// иначе замер duration может быть неточным.
	if bodyErr == nil {
		tunnelLatency.With(labels).Set(duration.Seconds())
	}
	tunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
	tunnelCheckTotal.With(resultLabels("success")).Inc()
}

func runTunnelChecker(ctx context.Context, ti *TunnelInstance) {
	// Jitter на первую проверку — защита от thundering herd
	jitter := time.Duration(rand.Int64N(int64(ti.CheckInterval)))
	slog.Debug("staggering initial check", "tunnel", ti.Name, "jitter", jitter)
	timer := time.NewTimer(jitter)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return
	}

	checkTunnel(ti)

	ticker := time.NewTicker(ti.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkTunnel(ti)
		}
	}
}

// waitForSOCKSPort polls the SOCKS port until it accepts connections or the timeout expires.
func waitForSOCKSPort(port int, timeout time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready after %v", port, timeout)
}

// Validate checks that a tunnel configuration is valid without starting an Xray instance.
// It collects all validation errors and returns them joined together.
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
		if strings.HasPrefix(t.URL, "vless://") {
			if _, err := parseVLESSURL(t.URL); err != nil {
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

// validateTunnels checks that all tunnel configs are valid without starting Xray instances.
// This allows catching errors before stopping existing tunnels during reload.
func validateTunnels(config *Config) error {
	var errs []error
	for i, tunnel := range config.Tunnels {
		if err := tunnel.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("tunnel %d (%s): %w", i+1, tunnel.Name, err))
		}
	}
	return errors.Join(errs...)
}

// initializeTunnels creates and starts all tunnel instances from config
func initializeTunnels(config *Config, baseSocksPort int) ([]*TunnelInstance, error) {
	if len(config.Tunnels) == 0 {
		return nil, fmt.Errorf("no tunnels to initialize")
	}

	var tunnelInstances []*TunnelInstance

	for i, tunnel := range config.Tunnels {
		socksPort := baseSocksPort + i

		slog.Debug("initializing tunnel", "index", i+1, "tunnel", tunnel.Name, "socks_port", socksPort)

		ti, err := initTunnel(&tunnel, socksPort)
		if err != nil {
			// Cleanup already created instances
			for _, instance := range tunnelInstances {
				instance.XrayInstance.Close()
				if instance.cancelFunc != nil {
					instance.cancelFunc()
				}
			}
			return nil, fmt.Errorf("failed to initialize tunnel %d: %v", i+1, err)
		}

		tunnelInstances = append(tunnelInstances, ti)

		slog.Info("started tunnel",
			"tunnel", ti.Name,
			"server", ti.MetricLabels.Server,
			"security", ti.MetricLabels.Security,
			"socks_port", socksPort)
	}

	// Wait for all SOCKS ports to become ready
	for _, ti := range tunnelInstances {
		if err := waitForSOCKSPort(ti.SocksPort, socksStartupTimeout); err != nil {
			slog.Warn("SOCKS port not ready", "tunnel", ti.Name, "port", ti.SocksPort, "error", err)
		}
	}

	// Start checker goroutines for all tunnels
	for _, ti := range tunnelInstances {
		ctx, cancel := context.WithCancel(context.Background())
		ti.cancelFunc = cancel
		go runTunnelChecker(ctx, ti)
	}

	return tunnelInstances, nil
}

// stopTunnels gracefully stops all tunnel instances
func stopTunnels(instances []*TunnelInstance) {
	for _, ti := range instances {
		if ti.cancelFunc != nil {
			ti.cancelFunc()
		}
		if ti.XrayInstance != nil {
			ti.XrayInstance.Close()
		}
	}
}

func tunnelMetricLabels(ti *TunnelInstance) []string {
	return []string{
		ti.Name,
		ti.MetricLabels.Server,
		ti.MetricLabels.Security,
		ti.MetricLabels.SNI,
	}
}

func cleanupRemovedTunnelMetrics(oldInstances, newInstances []*TunnelInstance) {
	if len(oldInstances) == 0 {
		return
	}

	newKeys := make(map[string]struct{}, len(newInstances))
	for _, ti := range newInstances {
		key := strings.Join(tunnelMetricLabels(ti), "|")
		newKeys[key] = struct{}{}
	}

	for _, ti := range oldInstances {
		key := strings.Join(tunnelMetricLabels(ti), "|")
		if _, exists := newKeys[key]; exists {
			continue
		}

		labels := tunnelMetricLabels(ti)
		tunnelUp.DeleteLabelValues(labels...)
		tunnelLatency.DeleteLabelValues(labels...)
		tunnelLastSuccess.DeleteLabelValues(labels...)
		tunnelHTTPStatus.DeleteLabelValues(labels...)
		tunnelCheckTotal.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], "success")
		tunnelCheckTotal.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], "failure")

		// Delete error metrics for all known reason categories
		for _, reason := range []string{"timeout", "dns", "tls", "connection_refused", "bad_status", "socks_error", "unknown"} {
			tunnelErrorTotal.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], reason)
		}
	}
}

// reloadConfig gracefully reloads configuration using a "start new, then stop old" strategy
// to avoid downtime: new tunnels are started on fresh ports before old ones are stopped.
func (tm *TunnelManager) reloadConfig(configFile string) error {
	slog.Info("reloading configuration", "config_file", configFile)

	// Load new config
	newConfig, err := loadConfig(configFile)
	if err != nil {
		slog.Error("failed to load new config", "error", err)
		return fmt.Errorf("failed to load config: %v", err)
	}

	// Resolve subscriptions
	subTunnels := resolveSubscriptions(newConfig)
	newConfig.Tunnels = append(newConfig.Tunnels, subTunnels...)

	if len(newConfig.Tunnels) == 0 {
		slog.Error("no tunnels after resolving subscriptions, keeping current config")
		return fmt.Errorf("no tunnels to initialize")
	}

	// Validate all tunnels before attempting to start new ones
	if err := validateTunnels(newConfig); err != nil {
		slog.Error("config validation failed, keeping current tunnels", "error", err)
		return fmt.Errorf("config validation failed: %v", err)
	}

	// Start new tunnels on next available ports (no overlap with current)
	tm.mu.RLock()
	newBasePort := tm.nextSocksPort
	tm.mu.RUnlock()

	newInstances, err := initializeTunnels(newConfig, newBasePort)
	if err != nil {
		slog.Error("failed to start new tunnels, keeping current", "error", err)
		return fmt.Errorf("failed to initialize tunnels: %v", err)
	}

	// New tunnels are running — safe to swap and stop old ones
	tm.mu.Lock()
	oldInstances := tm.instances
	tm.instances = newInstances
	tm.nextSocksPort = newBasePort + len(newInstances)
	tm.config = newConfig
	tm.mu.Unlock()

	stopTunnels(oldInstances)
	cleanupRemovedTunnelMetrics(oldInstances, newInstances)

	slog.Info("configuration reloaded successfully", "tunnel_count", len(newInstances))
	return nil
}

// watchConfigFile watches for config file changes and triggers reload
func watchConfigFile(ctx context.Context, tm *TunnelManager, configFile string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}
	defer watcher.Close()

	absConfig, err := filepath.Abs(configFile)
	if err != nil {
		return fmt.Errorf("failed to resolve config path: %v", err)
	}

	configDir := filepath.Dir(absConfig)
	configName := filepath.Base(absConfig)

	if err := watcher.Add(configDir); err != nil {
		return fmt.Errorf("failed to watch config directory: %v", err)
	}

	var (
		fileWatchActive bool
		fileWatchMu     sync.Mutex
	)

	addFileWatch := func() {
		fileWatchMu.Lock()
		defer fileWatchMu.Unlock()

		if fileWatchActive {
			return
		}

		if _, err := os.Stat(absConfig); err != nil {
			if !os.IsNotExist(err) {
				slog.Error("failed to stat config file", "path", absConfig, "error", err)
			}
			return
		}

		if err := watcher.Add(absConfig); err != nil {
			slog.Error("failed to watch config file", "path", absConfig, "error", err)
			return
		}

		fileWatchActive = true
		slog.Debug("watching config file", "path", absConfig)
	}

	removeFileWatch := func() {
		fileWatchMu.Lock()
		defer fileWatchMu.Unlock()

		if !fileWatchActive {
			return
		}

		if err := watcher.Remove(absConfig); err != nil {
			slog.Debug("failed to remove config file watch", "path", absConfig, "error", err)
		}
		fileWatchActive = false
	}

	scheduleFileRewatch := func() {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := os.Stat(absConfig); err == nil {
						addFileWatch()
						return
					}
				}
			}
		}()
	}

	addFileWatch()

	slog.Info("watching for config changes", "path", absConfig)

	// Debounce timer to avoid multiple reloads
	var debounceTimer *time.Timer
	debounceDuration := 1 * time.Second
	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			if event.Name == "" || filepath.Base(event.Name) != configName {
				continue
			}

			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				slog.Debug("config file removed or renamed", "path", absConfig)
				removeFileWatch()
				scheduleFileRewatch()
				continue
			}

			// Check if it's a write or create event
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Chmod) {
				slog.Info("config file changed", "path", event.Name)

				// Reset debounce timer
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				debounceTimer = time.AfterFunc(debounceDuration, func() {
					if err := tm.reloadConfig(absConfig); err != nil {
						slog.Error("failed to reload config after file change", "error", err)
					}
				})
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.Error("file watcher error", "error", err)
		}
	}
}

func watchSubscriptions(ctx context.Context, tm *TunnelManager, configFile string) {
	tm.mu.RLock()
	config := tm.config
	tm.mu.RUnlock()

	if config == nil || len(config.Subscriptions) == 0 {
		return
	}

	// Find minimum update interval
	minInterval := 1 * time.Hour
	for _, sub := range config.Subscriptions {
		d, err := time.ParseDuration(sub.UpdateInterval)
		if err == nil && d < minInterval {
			minInterval = d
		}
	}

	ticker := time.NewTicker(minInterval)
	defer ticker.Stop()

	slog.Info("subscription watcher started", "interval", minInterval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := tm.reloadConfig(configFile); err != nil {
				slog.Warn("subscription reload failed", "error", err)
			}
		}
	}
}

// leaderElectionConfig holds parameters for k8s lease-based leader election.
type leaderElectionConfig struct {
	Namespace     string
	Name          string
	Identity      string
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

// serviceAccountNamespacePath is the standard location of the in-pod namespace file.
// Declared as a variable so tests can override it.
var serviceAccountNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// readLeaderElectionConfig reads LEADER_ELECTION_* env vars and returns a
// leaderElectionConfig if leader election is enabled, or (nil, nil) if disabled.
func readLeaderElectionConfig() (*leaderElectionConfig, error) {
	if os.Getenv("LEADER_ELECTION") != "true" {
		return nil, nil
	}

	namespace := os.Getenv("LEADER_ELECTION_NAMESPACE")
	if namespace == "" {
		if data, err := os.ReadFile(serviceAccountNamespacePath); err == nil {
			namespace = strings.TrimSpace(string(data))
		}
	}
	if namespace == "" {
		return nil, fmt.Errorf("LEADER_ELECTION_NAMESPACE is required (or run inside a pod)")
	}

	name := os.Getenv("LEADER_ELECTION_NAME")
	if name == "" {
		name = "xray-health-exporter"
	}

	identity := os.Getenv("LEADER_ELECTION_IDENTITY")
	if identity == "" {
		identity = os.Getenv("HOSTNAME")
	}
	if identity == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to determine leader election identity: %v", err)
		}
		identity = hostname
	}

	return &leaderElectionConfig{
		Namespace:     namespace,
		Name:          name,
		Identity:      identity,
		LeaseDuration: 30 * time.Second,
		RenewDeadline: 20 * time.Second,
		RetryPeriod:   5 * time.Second,
	}, nil
}

// runProbing initializes tunnels, starts watchers, and blocks until ctx is canceled.
// On return all tunnel instances are stopped and per-tunnel metrics are cleared.
func runProbing(ctx context.Context, configFile string) error {
	config, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	subTunnels := resolveSubscriptions(config)
	config.Tunnels = append(config.Tunnels, subTunnels...)

	if len(config.Tunnels) == 0 {
		return fmt.Errorf("no tunnels to initialize (including subscriptions)")
	}

	slog.Debug("loaded config", "tunnel_count", len(config.Tunnels))

	tunnelManager := &TunnelManager{nextSocksPort: defaultSocksPort}

	tunnelInstances, err := initializeTunnels(config, defaultSocksPort)
	if err != nil {
		return fmt.Errorf("failed to initialize tunnels: %v", err)
	}

	tunnelManager.mu.Lock()
	tunnelManager.instances = tunnelInstances
	tunnelManager.nextSocksPort = defaultSocksPort + len(tunnelInstances)
	tunnelManager.config = config
	tunnelManager.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := watchConfigFile(ctx, tunnelManager, configFile); err != nil {
			slog.Error("file watcher stopped", "error", err)
		}
	}()
	go func() {
		defer wg.Done()
		watchSubscriptions(ctx, tunnelManager, configFile)
	}()

	slog.Info("probing started", "tunnel_count", len(tunnelInstances))
	slog.Info("config auto-reload enabled", "config_file", configFile)

	<-ctx.Done()

	tunnelManager.mu.Lock()
	finalInstances := tunnelManager.instances
	tunnelManager.instances = nil
	tunnelManager.mu.Unlock()

	stopTunnels(finalInstances)
	cleanupRemovedTunnelMetrics(finalInstances, nil)

	wg.Wait()
	slog.Info("probing stopped")
	return nil
}

// runWithLeaderElection starts a k8s lease-based leader election and runs runProbing
// only on the leader. Requires running inside a pod (uses InClusterConfig). Blocks
// until ctx is canceled.
func runWithLeaderElection(ctx context.Context, lec *leaderElectionConfig, configFile string) error {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to load in-cluster config (LEADER_ELECTION requires running inside a pod): %v", err)
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %v", err)
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      lec.Name,
			Namespace: lec.Namespace,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: lec.Identity,
		},
	}

	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   lec.LeaseDuration,
		RenewDeadline:   lec.RenewDeadline,
		RetryPeriod:     lec.RetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderCtx context.Context) {
				slog.Info("acquired leadership, starting probes")
				exporterLeader.Set(1)
				if err := runProbing(leaderCtx, configFile); err != nil {
					slog.Error("probing error while leader", "error", err)
				}
			},
			OnStoppedLeading: func() {
				// Per-tunnel metrics are cleared inside runProbing's deferred path;
				// here we only flip the leader gauge so followers report leader=0.
				slog.Info("lost leadership, stopping probes")
				exporterLeader.Set(0)
			},
			OnNewLeader: func(identity string) {
				if identity == lec.Identity {
					return
				}
				slog.Info("new leader elected", "identity", identity)
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create leader elector: %v", err)
	}

	slog.Info("leader election enabled", "namespace", lec.Namespace, "name", lec.Name, "identity", lec.Identity)
	elector.Run(ctx)
	return nil
}

func setupLogger() {
	levelStr := os.Getenv("LOG_LEVEL")

	if os.Getenv("DEBUG") == "true" {
		if levelStr != "" {
			slog.Warn("DEBUG is deprecated, use LOG_LEVEL=debug instead; using LOG_LEVEL value", "log_level", levelStr)
		} else {
			levelStr = "debug"
		}
	}

	if levelStr == "" {
		levelStr = "info"
	}

	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		slog.Warn("unknown LOG_LEVEL, falling back to info", "log_level", levelStr)
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))
}

func main() {
	setupLogger()

	slog.Info("xray-health-exporter starting", "version", Version)

	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = defaultConfigFile
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	lec, err := readLeaderElectionConfig()
	if err != nil {
		slog.Error("invalid leader election config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// When leader election is disabled this instance is the implicit leader for the
	// lifetime of the process. Set the gauge before serving /metrics to avoid a
	// brief window where scrapes see leader=0.
	if lec == nil {
		exporterLeader.Set(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	slog.Info("metrics server listening", "address", listenAddr)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	probingDone := make(chan struct{})
	go func() {
		defer close(probingDone)
		if lec != nil {
			if err := runWithLeaderElection(ctx, lec, configFile); err != nil {
				slog.Info("leader election stopped", "error", err)
			}
			return
		}
		if err := runProbing(ctx, configFile); err != nil {
			slog.Info("probing stopped", "error", err)
		}
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server error", "error", err)
		}
	case <-ctx.Done():
	case <-probingDone:
		slog.Warn("probing exited unexpectedly, shutting down")
	}

	slog.Info("shutdown signal received, stopping HTTP server")
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HTTP server shutdown error", "error", err)
	}

	select {
	case <-probingDone:
	case <-time.After(15 * time.Second):
		slog.Warn("probing did not stop within timeout, exiting anyway", "timeout", "15s")
	}
}
