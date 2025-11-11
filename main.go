package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"gopkg.in/yaml.v3"

	_ "github.com/xtls/xray-core/main/distro/all"
)

const (
	defaultListenAddr    = ":9273"
	defaultCheckURL      = "https://www.google.com"
	defaultTimeout       = 30 * time.Second
	defaultSocksPort     = 1080
	defaultCheckInterval = 30 * time.Second
	defaultConfigFile    = "/app/config.yaml"
)

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
)

func init() {
	prometheus.MustRegister(tunnelUp)
	prometheus.MustRegister(tunnelLatency)
	prometheus.MustRegister(tunnelCheckTotal)
	prometheus.MustRegister(tunnelLastSuccess)
	prometheus.MustRegister(tunnelHTTPStatus)
}

// Config structures
type Config struct {
	Defaults Defaults `yaml:"defaults"`
	Tunnels  []Tunnel `yaml:"tunnels"`
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

type VLESSConfig struct {
	UUID     string
	Address  string
	Port     int
	Security string
	PBK      string
	SNI      string
	FP       string
	SID      string
	SPX      string
	Type     string
}

type TunnelInstance struct {
	Name          string
	VLESSConfig   *VLESSConfig
	XrayInstance  *core.Instance
	SocksPort     int
	CheckURL      string
	CheckInterval time.Duration
	CheckTimeout  time.Duration
	cancelFunc    context.CancelFunc
}

// TunnelManager manages tunnel instances with thread-safe access
type TunnelManager struct {
	mu        sync.RWMutex
	instances []*TunnelInstance
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
	if len(config.Tunnels) == 0 {
		return nil, fmt.Errorf("no tunnels defined in config")
	}

	// Apply defaults to tunnels
	for i := range config.Tunnels {
		tunnel := &config.Tunnels[i]

		if tunnel.URL == "" {
			return nil, fmt.Errorf("tunnel %d: url is required", i)
		}

		// Apply defaults if not specified in tunnel
		if tunnel.CheckURL == "" {
			tunnel.CheckURL = config.Defaults.CheckURL
		}
		if tunnel.CheckInterval == "" {
			tunnel.CheckInterval = config.Defaults.CheckInterval
		}
		if tunnel.CheckTimeout == "" {
			tunnel.CheckTimeout = config.Defaults.CheckTimeout
		}

		// Set global defaults if not specified anywhere
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

	return &config, nil
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
									"flow":       "",
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

func initTunnel(tunnel *Tunnel, socksPort int, debug bool) (*TunnelInstance, error) {
	// Parse VLESS URL
	vlessConfig, err := parseVLESSURL(tunnel.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VLESS URL: %v", err)
	}

	// Parse durations
	checkInterval, err := time.ParseDuration(tunnel.CheckInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid check_interval: %v", err)
	}

	checkTimeout, err := time.ParseDuration(tunnel.CheckTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid check_timeout: %v", err)
	}

	// Create Xray config
	xrayConfigJSON, err := createXrayConfig(vlessConfig, socksPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create Xray config: %v", err)
	}

	if debug {
		log.Printf("[%s] Xray config: %s", tunnel.Name, string(xrayConfigJSON))
	}

	// Start Xray instance
	xrayInstance, err := startXray(xrayConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to start Xray: %v", err)
	}

	// Generate name if not specified
	name := tunnel.Name
	if name == "" {
		name = fmt.Sprintf("%s:%d", vlessConfig.Address, vlessConfig.Port)
	}

	return &TunnelInstance{
		Name:          name,
		VLESSConfig:   vlessConfig,
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

func checkTunnel(ti *TunnelInstance) {
	start := time.Now()

	// Labels для метрик
	serverLabel := fmt.Sprintf("%s:%d", ti.VLESSConfig.Address, ti.VLESSConfig.Port)
	labels := prometheus.Labels{
		"name":     ti.Name,
		"server":   serverLabel,
		"security": ti.VLESSConfig.Security,
		"sni":      ti.VLESSConfig.SNI,
	}

	socksProxy := fmt.Sprintf("127.0.0.1:%d", ti.SocksPort)

	// Сначала проверим что SOCKS5 прокси вообще работает
	conn, err := net.DialTimeout("tcp", socksProxy, 5*time.Second)
	if err != nil {
		log.Printf("[%s] ✗ Tunnel DOWN: %v", ti.Name, err)
		tunnelUp.With(labels).Set(0)
		tunnelCheckTotal.With(prometheus.Labels{
			"name":     ti.Name,
			"server":   serverLabel,
			"security": ti.VLESSConfig.Security,
			"sni":      ti.VLESSConfig.SNI,
			"result":   "failure",
		}).Inc()
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
		log.Printf("[%s] ✗ Tunnel DOWN: %v", ti.Name, err)
		tunnelUp.With(labels).Set(0)
		tunnelCheckTotal.With(prometheus.Labels{
			"name":     ti.Name,
			"server":   serverLabel,
			"security": ti.VLESSConfig.Security,
			"sni":      ti.VLESSConfig.SNI,
			"result":   "failure",
		}).Inc()
		return
	}
	defer resp.Body.Close()

	// Сохраняем HTTP статус
	tunnelHTTPStatus.With(labels).Set(float64(resp.StatusCode))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusTemporaryRedirect {
		log.Printf("[%s] ✗ Tunnel DOWN: status %d", ti.Name, resp.StatusCode)
		tunnelUp.With(labels).Set(0)
		tunnelCheckTotal.With(prometheus.Labels{
			"name":     ti.Name,
			"server":   serverLabel,
			"security": ti.VLESSConfig.Security,
			"sni":      ti.VLESSConfig.SNI,
			"result":   "failure",
		}).Inc()
		return
	}

	// Читаем немного тела ответа чтобы убедиться что соединение работает
	buf := make([]byte, 1024)
	resp.Body.Read(buf)

	duration := time.Since(start)
	log.Printf("[%s] ✓ Tunnel UP [%v]", ti.Name, duration.Round(time.Millisecond))
	tunnelUp.With(labels).Set(1)
	tunnelLatency.With(labels).Set(duration.Seconds())
	tunnelLastSuccess.With(labels).Set(float64(time.Now().Unix()))
	tunnelCheckTotal.With(prometheus.Labels{
		"name":     ti.Name,
		"server":   serverLabel,
		"security": ti.VLESSConfig.Security,
		"sni":      ti.VLESSConfig.SNI,
		"result":   "success",
	}).Inc()
}

func runTunnelChecker(ctx context.Context, ti *TunnelInstance) {
	ticker := time.NewTicker(ti.CheckInterval)
	defer ticker.Stop()

	// Первая проверка сразу
	checkTunnel(ti)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkTunnel(ti)
		}
	}
}

// initializeTunnels creates and starts all tunnel instances from config
func initializeTunnels(config *Config, debug bool) ([]*TunnelInstance, error) {
	if len(config.Tunnels) == 0 {
		return nil, fmt.Errorf("no tunnels to initialize")
	}

	var tunnelInstances []*TunnelInstance
	baseSocksPort := defaultSocksPort

	for i, tunnel := range config.Tunnels {
		socksPort := baseSocksPort + i

		if debug {
			log.Printf("Initializing tunnel %d: %s (SOCKS port: %d)", i+1, tunnel.Name, socksPort)
		}

		ti, err := initTunnel(&tunnel, socksPort, debug)
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

		log.Printf("Started tunnel [%s] → %s:%d [%s] on SOCKS port %d",
			ti.Name, ti.VLESSConfig.Address, ti.VLESSConfig.Port, ti.VLESSConfig.Security, socksPort)
	}

	// Wait for all Xray instances to start
	time.Sleep(5 * time.Second)

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

// reloadConfig gracefully reloads configuration
func (tm *TunnelManager) reloadConfig(configFile string, debug bool) error {
	log.Printf("Reloading configuration from %s", configFile)

	// Load new config
	newConfig, err := loadConfig(configFile)
	if err != nil {
		log.Printf("Failed to load new config: %v", err)
		return fmt.Errorf("failed to load config: %v", err)
	}

	// Initialize new tunnels
	newInstances, err := initializeTunnels(newConfig, debug)
	if err != nil {
		log.Printf("Failed to initialize new tunnels: %v", err)
		return fmt.Errorf("failed to initialize tunnels: %v", err)
	}

	// Replace old instances with new ones
	tm.mu.Lock()
	oldInstances := tm.instances
	tm.instances = newInstances
	tm.mu.Unlock()

	// Stop old tunnels
	log.Printf("Stopping old tunnel instances")
	stopTunnels(oldInstances)

	log.Printf("Configuration reloaded successfully with %d tunnels", len(newInstances))
	return nil
}

// watchConfigFile watches for config file changes and triggers reload
func watchConfigFile(tm *TunnelManager, configFile string, debug bool) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}
	defer watcher.Close()

	// Watch the config file
	err = watcher.Add(configFile)
	if err != nil {
		return fmt.Errorf("failed to watch config file: %v", err)
	}

	log.Printf("Watching for config changes: %s", configFile)

	// Debounce timer to avoid multiple reloads
	var debounceTimer *time.Timer
	debounceDuration := 1 * time.Second

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			// Check if it's a write or create event
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				log.Printf("Config file changed: %s", event.Name)

				// Reset debounce timer
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				debounceTimer = time.AfterFunc(debounceDuration, func() {
					if err := tm.reloadConfig(configFile, debug); err != nil {
						log.Printf("Failed to reload config: %v", err)
					}
				})
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("File watcher error: %v", err)
		}
	}
}

func main() {
	// Get config file path
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = defaultConfigFile
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	debug := os.Getenv("DEBUG") == "true"

	// Load config
	config, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if debug {
		log.Printf("Loaded config with %d tunnels", len(config.Tunnels))
	}

	// Initialize tunnel manager
	tunnelManager := &TunnelManager{}

	// Initialize all tunnels
	tunnelInstances, err := initializeTunnels(config, debug)
	if err != nil {
		log.Fatalf("Failed to initialize tunnels: %v", err)
	}

	tunnelManager.mu.Lock()
	tunnelManager.instances = tunnelInstances
	tunnelManager.mu.Unlock()

	// Cleanup on exit
	defer func() {
		tunnelManager.mu.RLock()
		stopTunnels(tunnelManager.instances)
		tunnelManager.mu.RUnlock()
	}()

	// Start file watcher for automatic config reload
	go func() {
		if err := watchConfigFile(tunnelManager, configFile, debug); err != nil {
			log.Printf("File watcher stopped: %v", err)
		}
	}()

	// HTTP server for metrics
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	log.Printf("Metrics server listening on %s", listenAddr)
	log.Printf("Config auto-reload enabled for: %s", configFile)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
