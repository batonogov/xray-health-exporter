package tunnel

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// ParseVLESSURL parses a VLESS URL into a VLESSConfig.
func ParseVLESSURL(vlessURL string) (*VLESSConfig, error) {
	u, err := url.Parse(vlessURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VLESS URL: %w", err)
	}
	if u.Scheme != "vless" {
		return nil, fmt.Errorf("invalid vless URL")
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("VLESS UUID is required")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("VLESS server address is required")
	}

	config := &VLESSConfig{
		UUID:    u.User.Username(),
		Address: u.Hostname(),
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port: must be between 1 and 65535")
	}
	config.Port = port

	query := u.Query()
	for key, values := range query {
		if len(values) > 1 {
			return nil, fmt.Errorf("duplicate VLESS query parameter %q", key)
		}
	}

	config.Type = query.Get("type")
	if config.Type == "" {
		config.Type = "tcp"
	}
	switch config.Type {
	case "raw":
		config.Type = "tcp"
	case "websocket":
		config.Type = "ws"
	case "mkcp":
		config.Type = "kcp"
	case "splithttp":
		config.Type = "xhttp"
	case "http", "h2", "h3":
		// Xray removed the legacy HTTP transport in favor of XHTTP
		// stream-one, which provides the equivalent HTTP/2 or HTTP/3 mode.
		config.Type = "xhttp"
		if query.Get("mode") == "" {
			config.Mode = "stream-one"
		}
	case "tcp", "kcp", "ws", "grpc", "httpupgrade", "xhttp":
	default:
		return nil, fmt.Errorf("unsupported VLESS transport %q", config.Type)
	}

	config.Encryption = query.Get("encryption")
	if config.Encryption == "" {
		config.Encryption = "none"
	}
	config.Flow = query.Get("flow")
	config.Security = query.Get("security")
	if config.Security == "" {
		config.Security = "none"
	}
	switch config.Security {
	case "none", "tls", "reality":
	default:
		return nil, fmt.Errorf("unsupported VLESS transport security %q", config.Security)
	}

	config.PBK = query.Get("pbk")
	config.SNI = query.Get("sni")
	config.FP = query.Get("fp")
	config.SID = query.Get("sid")
	config.PQV = query.Get("pqv")
	config.SPX = query.Get("spx")
	config.ALPN = splitCommaSeparated(query.Get("alpn"))
	config.ECHConfigList = query.Get("ech")
	config.PinnedPeerCertSHA256 = query.Get("pcs")
	config.VerifyPeerCertByName = query.Get("vcn")
	config.ServiceName = query.Get("serviceName")
	config.Authority = query.Get("authority")
	config.Host = query.Get("host")
	config.Path = query.Get("path")

	if config.Security == "tls" || config.Security == "reality" {
		if config.SNI == "" {
			config.SNI = config.Address
		}
		if config.FP == "" {
			config.FP = "chrome"
		}
	}
	if config.Security == "reality" && config.PBK == "" {
		return nil, fmt.Errorf("pbk is required for reality security")
	}

	switch config.Type {
	case "grpc":
		if config.ServiceName == "" {
			return nil, fmt.Errorf("serviceName is required for grpc transport")
		}
		config.Mode = query.Get("mode")
		switch config.Mode {
		case "", "gun", "guna":
		case "multi":
			config.MultiMode = true
		default:
			return nil, fmt.Errorf("unsupported gRPC mode %q", config.Mode)
		}
		if query.Get("multiMode") == "true" {
			config.MultiMode = true
		}
	case "xhttp":
		if config.Mode == "" {
			config.Mode = query.Get("mode")
		}
		switch config.Mode {
		case "", "auto", "packet-up", "stream-up", "stream-one":
		default:
			return nil, fmt.Errorf("unsupported XHTTP mode %q", config.Mode)
		}
		config.Extra, err = parseJSONObjectParameter(query, "extra")
		if err != nil {
			return nil, err
		}
	case "kcp":
		config.KCPMTU, err = parseUint32Parameter(query, "mtu")
		if err != nil {
			return nil, err
		}
		config.KCPTTI, err = parseUint32Parameter(query, "tti")
		if err != nil {
			return nil, err
		}
	}

	config.FinalMask, err = parseJSONObjectParameter(query, "fm")
	if err != nil {
		return nil, err
	}

	return config, nil
}

func splitCommaSeparated(value string) []string {
	if value == "" {
		return nil
	}

	var result []string
	for part := range strings.SplitSeq(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func parseJSONObjectParameter(query url.Values, key string) (json.RawMessage, error) {
	value := query.Get(key)
	if value == "" {
		return nil, nil
	}

	var object map[string]interface{}
	if err := json.Unmarshal([]byte(value), &object); err != nil {
		return nil, fmt.Errorf("invalid %s JSON: %w", key, err)
	}
	if object == nil {
		return nil, fmt.Errorf("invalid %s JSON: object is required", key)
	}
	return json.RawMessage(value), nil
}

func parseUint32Parameter(query url.Values, key string) (*uint32, error) {
	value := query.Get(key)
	if value == "" {
		return nil, nil
	}

	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return nil, fmt.Errorf("invalid %s: must be a positive 32-bit integer", key)
	}
	result := uint32(parsed)
	return &result, nil
}

// CreateXrayConfig generates a complete Xray JSON config for a VLESS tunnel
// with a SOCKS5 inbound on the given port.
func CreateXrayConfig(vlessConfig *VLESSConfig, socksPort int) ([]byte, error) {
	logLevel := os.Getenv("XRAY_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "warning"
	}

	encryption := vlessConfig.Encryption
	if encryption == "" {
		encryption = "none"
	}
	user := map[string]interface{}{
		"id":         vlessConfig.UUID,
		"encryption": encryption,
	}
	if vlessConfig.Flow != "" {
		user["flow"] = vlessConfig.Flow
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
								user,
							},
						},
					},
				},
				"streamSettings": CreateStreamSettings(vlessConfig),
			},
		},
	}

	return json.MarshalIndent(config, "", "  ")
}

// CreateStreamSettings builds the streamSettings map for a VLESS config.
func CreateStreamSettings(vlessConfig *VLESSConfig) map[string]interface{} {
	streamSettings := map[string]interface{}{
		"network": vlessConfig.Type,
	}

	if len(vlessConfig.FinalMask) > 0 {
		streamSettings["finalmask"] = vlessConfig.FinalMask
	}

	if vlessConfig.Type == "tcp" {
		streamSettings["rawSettings"] = map[string]interface{}{
			"header": map[string]interface{}{
				"type": "none",
			},
		}
	}

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

	if vlessConfig.Type == "ws" {
		wsSettings := map[string]interface{}{}
		if vlessConfig.Path != "" {
			wsSettings["path"] = vlessConfig.Path
		}
		if vlessConfig.Host != "" {
			wsSettings["host"] = vlessConfig.Host
		}
		streamSettings["wsSettings"] = wsSettings
	}

	if vlessConfig.Type == "httpupgrade" {
		httpUpgradeSettings := map[string]interface{}{}
		if vlessConfig.Path != "" {
			httpUpgradeSettings["path"] = vlessConfig.Path
		}
		if vlessConfig.Host != "" {
			httpUpgradeSettings["host"] = vlessConfig.Host
		}
		streamSettings["httpupgradeSettings"] = httpUpgradeSettings
	}

	if vlessConfig.Type == "xhttp" {
		xhttpSettings := map[string]interface{}{}
		if vlessConfig.Path != "" {
			xhttpSettings["path"] = vlessConfig.Path
		}
		if vlessConfig.Host != "" {
			xhttpSettings["host"] = vlessConfig.Host
		}
		if vlessConfig.Mode != "" {
			xhttpSettings["mode"] = vlessConfig.Mode
		}
		if len(vlessConfig.Extra) > 0 {
			xhttpSettings["extra"] = vlessConfig.Extra
		}
		streamSettings["xhttpSettings"] = xhttpSettings
	}

	if vlessConfig.Type == "kcp" {
		kcpSettings := map[string]interface{}{}
		if vlessConfig.KCPMTU != nil {
			kcpSettings["mtu"] = *vlessConfig.KCPMTU
		}
		if vlessConfig.KCPTTI != nil {
			kcpSettings["tti"] = *vlessConfig.KCPTTI
		}
		streamSettings["kcpSettings"] = kcpSettings
	}

	if vlessConfig.Security == "reality" {
		streamSettings["security"] = "reality"

		realitySettings := map[string]interface{}{
			"show":        false,
			"fingerprint": vlessConfig.FP,
			"serverName":  vlessConfig.SNI,
			"password":    vlessConfig.PBK,
		}

		if vlessConfig.SID != "" {
			realitySettings["shortId"] = vlessConfig.SID
		}
		if vlessConfig.PQV != "" {
			realitySettings["mldsa65Verify"] = vlessConfig.PQV
		}
		if vlessConfig.SPX != "" {
			realitySettings["spiderX"] = vlessConfig.SPX
		}

		streamSettings["realitySettings"] = realitySettings
	} else if vlessConfig.Security == "tls" {
		streamSettings["security"] = "tls"
		tlsSettings := map[string]interface{}{
			"serverName":  vlessConfig.SNI,
			"fingerprint": vlessConfig.FP,
		}
		if len(vlessConfig.ALPN) > 0 {
			tlsSettings["alpn"] = vlessConfig.ALPN
		}
		if vlessConfig.ECHConfigList != "" {
			tlsSettings["echConfigList"] = vlessConfig.ECHConfigList
		}
		if vlessConfig.PinnedPeerCertSHA256 != "" {
			tlsSettings["pinnedPeerCertSha256"] = vlessConfig.PinnedPeerCertSHA256
		}
		if vlessConfig.VerifyPeerCertByName != "" {
			tlsSettings["verifyPeerCertByName"] = vlessConfig.VerifyPeerCertByName
		}
		streamSettings["tlsSettings"] = tlsSettings
	}

	return streamSettings
}

// StartXray parses the JSON config and starts an Xray core instance.
func StartXray(configJSON []byte) (*core.Instance, error) {
	var config conf.Config
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	pbConfig, err := config.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build config: %v", err)
	}

	instance, err := core.New(pbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create xray instance: %v", err)
	}

	if err := instance.Start(); err != nil {
		return nil, fmt.Errorf("failed to start xray: %v", err)
	}

	return instance, nil
}

// LoadXrayConfigFile reads a native Xray JSON config file, injects a SOCKS5
// inbound on the given port, and returns the modified JSON along with the
// extracted metric labels.
func LoadXrayConfigFile(path string, socksPort int) ([]byte, MetricLabels, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, MetricLabels{}, fmt.Errorf("failed to read xray config file: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, MetricLabels{}, fmt.Errorf("failed to parse xray config JSON: %v", err)
	}

	labels := ExtractMetricLabelsFromXrayConfig(raw)

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

// ExtractMetricLabelsFromXrayConfig extracts Prometheus metric labels from
// the first outbound of a raw Xray JSON config. Supports VLESS/VMess (vnext)
// and Trojan/Shadowsocks (servers).
func ExtractMetricLabelsFromXrayConfig(raw map[string]interface{}) MetricLabels {
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
