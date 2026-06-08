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

// CreateXrayConfig generates a complete Xray JSON config for a VLESS tunnel
// with a SOCKS5 inbound on the given port.
func CreateXrayConfig(vlessConfig *VLESSConfig, socksPort int) ([]byte, error) {
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

		// ShortId may be empty or an array
		if vlessConfig.SID != "" {
			realitySettings["shortId"] = vlessConfig.SID
		}

		// SpiderX - path for obfuscation
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
