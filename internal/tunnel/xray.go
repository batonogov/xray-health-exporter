package tunnel

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	_ "github.com/xtls/xray-core/main/distro/all"
)

// CreateXrayConfig generates Xray JSON configuration from VLESS config.
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
									"flow":       "",
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

// CreateStreamSettings builds stream settings for the Xray config.
func CreateStreamSettings(vlessConfig *VLESSConfig) map[string]interface{} {
	streamSettings := map[string]interface{}{
		"network": vlessConfig.Type,
	}

	if vlessConfig.Type == "tcp" {
		streamSettings["tcpSettings"] = map[string]interface{}{
			"header": map[string]interface{}{
				"type": "none",
			},
		}
	}

	switch vlessConfig.Security {
	case "reality":
		streamSettings["security"] = "reality"

		realitySettings := map[string]interface{}{
			"show":        false,
			"fingerprint": vlessConfig.FP,
			"serverName":  vlessConfig.SNI,
			"publicKey":   vlessConfig.PBK,
		}

		if vlessConfig.SID != "" {
			realitySettings["shortId"] = vlessConfig.SID
		}

		if vlessConfig.SPX != "" {
			realitySettings["spiderX"] = vlessConfig.SPX
		}

		streamSettings["realitySettings"] = realitySettings
	case "tls":
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName":    vlessConfig.SNI,
			"allowInsecure": false,
			"fingerprint":   vlessConfig.FP,
		}
	}

	return streamSettings
}

// StartXray creates and starts an Xray instance from JSON config.
func StartXray(configJSON []byte) (*core.Instance, error) {
	var config conf.Config
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	pbConfig, err := config.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build config: %w", err)
	}

	instance, err := core.New(pbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create xray instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		return nil, fmt.Errorf("failed to start xray: %w", err)
	}

	return instance, nil
}
