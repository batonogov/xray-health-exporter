package tunnel

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VLESSConfig holds parsed VLESS URL parameters.
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

// ParseVLESSURL parses a VLESS URL into a VLESSConfig.
func ParseVLESSURL(vlessURL string) (*VLESSConfig, error) {
	if !strings.HasPrefix(vlessURL, "vless://") {
		return nil, fmt.Errorf("invalid vless URL")
	}

	u, err := url.Parse(vlessURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	config := &VLESSConfig{
		UUID:    u.User.Username(),
		Address: u.Hostname(),
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
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
