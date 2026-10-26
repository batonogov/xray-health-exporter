package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Clash subscriptions describe proxies individually; routing and proxy groups
// belong to the client and are intentionally not imported by the exporter.
func parseClashSubscription(body []byte) ([]Tunnel, error) {
	var document struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(body, &document) != nil {
		return nil, errors.New("invalid Clash YAML subscription")
	}
	if len(document.Proxies) == 0 {
		return nil, errors.New("Clash subscription contains no proxies")
	}
	result := make([]Tunnel, 0, len(document.Proxies))
	for i, proxy := range document.Proxies {
		tunnel, err := clashProxy(proxy)
		if err != nil {
			return nil, fmt.Errorf("Clash proxy %d: %w", i, err)
		}
		result = append(result, tunnel)
	}
	return result, nil
}

func clashProxy(p map[string]any) (Tunnel, error) {
	protocol, _ := p["type"].(string)
	allowed := "name type server port udp network tls servername sni skip-cert-verify client-fingerprint alpn ws-opts grpc-opts reality-opts"
	switch protocol {
	case "vless":
		allowed += " uuid flow"
	case "vmess":
		allowed += " uuid alterId cipher"
	case "trojan":
		allowed += " password"
	case "ss":
		allowed = "name type server port udp cipher password"
	default:
		return Tunnel{}, errors.New("unsupported proxy type (supported: vless, vmess, trojan, ss)")
	}
	if err := rejectClashKeys(p, allowed); err != nil {
		return Tunnel{}, err
	}
	name, err := clashString(p, "name", true)
	if err != nil {
		return Tunnel{}, err
	}
	host, err := clashString(p, "server", true)
	if err != nil {
		return Tunnel{}, err
	}
	port, err := clashInt(p, "port", 1, 65535, true)
	if err != nil {
		return Tunnel{}, err
	}
	if _, err := clashBool(p, "udp"); err != nil {
		return Tunnel{}, err
	}
	server := map[string]any{"address": host, "port": port}
	var settings map[string]any
	switch protocol {
	case "vless", "vmess":
		id, err := clashString(p, "uuid", true)
		if err != nil {
			return Tunnel{}, err
		}
		user := map[string]any{"id": id}
		if protocol == "vless" {
			user["encryption"] = "none"
			if flow, err := clashString(p, "flow", false); err != nil {
				return Tunnel{}, err
			} else if flow != "" {
				user["flow"] = flow
			}
		} else {
			aid, err := clashInt(p, "alterId", 0, 65535, false)
			if err != nil {
				return Tunnel{}, err
			}
			if aid != 0 {
				return Tunnel{}, errors.New("VMess alterId must be zero")
			}
			user["alterId"] = aid
			cipher, err := clashString(p, "cipher", false)
			if err != nil {
				return Tunnel{}, err
			}
			if cipher == "" {
				cipher = "auto"
			}
			switch cipher {
			case "auto", "aes-128-gcm", "chacha20-poly1305":
			default:
				return Tunnel{}, errors.New("unsupported VMess cipher")
			}
			user["security"] = cipher
		}
		server["users"] = []any{user}
		settings = map[string]any{"vnext": []any{server}}
	case "trojan", "ss":
		password, err := clashString(p, "password", true)
		if err != nil {
			return Tunnel{}, err
		}
		server["password"] = password
		if protocol == "ss" {
			cipher, err := clashString(p, "cipher", true)
			if err != nil {
				return Tunnel{}, err
			}
			server["method"] = cipher
		}
		settings = map[string]any{"servers": []any{server}}
	}
	xrayProtocol := protocol
	if protocol == "ss" {
		xrayProtocol = "shadowsocks"
	}
	outbound := map[string]any{"protocol": xrayProtocol, "settings": settings, "tag": "proxy"}
	if protocol != "ss" {
		stream, err := clashStream(p, protocol)
		if err != nil {
			return Tunnel{}, err
		}
		outbound["streamSettings"] = stream
	}
	raw, err := json.Marshal(map[string]any{"outbounds": []any{outbound}})
	if err != nil {
		return Tunnel{}, errors.New("cannot encode Clash proxy")
	}
	return Tunnel{Name: name, XrayConfigJSON: raw}, nil
}

func clashStream(p map[string]any, protocol string) (map[string]any, error) {
	network, err := clashString(p, "network", false)
	if err != nil {
		return nil, err
	}
	if network == "" {
		network = "tcp"
	}
	stream := map[string]any{"network": network}
	switch network {
	case "tcp":
	case "ws":
		opts, err := clashMap(p, "ws-opts")
		if err != nil {
			return nil, err
		}
		if err := rejectClashKeys(opts, "path headers"); err != nil {
			return nil, err
		}
		settings := map[string]any{}
		if path, err := clashString(opts, "path", false); err != nil {
			return nil, err
		} else if path != "" {
			settings["path"] = path
		}
		if headers, ok := opts["headers"]; ok {
			m, ok := headers.(map[string]any)
			if !ok {
				return nil, errors.New("ws-opts.headers must be a string map")
			}
			for _, v := range m {
				if _, ok := v.(string); !ok {
					return nil, errors.New("ws-opts.headers must be a string map")
				}
			}
			settings["headers"] = m
		}
		stream["wsSettings"] = settings
	case "grpc":
		opts, err := clashMap(p, "grpc-opts")
		if err != nil {
			return nil, err
		}
		if err := rejectClashKeys(opts, "grpc-service-name"); err != nil {
			return nil, err
		}
		service, err := clashString(opts, "grpc-service-name", false)
		if err != nil {
			return nil, err
		}
		stream["grpcSettings"] = map[string]any{"serviceName": service}
	default:
		return nil, errors.New("unsupported Clash network (supported: tcp, ws, grpc)")
	}
	if _, ok := p["ws-opts"]; ok && network != "ws" {
		return nil, errors.New("ws-opts requires network ws")
	}
	if _, ok := p["grpc-opts"]; ok && network != "grpc" {
		return nil, errors.New("grpc-opts requires network grpc")
	}
	tls, err := clashBool(p, "tls")
	if err != nil {
		return nil, err
	}
	if protocol == "trojan" {
		tls = true
	}
	reality, err := clashMap(p, "reality-opts")
	if err != nil {
		return nil, err
	}
	sni, err := clashString(p, "servername", false)
	if err != nil {
		return nil, err
	}
	if other, err := clashString(p, "sni", false); err != nil {
		return nil, err
	} else if other != "" {
		if sni != "" && other != sni {
			return nil, errors.New("conflicting sni and servername")
		}
		sni = other
	}
	fingerprint, err := clashString(p, "client-fingerprint", false)
	if err != nil {
		return nil, err
	}
	insecure, err := clashBool(p, "skip-cert-verify")
	if err != nil {
		return nil, err
	}
	if insecure {
		return nil, errors.New("skip-cert-verify is not supported by the embedded Xray core")
	}
	if _, hasReality := p["reality-opts"]; hasReality {
		if protocol != "vless" {
			return nil, errors.New("reality-opts requires vless")
		}
		if err := rejectClashKeys(reality, "public-key short-id"); err != nil {
			return nil, err
		}
		if _, ok := p["alpn"]; ok {
			return nil, errors.New("alpn is not supported with reality")
		}
		key, err := clashString(reality, "public-key", true)
		if err != nil {
			return nil, err
		}
		shortID, err := clashString(reality, "short-id", false)
		if err != nil {
			return nil, err
		}
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		stream["security"] = "reality"
		stream["realitySettings"] = map[string]any{"serverName": sni, "password": key, "shortId": shortID, "fingerprint": fingerprint}
	} else if tls {
		stream["security"] = "tls"
		settings := map[string]any{"serverName": sni}
		if fingerprint != "" {
			settings["fingerprint"] = fingerprint
		}
		if alpn, ok := p["alpn"]; ok {
			values, ok := alpn.([]any)
			if !ok {
				return nil, errors.New("alpn must be a string list")
			}
			for _, value := range values {
				if _, ok := value.(string); !ok {
					return nil, errors.New("alpn must be a string list")
				}
			}
			settings["alpn"] = values
		}
		stream["tlsSettings"] = settings
	} else {
		for _, key := range []string{"servername", "sni", "skip-cert-verify", "client-fingerprint", "alpn", "reality-opts"} {
			if _, ok := p[key]; ok {
				return nil, fmt.Errorf("%s requires TLS or Reality", key)
			}
		}
		stream["security"] = "none"
	}
	return stream, nil
}

func rejectClashKeys(values map[string]any, allowed string) error {
	allowed = " " + allowed + " "
	for key := range values {
		if !strings.Contains(allowed, " "+key+" ") {
			return fmt.Errorf("unsupported Clash option %q", key)
		}
	}
	return nil
}
func clashString(values map[string]any, key string, required bool) (string, error) {
	v, exists := values[key]
	if !exists && !required {
		return "", nil
	}
	s, ok := v.(string)
	if !ok || (required && s == "") {
		return "", fmt.Errorf("%s must be a nonempty string", key)
	}
	return s, nil
}
func clashInt(values map[string]any, key string, min, max int, required bool) (int, error) {
	v, exists := values[key]
	if !exists && !required {
		return 0, nil
	}
	var n int
	var err error
	switch v := v.(type) {
	case int:
		n = v
	case string:
		n, err = strconv.Atoi(v)
	default:
		err = errors.New("not integer")
	}
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be an integer in range %d-%d", key, min, max)
	}
	return n, nil
}
func clashBool(values map[string]any, key string) (bool, error) {
	v, exists := values[key]
	if !exists {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be boolean", key)
	}
	return b, nil
}
func clashMap(values map[string]any, key string) (map[string]any, error) {
	v, exists := values[key]
	if !exists {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a mapping", key)
	}
	return m, nil
}
