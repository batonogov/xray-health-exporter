package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// CreateShareLinkConfig converts a supported share link into an exporter-owned
// Xray configuration. External Shadowsocks plugins are deliberately unsupported.
func CreateShareLinkConfig(link string, socksPort int) ([]byte, MetricLabels, error) {
	var outbound map[string]interface{}
	var err error
	switch {
	case strings.HasPrefix(link, "trojan://"):
		outbound, err = parseTrojanLink(link)
	case strings.HasPrefix(link, "ss://"):
		outbound, err = parseShadowsocksLink(link)
	case strings.HasPrefix(link, "vmess://"):
		outbound, err = parseVMessLink(link)
	default:
		return nil, MetricLabels{}, fmt.Errorf("unsupported share-link protocol")
	}
	if err != nil {
		return nil, MetricLabels{}, err
	}
	data, err := json.Marshal(map[string]interface{}{"outbounds": []interface{}{outbound}})
	if err != nil {
		return nil, MetricLabels{}, err
	}
	return LoadXrayConfigJSON(data, socksPort)
}

func decodeShareBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err := encoding.DecodeString(value); err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 share-link payload")
}

func parseShareURL(link string) (*url.URL, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("malformed share-link URL")
	}
	if u.Hostname() == "" || u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("share link requires server and credentials")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("share-link port must be between 1 and 65535")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("share-link path must be supplied as a query parameter")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("malformed share-link query")
	}
	for _, values := range q {
		if len(values) != 1 {
			return nil, fmt.Errorf("duplicate share-link query parameter")
		}
	}
	return u, nil
}

// shareStreamSettings reuses the validated VLESS transport representation; the
// synthetic identity is never emitted in the resulting outbound configuration.
func shareStreamSettings(u *url.URL, defaultSecurity string) (map[string]interface{}, error) {
	clone := *u
	clone.Scheme = "vless"
	clone.User = url.User("00000000-0000-4000-8000-000000000001")
	q := clone.Query()
	allowed := map[string]bool{}
	for _, k := range strings.Fields("type security sni peer fp pbk sid pqv spx alpn ech pcs vcn serviceName authority host path mode multiMode extra mtu tti fm allowInsecure insecure encryption aid scy") {
		allowed[k] = true
	}
	for k := range q {
		if !allowed[k] {
			return nil, fmt.Errorf("unsupported share-link query option %q", k)
		}
	}
	if q.Get("sni") == "" && q.Get("peer") != "" {
		q.Set("sni", q.Get("peer"))
	}
	if q.Get("security") == "" {
		q.Set("security", defaultSecurity)
	}
	// Xray removed allowInsecure. Never silently ignore requests to disable TLS verification.
	for _, key := range []string{"allowInsecure", "insecure"} {
		if q.Has(key) {
			enabled, err := strconv.ParseBool(q.Get(key))
			if err != nil {
				return nil, fmt.Errorf("invalid %s boolean", key)
			}
			if enabled {
				return nil, fmt.Errorf("insecure TLS is unsupported; use certificate pinning (pcs/vcn)")
			}
		}
	}
	clone.RawQuery = q.Encode()
	cfg, err := ParseVLESSURL(clone.String())
	if err != nil {
		return nil, err
	}
	return CreateStreamSettings(cfg), nil
}

func parseTrojanLink(link string) (map[string]interface{}, error) {
	u, err := parseShareURL(link)
	if err != nil {
		return nil, err
	}
	if _, present := u.User.Password(); present {
		return nil, fmt.Errorf("Trojan password must be encoded in the URL username")
	}
	for _, key := range []string{"encryption", "scy", "aid"} {
		if u.Query().Has(key) {
			return nil, fmt.Errorf("unsupported Trojan query option %q", key)
		}
	}
	stream, err := shareStreamSettings(u, "tls")
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	return map[string]interface{}{
		"protocol": "trojan", "streamSettings": stream,
		"settings": map[string]interface{}{"servers": []interface{}{map[string]interface{}{
			"address": u.Hostname(), "port": port, "password": u.User.Username(),
		}}},
	}, nil
}

func parseShadowsocksLink(link string) (map[string]interface{}, error) {
	payload := strings.TrimPrefix(link, "ss://")
	// Legacy links encode the entire method:password@host:port tuple. Split at
	// the last @ after decoding so passwords may themselves contain @ or /.
	if !strings.Contains(strings.SplitN(payload, "#", 2)[0], "@") {
		data, err := decodeShareBase64(strings.SplitN(payload, "#", 2)[0])
		if err != nil {
			return nil, err
		}
		auth, address, found := strings.Cut(string(data), "@")
		if index := strings.LastIndexByte(string(data), '@'); index >= 0 {
			auth, address, found = string(data[:index]), string(data[index+1:]), true
		}
		method, password, valid := strings.Cut(auth, ":")
		if !found || !valid {
			return nil, fmt.Errorf("invalid legacy Shadowsocks credentials")
		}
		u := &url.URL{Scheme: "ss", Host: address, User: url.UserPassword(method, password)}
		link = u.String()
	}
	u, err := parseShareURL(link)
	if err != nil {
		return nil, err
	}
	for key := range u.Query() {
		if key != "remarks" {
			return nil, fmt.Errorf("unsupported Shadowsocks option %q (plugins require an external process)", key)
		}
	}
	method := u.User.Username()
	password, present := u.User.Password()
	if !present {
		decoded, err := decodeShareBase64(method)
		if err != nil {
			return nil, err
		}
		method, password, present = strings.Cut(string(decoded), ":")
	}
	if !present || method == "" || password == "" {
		return nil, fmt.Errorf("Shadowsocks method and password are required")
	}
	port, _ := strconv.Atoi(u.Port())
	return map[string]interface{}{"protocol": "shadowsocks", "settings": map[string]interface{}{"servers": []interface{}{map[string]interface{}{
		"address": u.Hostname(), "port": port, "method": method, "password": password,
	}}}}, nil
}

func parseVMessLink(link string) (map[string]interface{}, error) {
	payload := strings.TrimPrefix(link, "vmess://")
	if strings.Contains(strings.SplitN(payload, "#", 2)[0], "@") {
		return parseVMessURL(link)
	}
	data, err := decodeShareBase64(strings.SplitN(payload, "#", 2)[0])
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("VMess payload must be a JSON object")
	}
	values := map[string]string{}
	for key, raw := range fields {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			var number json.Number
			if err := json.Unmarshal(raw, &number); err != nil {
				return nil, fmt.Errorf("VMess field %q must be a string or number", key)
			}
			value = number.String()
		}
		values[key] = value
	}
	allowed := map[string]bool{}
	for _, key := range strings.Fields("v ps add port id aid scy net type host path tls sni alpn fp insecure allowInsecure vcn pcs serviceName authority mode pbk sid") {
		allowed[key] = true
	}
	for key := range fields {
		if !allowed[key] {
			return nil, fmt.Errorf("unsupported VMess field %q", key)
		}
	}
	if values["type"] != "" && values["type"] != "none" {
		return nil, fmt.Errorf("VMess transport header disguise is unsupported")
	}
	if values["add"] == "" || values["id"] == "" {
		return nil, fmt.Errorf("VMess server and ID are required")
	}
	u := &url.URL{Scheme: "vmess", Host: net.JoinHostPort(values["add"], values["port"]), User: url.User(values["id"])}
	q := url.Values{}
	for key, value := range values {
		switch key {
		case "net":
			q.Set("type", value)
		case "tls":
			if value != "" {
				q.Set("security", value)
			}
		case "sni", "alpn", "fp", "insecure", "allowInsecure", "vcn", "pcs", "host", "path", "serviceName", "authority", "mode", "pbk", "sid", "aid", "scy":
			if value != "" {
				q.Set(key, value)
			}
		}
	}
	if values["net"] == "grpc" && q.Get("serviceName") == "" {
		q.Set("serviceName", values["path"])
		q.Del("path")
	}
	u.RawQuery = q.Encode()
	return parseVMessURL(u.String())
}

func parseVMessURL(link string) (map[string]interface{}, error) {
	u, err := parseShareURL(link)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	// Check after JSON conversion so transport aliases and URI links use the
	// same validation instead of silently discarding a required KCP seed.
	if (q.Get("type") == "kcp" || q.Get("type") == "mkcp") && q.Get("path") != "" {
		return nil, fmt.Errorf("VMess KCP seed is unsupported")
	}
	if q.Get("scy") != "" && q.Get("encryption") != "" && q.Get("scy") != q.Get("encryption") {
		return nil, fmt.Errorf("conflicting VMess cipher parameters")
	}
	// Some URI exporters encode cipher:UUID as userinfo instead of using the
	// scy/encryption query parameter. Accept it only when the cipher agrees.
	if identity, present := u.User.Password(); present {
		cipher := u.User.Username()
		if identity == "" || (q.Get("scy") != "" && q.Get("scy") != cipher) || (q.Get("encryption") != "" && q.Get("encryption") != cipher) {
			return nil, fmt.Errorf("conflicting or empty VMess credentials")
		}
		q.Set("scy", cipher)
		u.User = url.User(identity)
		u.RawQuery = q.Encode()
	}
	if aid := q.Get("aid"); aid != "" && aid != "0" {
		return nil, fmt.Errorf("legacy VMess alterId is unsupported; use AEAD (aid=0)")
	}
	cipher := q.Get("scy")
	if cipher == "" {
		cipher = q.Get("encryption")
	}
	if cipher == "" {
		cipher = "auto"
	}
	switch cipher {
	case "auto", "aes-128-gcm", "chacha20-poly1305":
	default:
		return nil, fmt.Errorf("unsupported VMess cipher")
	}
	stream, err := shareStreamSettings(u, "none")
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	return map[string]interface{}{"protocol": "vmess", "streamSettings": stream, "settings": map[string]interface{}{"vnext": []interface{}{map[string]interface{}{
		"address": u.Hostname(), "port": port, "users": []interface{}{map[string]interface{}{"id": u.User.Username(), "security": cipher}},
	}}}}, nil
}
