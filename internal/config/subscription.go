package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxSubscriptionBytes = 10 * 1024 * 1024

func validateSubscription(sub Subscription) error {
	u, err := url.Parse(sub.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("url must be an absolute HTTP or HTTPS URL")
	}
	if sub.UpdateInterval != "" {
		if d, err := time.ParseDuration(sub.UpdateInterval); err != nil || d <= 0 {
			return errors.New("update_interval must be a positive duration")
		}
	}
	if sub.Timeout != "" {
		if d, err := time.ParseDuration(sub.Timeout); err != nil || d <= 0 {
			return errors.New("timeout must be a positive duration")
		}
	}
	switch sub.Format {
	case "", "auto", "text", "xray", "clash":
	default:
		return errors.New("format must be auto, text, xray, or clash")
	}
	return nil
}

// FetchSubscription retains the original URL-only API. New callers should use
// FetchSubscriptionContext to configure the request and propagate cancellation.
func FetchSubscription(subURL string) ([]Tunnel, error) {
	return fetchSubscription(context.Background(), Subscription{URL: subURL}, true)
}

// FetchSubscriptionContext retrieves and parses a complete subscription. Empty,
// malformed, and oversized responses are errors, so callers can retain old state.
func FetchSubscriptionContext(ctx context.Context, sub Subscription) ([]Tunnel, error) {
	return fetchSubscription(ctx, sub, false)
}

func fetchSubscription(ctx context.Context, sub Subscription, allowEmpty bool) ([]Tunnel, error) {
	if err := validateSubscription(sub); err != nil {
		return nil, err
	}
	timeout := 30 * time.Second
	if sub.Timeout != "" {
		timeout, _ = time.ParseDuration(sub.Timeout)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return nil, errors.New("invalid subscription request")
	}
	for name, value := range sub.Headers {
		req.Header.Set(name, value)
		if strings.EqualFold(name, "Host") {
			req.Host = value
		}
	}
	if sub.UserAgent != "" {
		req.Header.Set("User-Agent", sub.UserAgent)
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		// Custom headers may contain credentials. Do not forward them to another origin.
		if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host) {
			for name := range sub.Headers {
				req.Header.Del(name)
			}
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.Host = ""
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		// net/http errors contain the full URL (often including a subscription token).
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var timeoutErr interface{ Timeout() bool }
		if errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
			return nil, errors.New("subscription request timed out")
		}
		return nil, errors.New("subscription request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("failed to read subscription response")
	}
	if len(body) > maxSubscriptionBytes {
		return nil, errors.New("subscription exceeds 10 MiB limit")
	}
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	if len(body) == 0 && allowEmpty {
		return nil, nil
	}
	return parseSubscription(body, sub.Format)
}

// ResolveSubscriptionsContext returns successful sources alongside an aggregate
// error. Callers must not replace old source state when a fetch fails.
func ResolveSubscriptionsContext(ctx context.Context, cfg *Config) ([]Tunnel, error) {
	var all []Tunnel
	var errs []error
	for i, sub := range cfg.Subscriptions {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		tunnels, err := FetchSubscriptionContext(ctx, sub)
		if err != nil {
			errs = append(errs, fmt.Errorf("subscription %d: %w", i, err))
			continue
		}
		for j := range tunnels {
			ApplyTunnelDefaults(&tunnels[j], cfg.Defaults)
		}
		all = append(all, tunnels...)
	}
	return all, errors.Join(errs...)
}

// ResolveSubscriptions is the legacy best-effort resolver.
func ResolveSubscriptions(cfg *Config) []Tunnel {
	tunnels, err := ResolveSubscriptionsContext(context.Background(), cfg)
	if err != nil {
		slog.Error("failed to resolve subscriptions", "error", err)
	}
	return tunnels
}

func decodeSubscriptionBase64(content string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := encoding.DecodeString(content); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func parseSubscription(body []byte, format string) ([]Tunnel, error) {
	if len(body) == 0 {
		return nil, errors.New("empty subscription response")
	}
	if format == "" || format == "auto" {
		if decoded, err := decodeSubscriptionBase64(string(body)); err == nil {
			body = bytes.TrimSpace(decoded)
		}
		if len(body) == 0 {
			return nil, errors.New("empty subscription response")
		}
		var object map[string]json.RawMessage
		if body[0] == '{' && json.Unmarshal(body, &object) == nil {
			if _, ok := object["proxies"]; ok {
				return parseClashSubscription(body)
			}
		}
		switch {
		case body[0] == '{' || body[0] == '[':
			format = "xray"
		case bytes.Contains(body, []byte("proxies:")):
			format = "clash"
		default:
			format = "text"
		}
	}
	switch format {
	case "xray":
		return parseXraySubscription(body)
	case "clash":
		return parseClashSubscription(body)
	case "text":
		return parseTextSubscription(body)
	default:
		return nil, errors.New("unsupported subscription format")
	}
}

func parseTextSubscription(body []byte) ([]Tunnel, error) {
	content := strings.TrimSpace(string(body))
	if decoded, err := decodeSubscriptionBase64(content); err == nil {
		content = strings.TrimSpace(string(decoded))
	}
	var tunnels []Tunnel
	seen := make(map[string]bool)
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Scheme == "" {
			return nil, fmt.Errorf("invalid subscription entry on line %d", i+1)
		}
		switch u.Scheme {
		case "vless", "vmess", "trojan", "ss":
		default:
			return nil, fmt.Errorf("unsupported subscription protocol on line %d", i+1)
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		name := u.Fragment
		if name == "" && u.Scheme == "vmess" {
			if decoded, err := decodeSubscriptionBase64(strings.TrimPrefix(line, "vmess://")); err == nil {
				var vmess struct {
					Name string `json:"ps"`
					Host string `json:"add"`
				}
				if json.Unmarshal(decoded, &vmess) == nil {
					name = vmess.Name
					if name == "" {
						name = vmess.Host
					}
				}
			}
		}
		if name == "" && u.Scheme == "ss" && u.User == nil {
			payload := strings.SplitN(strings.TrimPrefix(line, "ss://"), "#", 2)[0]
			if decoded, err := decodeSubscriptionBase64(payload); err == nil {
				if decodedURL, err := url.Parse("ss://" + string(decoded)); err == nil && decodedURL.User != nil {
					name = decodedURL.Host
				}
			}
		} else if name == "" && u.Scheme != "vmess" {
			name = u.Host
		}
		if name == "" {
			sum := sha256.Sum256([]byte(line))
			name = fmt.Sprintf("server-%x", sum[:6])
		}
		tunnels = append(tunnels, Tunnel{Name: name, URL: line})
	}
	if len(tunnels) == 0 {
		return nil, errors.New("subscription contains no supported servers")
	}
	return tunnels, nil
}

func parseXraySubscription(body []byte) ([]Tunnel, error) {
	var configs []json.RawMessage
	if len(bytes.TrimSpace(body)) > 0 && bytes.TrimSpace(body)[0] == '[' {
		if json.Unmarshal(body, &configs) != nil {
			return nil, errors.New("invalid Xray JSON subscription")
		}
	} else {
		configs = []json.RawMessage{body}
	}
	if len(configs) == 0 {
		return nil, errors.New("Xray subscription contains no configs")
	}
	var tunnels []Tunnel
	for i, raw := range configs {
		var cfg map[string]json.RawMessage
		if json.Unmarshal(raw, &cfg) != nil || cfg == nil {
			return nil, fmt.Errorf("invalid Xray config at index %d", i)
		}
		var outbounds []json.RawMessage
		if json.Unmarshal(cfg["outbounds"], &outbounds) != nil || len(outbounds) == 0 {
			return nil, fmt.Errorf("Xray config %d requires nonempty outbounds", i)
		}
		var name string
		_ = json.Unmarshal(cfg["remarks"], &name)
		if name == "" {
			_ = json.Unmarshal(cfg["name"], &name)
		}
		if name == "" {
			sum := sha256.Sum256(raw)
			name = fmt.Sprintf("xray-%x", sum[:6])
		}
		tunnels = append(tunnels, Tunnel{Name: name, XrayConfigJSON: append(json.RawMessage(nil), raw...)})
	}
	return tunnels, nil
}
