package socks

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Dialer implements a SOCKS5 dialer.
type Dialer struct {
	ProxyAddr string
	Timeout   time.Duration
}

// NewDialer creates a new SOCKS5 dialer.
func NewDialer(proxyAddr string, timeout time.Duration) *Dialer {
	return &Dialer{
		ProxyAddr: proxyAddr,
		Timeout:   timeout,
	}
}

// DialContext connects to the target address through a SOCKS5 proxy.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", d.ProxyAddr, d.Timeout)
	if err != nil {
		return nil, err
	}

	// Set deadline from context if available
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to set deadline: %w", err)
		}
	}

	// SOCKS5 handshake: [VER, NMETHODS, METHODS]
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Read response: [VER, METHOD]
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if buf[0] != 5 || buf[1] != 0 { //nolint:gosec // length guaranteed by io.ReadFull above
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Send CONNECT request
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Read response
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if resp[1] != 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: %d", resp[1])
	}

	// Read remaining response (address and port)
	switch resp[3] {
	case 1: // IPv4
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil { //nolint:gosec // lenBuf is a single byte from trusted SOCKS5 server
			_ = conn.Close()
			return nil, err
		}
	case 4: // IPv6
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	// Clear deadline after handshake
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to clear deadline: %w", err)
	}

	return conn, nil
}
