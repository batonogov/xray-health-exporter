// Package socks provides a SOCKS5 dialer for tunneling connections through
// an Xray SOCKS5 inbound.
package socks

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// SOCKS5Dialer implements a minimal SOCKS5 client that connects through a
// given SOCKS5 proxy address.
type SOCKS5Dialer struct {
	ProxyAddr string
	Timeout   time.Duration
}

// NewSOCKS5Dialer creates a SOCKS5 dialer for the given proxy address and timeout.
func NewSOCKS5Dialer(proxyAddr string, timeout time.Duration) *SOCKS5Dialer {
	return &SOCKS5Dialer{
		ProxyAddr: proxyAddr,
		Timeout:   timeout,
	}
}

// DialContext connects to addr through the SOCKS5 proxy, respecting the
// cancellation and deadline of ctx.
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Connect to SOCKS5 proxy
	conn, err := net.DialTimeout("tcp", d.ProxyAddr, d.Timeout)
	if err != nil {
		return nil, err
	}

	// SOCKS5 handshake: [VER, NMETHODS, METHODS]
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response: [VER, METHOD]
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		conn.Close()
		return nil, err
	}

	if buf[0] != 5 || buf[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed")
	}

	// Parse target address
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

	// Send CONNECT request
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response
	resp := make([]byte, 4)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: %d", resp[1])
	}

	// Read remaining response (bound address and port)
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
