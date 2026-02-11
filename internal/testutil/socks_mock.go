package testutil

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// MockSOCKS5Options configures the mock SOCKS5 server behavior.
type MockSOCKS5Options struct {
	HTTPStatus     int
	HTTPBody       string
	SOCKSReplyCode byte
	ResponseDelay  time.Duration
	RawResponse    []byte
}

// MockOption is a functional option for StartMockSOCKS5.
type MockOption func(*MockSOCKS5Options)

// WithHTTPResponse sets the HTTP status and body the mock will return.
func WithHTTPResponse(status int, body string) MockOption {
	return func(o *MockSOCKS5Options) {
		o.HTTPStatus = status
		o.HTTPBody = body
	}
}

// WithSOCKSReplyCode makes the SOCKS5 server respond with a non-zero reply code.
func WithSOCKSReplyCode(code byte) MockOption {
	return func(o *MockSOCKS5Options) {
		o.SOCKSReplyCode = code
	}
}

// WithResponseDelay adds a delay after the SOCKS handshake, before sending the response.
func WithResponseDelay(d time.Duration) MockOption {
	return func(o *MockSOCKS5Options) {
		o.ResponseDelay = d
	}
}

// WithRawResponse sends raw bytes after the SOCKS handshake instead of an HTTP response.
func WithRawResponse(data []byte) MockOption {
	return func(o *MockSOCKS5Options) {
		o.RawResponse = data
	}
}

// StartMockSOCKS5 starts a mock SOCKS5 server and returns the port and cleanup function.
func StartMockSOCKS5(t *testing.T, opts ...MockOption) (int, func()) {
	t.Helper()

	options := &MockSOCKS5Options{
		HTTPStatus: 200,
		HTTPBody:   "OK",
	}
	for _, opt := range opts {
		opt(options)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create SOCKS listener: %v", err)
	}

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go handleMockConnection(conn, options)
		}
	}()

	return port, func() { _ = listener.Close() }
}

func handleMockConnection(c net.Conn, opts *MockSOCKS5Options) {
	defer func() { _ = c.Close() }()

	// SOCKS5 handshake
	buf := make([]byte, 3)
	if _, err := c.Read(buf); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0})

	// CONNECT request
	req := make([]byte, 4)
	if _, err := c.Read(req); err != nil {
		return
	}

	// Read address
	switch req[3] {
	case 1: // IPv4
		_, _ = c.Read(make([]byte, 4+2))
	case 3: // Domain
		lenBuf := make([]byte, 1)
		_, _ = c.Read(lenBuf)
		_, _ = c.Read(make([]byte, int(lenBuf[0])+2)) //nolint:gosec // mock server, lenBuf is a single byte
	case 4: // IPv6
		_, _ = c.Read(make([]byte, 16+2))
	}

	if opts.SOCKSReplyCode != 0 {
		_, _ = c.Write([]byte{5, opts.SOCKSReplyCode, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	// Success response
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	if opts.ResponseDelay > 0 {
		time.Sleep(opts.ResponseDelay)
	}

	if opts.RawResponse != nil {
		_, _ = c.Write(opts.RawResponse)
		return
	}

	// Wait for the HTTP request before responding to avoid
	// "readLoopPeekFailLocked" errors in Go's HTTP transport.
	reqBuf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Read(reqBuf)
	_ = c.SetReadDeadline(time.Time{})

	// Send HTTP response
	body := opts.HTTPBody
	statusText := http.StatusText(opts.HTTPStatus)
	httpResponse := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		opts.HTTPStatus, statusText, len(body), body)
	_, _ = c.Write([]byte(httpResponse))
}
