package socks

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewDialer(t *testing.T) {
	dialer := NewDialer("127.0.0.1:1080", 30*time.Second)
	if dialer == nil {
		t.Fatal("NewDialer() returned nil")
	}
	if dialer.ProxyAddr != "127.0.0.1:1080" {
		t.Errorf("ProxyAddr = %v, want 127.0.0.1:1080", dialer.ProxyAddr)
	}
}

func TestDialContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	socksAddr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				buf := make([]byte, 3)
				if _, err := c.Read(buf); err != nil {
					return
				}

				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}

				req := make([]byte, 4)
				if _, err := c.Read(req); err != nil {
					return
				}

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				response := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
				if _, err := c.Write(response); err != nil {
					return
				}

				time.Sleep(100 * time.Millisecond)
			}(conn)
		}
	}()

	dialer := NewDialer(socksAddr, 5*time.Second)

	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()

	if conn == nil {
		t.Error("DialContext() returned nil connection")
	}
}

func TestDialContext_WithDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	socksAddr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				buf := make([]byte, 3)
				if _, err := c.Read(buf); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}

				req := make([]byte, 4)
				if _, err := c.Read(req); err != nil {
					return
				}

				switch req[3] {
				case 1:
					c.Read(make([]byte, 4+2))
				case 3:
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4:
					c.Read(make([]byte, 16+2))
				}

				response := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
				if _, err := c.Write(response); err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}(conn)
		}
	}()

	dialer := NewDialer(socksAddr, 5*time.Second)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() with deadline error = %v", err)
	}
	defer conn.Close()
}

func TestDialContextErrors(t *testing.T) {
	t.Run("proxy connection failed", func(t *testing.T) {
		dialer := NewDialer("127.0.0.1:9999", 1*time.Second)
		ctx := context.Background()
		_, err := dialer.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected error for nonexistent proxy")
		}
	})

	t.Run("invalid destination address", func(t *testing.T) {
		dialer := NewDialer("127.0.0.1:1080", 1*time.Second)
		ctx := context.Background()
		_, err := dialer.DialContext(ctx, "tcp", "invalid-address")
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})
}

func TestDialContext_HandshakeErrors(t *testing.T) {
	t.Run("invalid socks version in response", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		socksAddr := listener.Addr().String()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 3)
			conn.Read(buf)
			conn.Write([]byte{4, 0})
		}()

		dialer := NewDialer(socksAddr, 5*time.Second)
		ctx := context.Background()
		_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected error for invalid SOCKS version")
		}
	})

	t.Run("write error during handshake", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		socksAddr := listener.Addr().String()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}()

		time.Sleep(100 * time.Millisecond)

		dialer := NewDialer(socksAddr, 5*time.Second)
		ctx := context.Background()
		_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected error for closed connection")
		}
	})

	t.Run("read error during handshake", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		socksAddr := listener.Addr().String()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 3)
			conn.Read(buf)
		}()

		dialer := NewDialer(socksAddr, 1*time.Second)
		ctx := context.Background()
		_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected error for incomplete handshake")
		}
	})

	t.Run("connect failure", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		socksAddr := listener.Addr().String()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 3)
			conn.Read(buf)
			conn.Write([]byte{5, 0})

			req := make([]byte, 4)
			conn.Read(req)

			switch req[3] {
			case 1:
				conn.Read(make([]byte, 4+2))
			case 3:
				lenBuf := make([]byte, 1)
				conn.Read(lenBuf)
				conn.Read(make([]byte, int(lenBuf[0])+2))
			case 4:
				conn.Read(make([]byte, 16+2))
			}

			conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		}()

		dialer := NewDialer(socksAddr, 5*time.Second)
		ctx := context.Background()
		_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected error for connection refused")
		}
	})

	t.Run("IPv4 address response", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		socksAddr := listener.Addr().String()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 3)
			conn.Read(buf)
			conn.Write([]byte{5, 0})

			req := make([]byte, 4)
			conn.Read(req)

			switch req[3] {
			case 1:
				conn.Read(make([]byte, 4+2))
			case 3:
				lenBuf := make([]byte, 1)
				conn.Read(lenBuf)
				conn.Read(make([]byte, int(lenBuf[0])+2))
			case 4:
				conn.Read(make([]byte, 16+2))
			}

			response := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}
			conn.Write(response)
			time.Sleep(100 * time.Millisecond)
		}()

		dialer := NewDialer(socksAddr, 5*time.Second)
		ctx := context.Background()
		conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
		if err != nil {
			t.Fatalf("DialContext() error = %v", err)
		}
		defer conn.Close()
	})

	t.Run("IPv6 address response", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		socksAddr := listener.Addr().String()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 3)
			conn.Read(buf)
			conn.Write([]byte{5, 0})

			req := make([]byte, 4)
			conn.Read(req)

			switch req[3] {
			case 1:
				conn.Read(make([]byte, 4+2))
			case 3:
				lenBuf := make([]byte, 1)
				conn.Read(lenBuf)
				conn.Read(make([]byte, int(lenBuf[0])+2))
			case 4:
				conn.Read(make([]byte, 16+2))
			}

			response := []byte{5, 0, 0, 4}
			response = append(response, make([]byte, 16)...)
			response = append(response, 0, 80)
			conn.Write(response)
			time.Sleep(100 * time.Millisecond)
		}()

		dialer := NewDialer(socksAddr, 5*time.Second)
		ctx := context.Background()
		conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
		if err != nil {
			t.Fatalf("DialContext() error = %v", err)
		}
		defer conn.Close()
	})
}
