package socks

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSOCKS5Dialer(t *testing.T) {
	dialer := NewSOCKS5Dialer("127.0.0.1:1080", 30)
	if dialer == nil {
		t.Fatal("NewSOCKS5Dialer() returned nil")
	}
	if dialer.ProxyAddr != "127.0.0.1:1080" {
		t.Errorf("ProxyAddr = %v, want 127.0.0.1:1080", dialer.ProxyAddr)
	}
}

func TestSOCKS5DialContext(t *testing.T) {
	// Создаем mock SOCKS5 сервер
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	socksAddr := listener.Addr().String()

	// Запускаем mock SOCKS5 сервер в горутине
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				// Читаем SOCKS5 handshake [VER, NMETHODS, METHODS]
				buf := make([]byte, 3)
				if _, err := c.Read(buf); err != nil {
					return
				}

				// Отвечаем [VER, METHOD]
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}

				// Читаем CONNECT request (минимум 4 байта)
				req := make([]byte, 4)
				if _, err := c.Read(req); err != nil {
					return
				}

				// Читаем оставшуюся часть запроса в зависимости от типа адреса
				switch req[3] {
				case 1: // IPv4
					c.Read(make([]byte, 4+2))
				case 3: // Domain
					lenBuf := make([]byte, 1)
					c.Read(lenBuf)
					c.Read(make([]byte, int(lenBuf[0])+2))
				case 4: // IPv6
					c.Read(make([]byte, 16+2))
				}

				// Отвечаем успехом: [VER, REP, RSV, ATYP, BIND.ADDR, BIND.PORT]
				response := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
				if _, err := c.Write(response); err != nil {
					return
				}

				// Теперь соединение установлено, можно передавать данные
				time.Sleep(100 * time.Millisecond)
			}(conn)
		}
	}()

	// Тестируем диалер
	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)

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

func TestSOCKS5DialContextErrors(t *testing.T) {
	// Тест с несуществующим прокси
	t.Run("proxy connection failed", func(t *testing.T) {
		dialer := NewSOCKS5Dialer("127.0.0.1:9999", 1*time.Second)
		ctx := context.Background()
		_, err := dialer.DialContext(ctx, "tcp", "example.com:80")
		if err == nil {
			t.Error("expected error for nonexistent proxy")
		}
	})

	// Тест с невалидным адресом назначения
	t.Run("invalid destination address", func(t *testing.T) {
		dialer := NewSOCKS5Dialer("127.0.0.1:1080", 1*time.Second)
		ctx := context.Background()
		_, err := dialer.DialContext(ctx, "tcp", "invalid-address")
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})
}

func TestSOCKS5DialContext_HandshakeErrors(t *testing.T) {
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

			// Read handshake
			buf := make([]byte, 3)
			conn.Read(buf)

			// Respond with wrong version
			conn.Write([]byte{4, 0})
		}()

		dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
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
			// Close immediately to cause write error
			conn.Close()
		}()

		time.Sleep(100 * time.Millisecond)

		dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
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

			// Read handshake but don't respond
			buf := make([]byte, 3)
			conn.Read(buf)
			// Close without responding
		}()

		dialer := NewSOCKS5Dialer(socksAddr, 1*time.Second)
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

			// SOCKS5 handshake
			buf := make([]byte, 3)
			conn.Read(buf)
			conn.Write([]byte{5, 0})

			// Read CONNECT request
			req := make([]byte, 4)
			conn.Read(req)

			// Read address
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

			// Respond with connection refused
			conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		}()

		dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
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

			// Response with IPv4 address type
			response := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}
			conn.Write(response)
			time.Sleep(100 * time.Millisecond)
		}()

		dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
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

			// Response with IPv6 address type (4)
			response := []byte{5, 0, 0, 4}
			response = append(response, make([]byte, 16)...) // IPv6 address
			response = append(response, 0, 80)               // Port
			conn.Write(response)
			time.Sleep(100 * time.Millisecond)
		}()

		dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
		ctx := context.Background()
		conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
		if err != nil {
			t.Fatalf("DialContext() error = %v", err)
		}
		defer conn.Close()
	})
}

func TestDialContext_WriteErrorDuringConnect(t *testing.T) {
	// Server that closes after handshake, causing write error during CONNECT
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

		// Read handshake
		buf := make([]byte, 3)
		conn.Read(buf)
		// Respond with valid handshake
		conn.Write([]byte{5, 0})

		// Read first 4 bytes of CONNECT request
		req := make([]byte, 4)
		conn.Read(req)

		// Read address bytes based on type
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

		// Close connection to cause write error on client's next write
	}()

	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error from DialContext due to server closing connection")
	}
}

func TestDialContext_ReadErrorResponseDomain(t *testing.T) {
	// Server responds with domain address type (ATYP=3) in CONNECT response
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

		// Response with domain address type (ATYP=3)
		domain := "bind.example.com"
		response := []byte{5, 0, 0, 3, byte(len(domain))}
		response = append(response, []byte(domain)...)
		response = append(response, 0, 80)
		conn.Write(response)
		time.Sleep(200 * time.Millisecond)
	}()

	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	conn.Close()
}

func TestDialContext_InvalidPort(t *testing.T) {
	// Server that does valid handshake but destination has invalid port
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
		// Read and discard
		time.Sleep(200 * time.Millisecond)
	}()

	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
	ctx := context.Background()
	// Pass address with non-numeric port
	_, err = dialer.DialContext(ctx, "tcp", "example.com:notaport")
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestDialContext_ResponseReadError(t *testing.T) {
	// Server that closes after sending CONNECT request, before response
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

		// Close without sending response
	}()

	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error when server closes before CONNECT response")
	}
}

func TestDialContext_IPv4ResponseReadError(t *testing.T) {
	// Server sends partial CONNECT response (only header, then closes during IPv4 read)
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

		// Send header indicating IPv4 response but close before full response
		conn.Write([]byte{5, 0, 0, 1})
		// Don't send the remaining 6 bytes for IPv4 + port
	}()

	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error when IPv4 response is incomplete")
	}
}

func TestDialContext_IPv6ResponseReadError(t *testing.T) {
	// Server sends partial CONNECT response (only header, then closes during IPv6 read)
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

		// Send header indicating IPv6 response but close before full response
		conn.Write([]byte{5, 0, 0, 4})
	}()

	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error when IPv6 response is incomplete")
	}
}

func TestDialContext_DomainResponseReadError(t *testing.T) {
	// Server sends CONNECT response header with domain type, then closes during domain read
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

		// Send header indicating domain response but close during domain read
		conn.Write([]byte{5, 0, 0, 3, 10}) // domain length = 10
		// Don't send the domain bytes + port
	}()

	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error when domain response is incomplete")
	}
}

func TestDialContext_DomainLenThenClose(t *testing.T) {
	// Server sends domain length byte but then immediately closes
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

		// Send CONNECT reply header with ATYP=3 (domain), and domain length = 255
		// Then close immediately. Client will try to read 257 bytes (255+2) and get EOF.
		conn.Write([]byte{5, 0, 0, 3, 255})
		// Close happens via defer - client's Read will get io.EOF
	}()

	dialer := NewSOCKS5Dialer(socksAddr, 5*time.Second)
	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error for partial domain response")
	}
}
