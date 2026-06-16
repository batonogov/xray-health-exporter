package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler is a stand-in for promhttp.Handler in tests.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("metrics"))
})

// TestBasicAuthCorrectCredentials verifies that valid credentials reach the
// protected handler and return 200.
func TestBasicAuthCorrectCredentials(t *testing.T) {
	h := basicAuthMiddleware("metricsUser", "s3cret", okHandler)

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.SetBasicAuth("metricsUser", "s3cret")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with correct credentials, got %d", resp.StatusCode)
	}
}

// TestBasicAuthWrongCredentials verifies that incorrect credentials return 401
// with the WWW-Authenticate header set.
func TestBasicAuthWrongCredentials(t *testing.T) {
	h := basicAuthMiddleware("metricsUser", "s3cret", okHandler)

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.SetBasicAuth("metricsUser", "wrong")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong credentials, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="metrics"` {
		t.Fatalf("expected WWW-Authenticate header, got %q", got)
	}
}

// TestBasicAuthMissingHeader verifies that a request without an Authorization
// header returns 401 with the WWW-Authenticate header set.
func TestBasicAuthMissingHeader(t *testing.T) {
	h := basicAuthMiddleware("metricsUser", "s3cret", okHandler)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without Authorization header, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="metrics"` {
		t.Fatalf("expected WWW-Authenticate header, got %q", got)
	}
}

// TestBasicAuthWrongUser verifies that a wrong username returns 401.
func TestBasicAuthWrongUser(t *testing.T) {
	h := basicAuthMiddleware("metricsUser", "s3cret", okHandler)

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.SetBasicAuth("admin", "s3cret")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong username, got %d", resp.StatusCode)
	}
}

// TestHealthAlwaysUnprotected verifies that the /health handler is reachable
// even when /metrics is protected: building a mux exactly as main() does, the
// health handler must not be wrapped by the auth middleware.
func TestHealthAlwaysUnprotected(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", basicAuthMiddleware("metricsUser", "s3cret", okHandler))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	req := httptest.NewRequest("GET", "/health", nil)
	// Deliberately no Authorization header.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected /health to always return 200, got %d", resp.StatusCode)
	}
}
