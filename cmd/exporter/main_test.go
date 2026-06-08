package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.StatusCode)
	}

	body := make([]byte, 2)
	resp.Body.Read(body)
	if string(body) != "OK" {
		t.Errorf("expected body 'OK', got '%s'", string(body))
	}
}

func TestSetupLogger(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		wantLevel slog.Level
	}{
		{
			name:      "default level (info)",
			env:       map[string]string{},
			wantLevel: slog.LevelInfo,
		},
		{
			name:      "debug level via LOG_LEVEL",
			env:       map[string]string{"LOG_LEVEL": "debug"},
			wantLevel: slog.LevelDebug,
		},
		{
			name:      "warn level",
			env:       map[string]string{"LOG_LEVEL": "warn"},
			wantLevel: slog.LevelWarn,
		},
		{
			name:      "error level",
			env:       map[string]string{"LOG_LEVEL": "error"},
			wantLevel: slog.LevelError,
		},
		{
			name:      "warning level (alias)",
			env:       map[string]string{"LOG_LEVEL": "warning"},
			wantLevel: slog.LevelWarn,
		},
		{
			name:      "unknown level falls back to info",
			env:       map[string]string{"LOG_LEVEL": "verbose"},
			wantLevel: slog.LevelInfo,
		},
		{
			name:      "json format",
			env:       map[string]string{"LOG_FORMAT": "json"},
			wantLevel: slog.LevelInfo,
		},
		{
			name:      "deprecated DEBUG=true",
			env:       map[string]string{"DEBUG": "true"},
			wantLevel: slog.LevelDebug,
		},
		{
			name:      "DEBUG=true with LOG_LEVEL set (LOG_LEVEL wins)",
			env:       map[string]string{"DEBUG": "true", "LOG_LEVEL": "error"},
			wantLevel: slog.LevelError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envKeys := []string{"LOG_LEVEL", "LOG_FORMAT", "DEBUG"}
			origVals := make(map[string]string)
			for _, k := range envKeys {
				origVals[k] = os.Getenv(k)
				os.Unsetenv(k)
			}
			defer func() {
				for _, k := range envKeys {
					if origVals[k] == "" {
						os.Unsetenv(k)
					} else {
						os.Setenv(k, origVals[k])
					}
				}
			}()

			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			setupLogger()

			logger := slog.Default()
			ctx := context.Background()
			if !logger.Handler().Enabled(ctx, tt.wantLevel) {
				t.Errorf("expected level %v to be enabled", tt.wantLevel)
			}
			if tt.wantLevel > slog.LevelDebug {
				belowLevel := tt.wantLevel - 4
				if logger.Handler().Enabled(ctx, belowLevel) {
					t.Errorf("expected level %v to be disabled (wantLevel=%v)", belowLevel, tt.wantLevel)
				}
			}
		})
	}
}
