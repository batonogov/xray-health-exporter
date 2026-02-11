package tunnel

import (
	"testing"
)

func TestParseVLESSURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		want    *VLESSConfig
	}{
		{
			name: "valid vless url with reality",
			url:  "vless://uuid-123@example.com:443?type=tcp&security=reality&pbk=test-key&sni=google.com&sid=short123&spx=/&fp=chrome",
			want: &VLESSConfig{
				UUID:     "uuid-123",
				Address:  "example.com",
				Port:     443,
				Type:     "tcp",
				Security: "reality",
				PBK:      "test-key",
				SNI:      "google.com",
				SID:      "short123",
				SPX:      "/",
				FP:       "chrome",
			},
			wantErr: false,
		},
		{
			name: "valid vless url with tls",
			url:  "vless://uuid-456@server.net:8443?type=ws&security=tls&sni=server.net&fp=firefox",
			want: &VLESSConfig{
				UUID:     "uuid-456",
				Address:  "server.net",
				Port:     8443,
				Type:     "ws",
				Security: "tls",
				SNI:      "server.net",
				FP:       "firefox",
			},
			wantErr: false,
		},
		{
			name:    "invalid protocol",
			url:     "http://example.com",
			wantErr: true,
		},
		{
			name:    "invalid port",
			url:     "vless://uuid@example.com:invalid?type=tcp",
			wantErr: true,
		},
		{
			name:    "empty url",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVLESSURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVLESSURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.UUID != tt.want.UUID {
					t.Errorf("UUID = %v, want %v", got.UUID, tt.want.UUID)
				}
				if got.Address != tt.want.Address {
					t.Errorf("Address = %v, want %v", got.Address, tt.want.Address)
				}
				if got.Port != tt.want.Port {
					t.Errorf("Port = %v, want %v", got.Port, tt.want.Port)
				}
				if got.Security != tt.want.Security {
					t.Errorf("Security = %v, want %v", got.Security, tt.want.Security)
				}
				if got.Type != tt.want.Type {
					t.Errorf("Type = %v, want %v", got.Type, tt.want.Type)
				}
			}
		})
	}
}
