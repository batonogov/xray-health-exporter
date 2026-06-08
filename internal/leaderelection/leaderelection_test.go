package leaderelection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLeaderElectionConfig(t *testing.T) {
	origPath := ServiceAccountNamespacePath
	t.Cleanup(func() { ServiceAccountNamespacePath = origPath })

	leaderEnv := []string{
		"LEADER_ELECTION",
		"LEADER_ELECTION_NAMESPACE",
		"LEADER_ELECTION_NAME",
		"LEADER_ELECTION_IDENTITY",
		"HOSTNAME",
	}

	tests := []struct {
		name          string
		env           map[string]string
		namespaceFile string
		wantNil       bool
		wantErr       bool
		wantNs        string
		wantLease     string
		wantIdent     string
		identityFn    func() string
	}{
		{
			name:    "disabled by default",
			env:     map[string]string{},
			wantNil: true,
		},
		{
			name:    "disabled when LEADER_ELECTION is not 'true'",
			env:     map[string]string{"LEADER_ELECTION": "false"},
			wantNil: true,
		},
		{
			name:    "disabled when LEADER_ELECTION is '1'",
			env:     map[string]string{"LEADER_ELECTION": "1"},
			wantNil: true,
		},
		{
			name: "enabled with all env vars",
			env: map[string]string{
				"LEADER_ELECTION":           "true",
				"LEADER_ELECTION_NAMESPACE": "monitoring",
				"LEADER_ELECTION_NAME":      "custom-lease",
				"LEADER_ELECTION_IDENTITY":  "pod-a",
			},
			wantNs:    "monitoring",
			wantLease: "custom-lease",
			wantIdent: "pod-a",
		},
		{
			name: "default lease name when only namespace set",
			env: map[string]string{
				"LEADER_ELECTION":           "true",
				"LEADER_ELECTION_NAMESPACE": "monitoring",
				"LEADER_ELECTION_IDENTITY":  "pod-a",
			},
			wantNs:    "monitoring",
			wantLease: "xray-health-exporter",
			wantIdent: "pod-a",
		},
		{
			name: "namespace falls back to service-account file",
			env: map[string]string{
				"LEADER_ELECTION":          "true",
				"LEADER_ELECTION_IDENTITY": "pod-a",
			},
			namespaceFile: "monitoring-from-file\n",
			wantNs:        "monitoring-from-file",
			wantLease:     "xray-health-exporter",
			wantIdent:     "pod-a",
		},
		{
			name: "identity falls back to HOSTNAME",
			env: map[string]string{
				"LEADER_ELECTION":           "true",
				"LEADER_ELECTION_NAMESPACE": "monitoring",
				"HOSTNAME":                  "host-from-env",
			},
			wantNs:    "monitoring",
			wantLease: "xray-health-exporter",
			wantIdent: "host-from-env",
		},
		{
			name: "identity falls back to os.Hostname when HOSTNAME unset",
			env: map[string]string{
				"LEADER_ELECTION":           "true",
				"LEADER_ELECTION_NAMESPACE": "monitoring",
			},
			wantNs:    "monitoring",
			wantLease: "xray-health-exporter",
			identityFn: func() string {
				h, _ := os.Hostname()
				return h
			},
		},
		{
			name: "missing namespace returns error",
			env: map[string]string{
				"LEADER_ELECTION":          "true",
				"LEADER_ELECTION_IDENTITY": "pod-a",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range leaderEnv {
				t.Setenv(k, "")
				os.Unsetenv(k)
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			if tt.namespaceFile != "" {
				path := filepath.Join(t.TempDir(), "namespace")
				if err := os.WriteFile(path, []byte(tt.namespaceFile), 0644); err != nil {
					t.Fatalf("write namespace file: %v", err)
				}
				ServiceAccountNamespacePath = path
			} else {
				ServiceAccountNamespacePath = filepath.Join(t.TempDir(), "does-not-exist")
			}

			got, err := ReadLeaderElectionConfig()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil config, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected non-nil config")
			}
			if got.Namespace != tt.wantNs {
				t.Errorf("Namespace = %q, want %q", got.Namespace, tt.wantNs)
			}
			if got.Name != tt.wantLease {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantLease)
			}
			wantIdent := tt.wantIdent
			if tt.identityFn != nil {
				wantIdent = tt.identityFn()
			}
			if got.Identity != wantIdent {
				t.Errorf("Identity = %q, want %q", got.Identity, wantIdent)
			}
			if got.LeaseDuration <= got.RenewDeadline {
				t.Errorf("LeaseDuration (%v) must be greater than RenewDeadline (%v)", got.LeaseDuration, got.RenewDeadline)
			}
			if got.RenewDeadline <= got.RetryPeriod {
				t.Errorf("RenewDeadline (%v) must be greater than RetryPeriod (%v)", got.RenewDeadline, got.RetryPeriod)
			}
		})
	}
}
