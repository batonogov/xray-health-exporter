package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMainExitsNonzeroAfterProbeFailure(t *testing.T) {
	if os.Getenv("XRAY_TEST_FAILURE_CHILD") == "true" {
		main()
		return
	}
	ip := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.1")) }))
	defer ip.Close()
	t.Setenv("XRAY_TEST_FAILURE_CHILD", "true")
	t.Setenv("RUN_ONCE", "false")
	t.Setenv("LEADER_ELECTION", "false")
	t.Setenv("METRICS_PROTECTED", "false")
	t.Setenv("METRICS_PUSH_URL", "")
	t.Setenv("CONFIG_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("IP_CHECK_URL", ip.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainExitsNonzeroAfterProbeFailure$")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("process failed to shut down: %s", output)
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		t.Fatalf("exit=%v, want1; output=%s", err, output)
	}
}
