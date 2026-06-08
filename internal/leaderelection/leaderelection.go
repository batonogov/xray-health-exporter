// Package leaderelection provides Kubernetes lease-based leader election for
// xray-health-exporter, ensuring only one replica actively probes tunnels.
package leaderelection

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/batonogov/xray-health-exporter/internal/tunnel"
)

// LeaderElectionConfig holds parameters for k8s lease-based leader election.
type LeaderElectionConfig struct {
	Namespace     string
	Name          string
	Identity      string
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

// ServiceAccountNamespacePath is the standard location of the in-pod namespace
// file. Declared as a variable so tests can override it.
var ServiceAccountNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// ReadLeaderElectionConfig reads LEADER_ELECTION_* env vars and returns a
// LeaderElectionConfig if leader election is enabled, or (nil, nil) if disabled.
func ReadLeaderElectionConfig() (*LeaderElectionConfig, error) {
	if os.Getenv("LEADER_ELECTION") != "true" {
		return nil, nil
	}

	namespace := os.Getenv("LEADER_ELECTION_NAMESPACE")
	if namespace == "" {
		if data, err := os.ReadFile(ServiceAccountNamespacePath); err == nil {
			namespace = strings.TrimSpace(string(data))
		}
	}
	if namespace == "" {
		return nil, fmt.Errorf("LEADER_ELECTION_NAMESPACE is required (or run inside a pod)")
	}

	name := os.Getenv("LEADER_ELECTION_NAME")
	if name == "" {
		name = "xray-health-exporter"
	}

	identity := os.Getenv("LEADER_ELECTION_IDENTITY")
	if identity == "" {
		identity = os.Getenv("HOSTNAME")
	}
	if identity == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to determine leader election identity: %v", err)
		}
		identity = hostname
	}

	return &LeaderElectionConfig{
		Namespace:     namespace,
		Name:          name,
		Identity:      identity,
		LeaseDuration: 30 * time.Second,
		RenewDeadline: 20 * time.Second,
		RetryPeriod:   5 * time.Second,
	}, nil
}

// RunWithLeaderElection starts a k8s lease-based leader election and runs
// tunnel.RunProbing only on the leader. Requires running inside a pod (uses
// InClusterConfig). Blocks until ctx is canceled.
func RunWithLeaderElection(ctx context.Context, lec *LeaderElectionConfig, configFile string, checker tunnel.HealthChecker, mu tunnel.MetricsUpdater) error {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to load in-cluster config (LEADER_ELECTION requires running inside a pod): %v", err)
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %v", err)
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      lec.Name,
			Namespace: lec.Namespace,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: lec.Identity,
		},
	}

	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   lec.LeaseDuration,
		RenewDeadline:   lec.RenewDeadline,
		RetryPeriod:     lec.RetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderCtx context.Context) {
				slog.Info("acquired leadership, starting probes")
				metrics.SetLeader(true)
				if err := tunnel.RunProbing(leaderCtx, configFile, checker, mu); err != nil {
					slog.Error("probing error while leader", "error", err)
				}
			},
			OnStoppedLeading: func() {
				// Per-tunnel metrics are cleared inside RunProbing's deferred path;
				// here we only flip the leader gauge so followers report leader=0.
				slog.Info("lost leadership, stopping probes")
				metrics.SetLeader(false)
			},
			OnNewLeader: func(identity string) {
				if identity == lec.Identity {
					return
				}
				slog.Info("new leader elected", "identity", identity)
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create leader elector: %v", err)
	}

	slog.Info("leader election enabled", "namespace", lec.Namespace, "name", lec.Name, "identity", lec.Identity)
	elector.Run(ctx)
	return nil
}
