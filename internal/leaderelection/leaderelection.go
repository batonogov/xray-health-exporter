// Package leaderelection provides Kubernetes lease-based leader election for
// xray-health-exporter, ensuring only one replica actively probes tunnels.
package leaderelection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/util/retry"

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
// InClusterConfig). Returns after cancellation, lost leadership, or probe failure.
func RunWithLeaderElection(ctx context.Context, lec *LeaderElectionConfig, configFile string, checker tunnel.HealthChecker, mu tunnel.MetricsUpdater) error {
	metrics.SetLeader(false)
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

	return runLeaderSession(ctx, lec, lock, func(probeCtx context.Context) error {
		return tunnel.RunProbing(probeCtx, configFile, checker, mu)
	}, func(cfg leaderelection.LeaderElectionConfig) (electionRunner, error) {
		return leaderelection.NewLeaderElector(cfg)
	})
}

type electionRunner interface {
	Run(context.Context)
	IsLeader() bool
}

// runLeaderSession owns one election/probing session. The elector renews while
// probes drain on shutdown; automatic release is disabled because client-go's
// OnStartedLeading runs asynchronously and automatic release does not join it.
func runLeaderSession(ctx context.Context, lec *LeaderElectionConfig, lock resourcelock.Interface, probe func(context.Context) error, newElector func(leaderelection.LeaderElectionConfig) (electionRunner, error)) error {
	electionCtx, cancelElection := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelElection()
	probeCtx, cancelProbe := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelProbe()
	var mu sync.Mutex
	var stopped, started bool
	var probeErr error
	probeDone := make(chan struct{})
	stop := func() {
		mu.Lock()
		stopped = true
		metrics.SetLeader(false)
		cancelProbe()
		mu.Unlock()
	}
	join := func() {
		mu.Lock()
		running := started
		mu.Unlock()
		if running {
			<-probeDone
		}
	}
	metrics.SetLeader(false)
	elector, err := newElector(leaderelection.LeaderElectionConfig{
		Lock: lock, ReleaseOnCancel: false,
		LeaseDuration: lec.LeaseDuration, RenewDeadline: lec.RenewDeadline, RetryPeriod: lec.RetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderCtx context.Context) {
				mu.Lock()
				if stopped || ctx.Err() != nil || leaderCtx.Err() != nil {
					mu.Unlock()
					return
				}
				started = true
				metrics.SetLeader(true)
				mu.Unlock()
				slog.Info("acquired leadership, starting probes")
				err := probe(probeCtx)
				if probeCtx.Err() != nil {
					err = nil
				}
				if err == nil && probeCtx.Err() == nil {
					err = errors.New("probing exited unexpectedly while leader")
				}
				mu.Lock()
				probeErr = err
				mu.Unlock()
				stop()
				close(probeDone)
				cancelElection()
			},
			OnStoppedLeading: func() {
				stop()
				join()
				slog.Info("leadership stopped; probes drained")
			},
			OnNewLeader: func(identity string) {
				if identity != lec.Identity {
					slog.Info("new leader elected", "identity", identity)
				}
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create leader elector: %w", err)
	}
	electionDone := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			stop()
			join()
			cancelElection()
		case <-electionDone:
		}
	}()
	slog.Info("leader election enabled", "namespace", lec.Namespace, "name", lec.Name, "identity", lec.Identity)
	elector.Run(electionCtx)
	close(electionDone)
	stop()
	join()
	<-shutdownDone
	// No renewal or probing goroutine can now race the explicit release. Read
	// ownership again so a lost lease is never cleared under a new holder.
	releaseCtx, cancelRelease := context.WithTimeout(context.WithoutCancel(ctx), lec.RenewDeadline)
	defer cancelRelease()
	var releaseErr error
	if elector.IsLeader() {
		releaseErr = releaseLease(releaseCtx, lock)
	}
	mu.Lock()
	result := probeErr
	mu.Unlock()
	if result != nil {
		return errors.Join(fmt.Errorf("probing failed while leader: %w", result), releaseErr)
	}
	if ctx.Err() != nil {
		return releaseErr
	}
	return errors.Join(errors.New("leader election stopped unexpectedly"), releaseErr)
}

func releaseLease(ctx context.Context, lock resourcelock.Interface) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		record, _, err := lock.Get(ctx)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read lease before release: %w", err)
		}
		if record.HolderIdentity != lock.Identity() {
			return nil
		}
		now := metav1.Now()
		err = lock.Update(ctx, resourcelock.LeaderElectionRecord{
			LeaderTransitions:    record.LeaderTransitions,
			LeaseDurationSeconds: 1, AcquireTime: now, RenewTime: now,
		})
		if err != nil {
			return fmt.Errorf("release leader lease: %w", err)
		}
		return nil
	})
}
