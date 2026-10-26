package leaderelection

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/batonogov/xray-health-exporter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kle "k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

type sessionElector func(context.Context)

func (f sessionElector) Run(ctx context.Context) { f(ctx) }
func (sessionElector) IsLeader() bool            { return true }

type sessionLock struct {
	mu            sync.Mutex
	record        resourcelock.LeaderElectionRecord
	updates       int
	reads         int
	updateFailure error
	beforeRelease func()
}

func (l *sessionLock) Get(context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reads++
	r := l.record
	return &r, nil, nil
}
func (l *sessionLock) Create(_ context.Context, r resourcelock.LeaderElectionRecord) error {
	return l.Update(context.Background(), r)
}
func (l *sessionLock) Update(_ context.Context, r resourcelock.LeaderElectionRecord) error {
	if l.beforeRelease != nil {
		l.beforeRelease()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.updateFailure != nil {
		err := l.updateFailure
		l.updateFailure = nil
		return err
	}
	l.record = r
	l.updates++
	return nil
}
func (*sessionLock) RecordEvent(string) {}
func (*sessionLock) Identity() string   { return "test-pod" }
func (*sessionLock) Describe() string   { return "test-lease" }
func sessionConfig() *LeaderElectionConfig {
	return &LeaderElectionConfig{Identity: "test-pod", LeaseDuration: time.Second, RenewDeadline: time.Second, RetryPeriod: time.Millisecond}
}
func defaultSessionElector(t *testing.T) func(kle.LeaderElectionConfig) (electionRunner, error) {
	return func(cfg kle.LeaderElectionConfig) (electionRunner, error) {
		if cfg.ReleaseOnCancel {
			t.Error("automatic release may outrun probe cleanup")
		}
		return sessionElector(func(ctx context.Context) {
			go cfg.Callbacks.OnStartedLeading(ctx)
			<-ctx.Done()
			cfg.Callbacks.OnStoppedLeading()
		}), nil
	}
}

func TestLeaderProbeFailureDemotesAndReleases(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(map[bool]string{true: "error", false: "unexpected-return"}[fail], func(t *testing.T) {
			lock := &sessionLock{record: resourcelock.LeaderElectionRecord{HolderIdentity: "test-pod"}}
			var finished atomic.Bool
			lock.beforeRelease = func() {
				if !finished.Load() {
					t.Error("released before probe stopped")
				}
				if testutil.ToFloat64(metrics.ExporterLeader) != 0 {
					t.Error("released while still marked leader")
				}
			}
			sentinel := errors.New("Xray startup failed")
			err := runLeaderSession(context.Background(), sessionConfig(), lock, func(context.Context) error {
				finished.Store(true)
				if fail {
					return sentinel
				}
				return nil
			}, defaultSessionElector(t))
			if err == nil || (fail && !errors.Is(err, sentinel)) {
				t.Fatalf("unexpected error: %v", err)
			}
			if lock.record.HolderIdentity != "" || lock.updates != 1 {
				t.Fatal("failed leader kept its lease")
			}
		})
	}
}

func TestLeaderShutdownDrainsBeforeStoppingRenewalAndRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lock := &sessionLock{record: resourcelock.LeaderElectionRecord{HolderIdentity: "test-pod"}}
	started, draining, allowStop := make(chan struct{}), make(chan struct{}), make(chan struct{})
	electionStopped := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runLeaderSession(ctx, sessionConfig(), lock, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(draining)
			<-allowStop
			return ctx.Err()
		}, func(cfg kle.LeaderElectionConfig) (electionRunner, error) {
			return sessionElector(func(ctx context.Context) {
				go cfg.Callbacks.OnStartedLeading(ctx)
				<-ctx.Done()
				close(electionStopped)
				cfg.Callbacks.OnStoppedLeading()
			}), nil
		})
	}()
	<-started
	cancel()
	<-draining
	if testutil.ToFloat64(metrics.ExporterLeader) != 0 {
		t.Error("shutdown did not demote immediately")
	}
	select {
	case <-electionStopped:
		t.Error("renewal stopped before probe drained")
	default:
	}
	record, _, _ := lock.Get(context.Background())
	if record.HolderIdentity != "test-pod" {
		t.Error("lease released before probe drained")
	}
	close(allowStop)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish")
	}
	if lock.record.HolderIdentity != "" {
		t.Fatal("lease not released after shutdown")
	}
}

func TestLeadershipLossJoinsProbeAndDoesNotReleaseNewOwner(t *testing.T) {
	lock := &sessionLock{record: resourcelock.LeaderElectionRecord{HolderIdentity: "test-pod"}}
	var finished atomic.Bool
	started := make(chan struct{})
	err := runLeaderSession(context.Background(), sessionConfig(), lock, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		finished.Store(true)
		return nil
	}, func(cfg kle.LeaderElectionConfig) (electionRunner, error) {
		return sessionElector(func(ctx context.Context) {
			leaderCtx, cancel := context.WithCancel(ctx)
			go cfg.Callbacks.OnStartedLeading(leaderCtx)
			<-started
			lock.mu.Lock()
			lock.record.HolderIdentity = "other-pod"
			lock.mu.Unlock()
			cancel()
			cfg.Callbacks.OnStoppedLeading()
		}), nil
	})
	if err == nil {
		t.Fatal("leadership loss returned success")
	}
	if !finished.Load() || testutil.ToFloat64(metrics.ExporterLeader) != 0 {
		t.Fatal("lost leader returned before demoting and joining probes")
	}
	if lock.record.HolderIdentity != "other-pod" || lock.updates != 0 {
		t.Fatal("cleared another pod's lease")
	}
}

func TestDelayedStartedCallbackCannotReviveStoppedSession(t *testing.T) {
	var callback func(context.Context)
	lock := &sessionLock{record: resourcelock.LeaderElectionRecord{HolderIdentity: "other-pod"}}
	var called atomic.Bool
	err := runLeaderSession(context.Background(), sessionConfig(), lock, func(context.Context) error { called.Store(true); return nil }, func(cfg kle.LeaderElectionConfig) (electionRunner, error) {
		callback = cfg.Callbacks.OnStartedLeading
		return sessionElector(func(context.Context) { cfg.Callbacks.OnStoppedLeading() }), nil
	})
	if err == nil {
		t.Fatal("unexpected election stop returned success")
	}
	callback(context.Background())
	if called.Load() || testutil.ToFloat64(metrics.ExporterLeader) != 0 {
		t.Fatal("late callback revived stopped session")
	}
}

func TestReleaseLeaseConflictRechecksOwnership(t *testing.T) {
	lock := &sessionLock{record: resourcelock.LeaderElectionRecord{HolderIdentity: "test-pod"}}
	lock.beforeRelease = func() {
		lock.mu.Lock()
		defer lock.mu.Unlock()
		lock.record.HolderIdentity = "new-pod"
		lock.updateFailure = apierrors.NewConflict(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, "test-lease", errors.New("changed resource version"))
	}
	if err := releaseLease(context.Background(), lock); err != nil {
		t.Fatal(err)
	}
	if lock.record.HolderIdentity != "new-pod" || lock.updates != 0 {
		t.Fatal("conflicting release overwrote new holder")
	}
}

type followerElector struct{ sessionElector }

func (followerElector) IsLeader() bool { return false }

func TestCanceledFollowerDoesNotAccessLeaseForRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lock := &sessionLock{record: resourcelock.LeaderElectionRecord{HolderIdentity: "other-pod"}}
	err := runLeaderSession(ctx, sessionConfig(), lock, func(context.Context) error { t.Error("follower started probes"); return nil }, func(cfg kle.LeaderElectionConfig) (electionRunner, error) {
		return followerElector{sessionElector(func(ctx context.Context) { <-ctx.Done(); cfg.Callbacks.OnStoppedLeading() })}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if lock.reads != 0 || lock.updates != 0 {
		t.Fatal("follower accessed Lease during shutdown")
	}
}
