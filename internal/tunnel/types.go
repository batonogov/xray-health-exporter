// Package tunnel provides tunnel lifecycle management, Xray configuration
// generation, and health-check coordination for xray-health-exporter.
package tunnel

import (
	"context"
	"time"

	"github.com/xtls/xray-core/core"
)

// HealthChecker performs a single health-check on a tunnel instance and
// records the result through the returned CheckResult.
type HealthChecker interface {
	Check(ti *TunnelInstance) CheckResult
}

// CheckResult holds the outcome of a single health-check.
//
// Contract:
//   - Up==true  => tunnel is reachable and returned an acceptable HTTP status.
//     Err may still be non-nil when the response body could not be
//     fully read (partial success). Callers should check Up first
//     and use Err for supplementary diagnostics only.
//   - Up==false => tunnel is down; Err describes the reason.
type CheckResult struct {
	Up         bool
	Latency    time.Duration
	HTTPStatus int
	Err        error
}

// MetricsUpdater records health-check results as Prometheus metrics.
type MetricsUpdater interface {
	Update(name string, labels MetricLabels, result CheckResult)
	RecordError(name string, ml MetricLabels, err error)
}

// VLESSConfig holds the parsed fields of a VLESS URL.
type VLESSConfig struct {
	UUID        string
	Address     string
	Port        int
	Security    string
	PBK         string
	SNI         string
	FP          string
	SID         string
	SPX         string
	Type        string
	ServiceName string
	Authority   string
	MultiMode   bool
	Host        string
	Path        string
}

// MetricLabels holds protocol-agnostic labels for Prometheus metrics.
// Populated from VLESSConfig for VLESS tunnels; extracted from xray_config_file
// metadata for raw-config tunnels.
type MetricLabels struct {
	Server   string
	Security string
	SNI      string
}

// TunnelInstance represents a running tunnel with its Xray instance and
// configuration parameters.
type TunnelInstance struct {
	Name              string
	VLESSConfig       *VLESSConfig // nil for xray_config_file tunnels
	MetricLabels      MetricLabels
	XrayInstance      *core.Instance
	SocksPort         int
	CheckURL          string
	CheckInterval     time.Duration
	CheckTimeout      time.Duration
	MaxBackoff        time.Duration
	BackoffMultiplier float64
	cancelFunc        context.CancelFunc
}
