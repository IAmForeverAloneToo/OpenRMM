// Package features schedules reviewed, compiled-in modules independently of
// heartbeats. Modules use the core's authenticated publisher, never their own TLS.
package features

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var ErrUnsupported = errors.New("collector unsupported on this platform")
var ErrReport = errors.New("invalid or unknown feature report")

// ErrRejected is returned by a Publisher when the server refused a report. The
// report is dropped (never resent) and the module collects again next interval.
var ErrRejected = errors.New("feature report rejected by the server")

type Module interface {
	Capability() protocol.Capability
	Collect(context.Context) (json.RawMessage, error)
}

type Job struct {
	Module   Module
	Enabled  bool
	Interval time.Duration
	// Zero keeps the small-metric default. Larger compiled-in modules must opt
	// into an explicit bounded payload; the absolute ceiling remains 2 MiB.
	MaxDataBytes int
	// Timeout bounds one collection: zero keeps the 5-second default; at most
	// 2 minutes (for modules that query WMI).
	Timeout time.Duration
}

// Settler is an optional Module interface: Settled is called
// once the last collected report was accepted (true) or rejected (false) by
// the server, never for an undelivered one, so an incremental module can
// advance its cursor only past delivered data.
type Settler interface {
	Settled(accepted bool)
}

type Publisher func(context.Context, protocol.FeatureReport) error

func wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Run sends one initial report, then collects on the configured interval. Failed
// publication retries the same bounded report until it is one interval old, then
// collects a fresh one; a rejected report is dropped. Collector errors are never
// sent.
func Run(ctx context.Context, job Job, publish Publisher, logger *slog.Logger) {
	run(ctx, job, publish, logger, wait)
}

func run(ctx context.Context, job Job, publish Publisher, logger *slog.Logger, wait func(context.Context, time.Duration) bool) {
	limit := 4096
	if job.MaxDataBytes > 0 && job.MaxDataBytes <= 2*1024*1024 {
		limit = job.MaxDataBytes
	}
	for ctx.Err() == nil {
		report := protocol.FeatureReport{Capability: job.Module.Capability(), Status: "disabled"}
		if job.Enabled {
			timeout := 5 * time.Second
			if job.Timeout > 0 && job.Timeout <= 2*time.Minute {
				timeout = job.Timeout
			}
			collectionCtx, cancel := context.WithTimeout(ctx, timeout)
			data, err := job.Module.Collect(collectionCtx)
			if err == nil {
				err = collectionCtx.Err()
			}
			cancel()
			report.Status = "ok"
			switch {
			case errors.Is(err, ErrUnsupported):
				report.Status = "unsupported"
			case err != nil || len(data) > limit || !json.Valid(data):
				report.Status = "failed"
			default:
				report.Data = data
			}
		}
		if ctx.Err() != nil {
			return
		}
		backoff := time.Second
		var waited time.Duration
		noticed, published, rejected := false, false, false
		for {
			err := publish(ctx, report)
			if err == nil {
				published = true
				break
			}
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, ErrRejected) {
				logger.Warn("feature report rejected by the server; collecting again next interval", "capability", report.Capability.Name)
				rejected = true
				break
			}
			if waited >= max(job.Interval, time.Minute) {
				break // never deliver an old snapshot late; collect a fresh one
			}
			if !noticed {
				logger.Warn("feature report unavailable; retrying", "capability", report.Capability.Name)
				noticed = true
			}
			if !wait(ctx, backoff) {
				return
			}
			waited += backoff
			backoff = min(backoff*2, time.Minute)
		}
		if s, ok := job.Module.(Settler); ok && report.Status == "ok" && (published || rejected) {
			s.Settled(published)
		}
		if published && (report.Status == "disabled" || report.Status == "unsupported") {
			return
		}
		if !published && !rejected {
			continue
		}
		if !wait(ctx, job.Interval) {
			return
		}
	}
}
