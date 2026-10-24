package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func runPatchScheduler(ctx context.Context, s *storage.Store, offline time.Duration, logger *slog.Logger) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check, cancel := context.WithTimeout(ctx, 4*time.Second)
			e := s.EvaluatePatchPolicies(check, time.Now(), offline)
			cancel()
			if e != nil && ctx.Err() == nil {
				logger.Warn("patch policy evaluation unavailable")
			}
		}
	}
}

// runAgentRings advances automatic agent rollouts once a minute.
func runAgentRings(ctx context.Context, s *storage.Store, offline time.Duration, logger *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	quiet := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			step, cancel := context.WithTimeout(ctx, 30*time.Second)
			queued, e := s.AdvanceAgentRings(step, time.Now(), offline)
			cancel()
			switch {
			case e != nil && ctx.Err() == nil && time.Since(quiet) >= 15*time.Minute:
				logger.Warn("automatic agent update step unavailable; retrying")
				quiet = time.Now()
			case queued > 0:
				logger.Info("automatic agent updates queued", "devices", queued)
			}
		}
	}
}

// runEvidenceVerifier verifies finished evidence uploads one at a time;
// hashing a large file can take minutes, so it runs apart from
// the request handlers and the housekeeping loop.
func runEvidenceVerifier(ctx context.Context, store *storage.Store, logger *slog.Logger) {
	for ctx.Err() == nil {
		handled, err := store.VerifyEvidence(ctx, time.Now)
		if err != nil && ctx.Err() == nil {
			logger.Warn("evidence verification unavailable")
		}
		if handled && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
