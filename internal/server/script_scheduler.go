package server

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"log/slog"
	"time"
)

func runScriptScheduler(ctx context.Context, store *storage.Store, offline time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check, cancel := context.WithTimeout(ctx, 4*time.Second)
			e := store.EvaluateScriptSchedules(check, time.Now(), offline)
			cancel()
			if e != nil && ctx.Err() == nil {
				logger.Warn("script schedule evaluation unavailable")
			}
		}
	}
}
