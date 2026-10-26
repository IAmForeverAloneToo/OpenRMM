package server

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"log/slog"
	"time"
)

func runAlertEvaluator(ctx context.Context, s *storage.Store, logger *slog.Logger) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if e := s.EvaluateAlerts(ctx, time.Now()); e != nil && ctx.Err() == nil {
			logger.Warn("alert evaluation unavailable")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runAlertMail sends queued notices with the mailer in use at each tick;
// current returns nil while e-mail is off.
func runAlertMail(ctx context.Context, s *storage.Store, current func() *alerting.Mailer, logger *slog.Logger) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if m := current(); m != nil {
			id, notice, e := s.ClaimAlertMail(ctx, m.ID, time.Now())
			if e == nil && id != 0 {
				r := m.Send(ctx, notice)
				if e = s.FinishAlertMail(ctx, id, r, time.Now()); e != nil && ctx.Err() == nil {
					logger.Warn("alert email outcome could not be recorded")
				}
			}
			if e != nil && ctx.Err() == nil {
				logger.Warn("alert email queue unavailable")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
