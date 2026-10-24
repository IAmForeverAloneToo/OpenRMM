package agent

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
	"log/slog"
	"time"
)

func (s *heartbeatSession) pollAction(ctx context.Context) (protocol.ServiceDispatch, error) {
	var v protocol.ServiceDispatch
	e := s.call(ctx, "/api/v1/agent/service-actions/poll", struct{}{}, &v)
	return v, e
}

// A server dispatch is consumed once. Retry result delivery only, never controls.
func runServiceActions(ctx context.Context, adapter winservices.Adapter, poll func(context.Context) (protocol.ServiceDispatch, error), send func(context.Context, protocol.ServiceResult) error, wait func(context.Context, time.Duration) bool, logger *slog.Logger) {
	var result *protocol.ServiceResult
	var pace pacer
	for ctx.Err() == nil {
		var failure error
		if result != nil {
			e := send(ctx, *result)
			if e == nil || errors.Is(e, ErrRequestRejected) {
				result = nil
			} else {
				failure = e
			}
		}
		if result == nil && failure == nil {
			d, e := poll(ctx)
			failure = e
			if e == nil && d.Action != nil {
				a := *d.Action
				if !protocol.ValidID(a.ID) || !winservices.Manageable(a.Service) || !winservices.Action(a.Action) || a.ExpiresAt <= 0 {
					logger.Warn("invalid service action discarded")
					failure = errInvalidDispatch
				} else {
					// Dispatch is fresh from an authenticated live request. Use a local elapsed
					// deadline; device wall-clock skew must not extend execution time.
					actionCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
					r := adapter.Execute(actionCtx, a)
					cancel()
					result = &r
					logger.Info("service action finished", "action_id", a.ID, "outcome", r.Outcome)
					continue
				}
			}
		}
		if !wait(ctx, pace.next(failure, 5*time.Second)) {
			return
		}
	}
}
