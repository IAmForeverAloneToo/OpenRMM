package agent

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"log/slog"
	"time"
)

func (s *heartbeatSession) pollProcessAction(ctx context.Context) (protocol.ProcessDispatch, error) {
	var v protocol.ProcessDispatch
	e := s.call(ctx, "/api/v1/agent/process-actions/poll", struct{}{}, &v)
	return v, e
}

// A server dispatch is consumed once. Retry result delivery only, never controls.
func runProcessActions(ctx context.Context, adapter processes.Adapter, poll func(context.Context) (protocol.ProcessDispatch, error), send func(context.Context, protocol.ProcessResult) error, wait func(context.Context, time.Duration) bool, logger *slog.Logger) {
	var result *protocol.ProcessResult
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
				if !protocol.ValidID(a.ID) || !processes.Manageable(a.PID, a.Name) || !processes.Start(a.Start) || a.ExpiresAt <= 0 {
					logger.Warn("invalid process action discarded")
					failure = errInvalidDispatch
				} else {
					// Dispatch is fresh from an authenticated live request. Use a local elapsed
					// deadline; device wall-clock skew must not extend execution time.
					actionCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
					r := adapter.Execute(actionCtx, a)
					cancel()
					result = &r
					logger.Info("process action finished", "action_id", a.ID, "outcome", r.Outcome)
					continue
				}
			}
		}
		if !wait(ctx, pace.next(failure, 5*time.Second)) {
			return
		}
	}
}
