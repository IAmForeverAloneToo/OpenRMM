package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"log/slog"
	"time"
)

func (s *heartbeatSession) pollEventQuery(ctx context.Context) (protocol.EventDispatch, error) {
	var d protocol.EventDispatch
	e := s.call(ctx, "/api/v1/agent/event-logs/poll", struct{}{}, &d)
	return d, e
}
func runEventQueries(ctx context.Context, adapter eventlogs.Adapter, poll func(context.Context) (protocol.EventDispatch, error), send func(context.Context, protocol.EventResult) error, wait func(context.Context, time.Duration) bool, logger *slog.Logger) {
	var result *protocol.EventResult
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
			if e == nil && d.Query != nil {
				q := *d.Query
				if !protocol.ValidID(q.ID) || !eventlogs.FilterValid(q.Filter) {
					logger.Warn("invalid event query discarded")
					failure = errInvalidDispatch
				} else {
					readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
					r := adapter.Query(readCtx, q)
					cancel()
					data, e := json.Marshal(r)
					if r.ID != q.ID || !eventlogs.ResultValid(r, q.Filter) || e != nil || len(data) > eventlogs.MaxResultBytes {
						r = protocol.EventResult{ID: q.ID, Outcome: "too_large", Events: []protocol.WindowsEvent{}}
					}
					result = &r
					logger.Info("event query finished", "query_id", q.ID, "outcome", r.Outcome)
					continue
				}
			}
		}
		if !wait(ctx, pace.next(failure, 5*time.Second)) {
			return
		}
	}
}
