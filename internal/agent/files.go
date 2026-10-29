package agent

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"log/slog"
	"time"
)

// fileTransferTimeout lets a dispatch or result of up to 12 MiB cross a slow
// link; the session timeout (5 s by default) only suits small requests.
const fileTransferTimeout = 10 * time.Minute

func (s *heartbeatSession) pollFile(ctx context.Context) (protocol.FileDispatch, error) {
	var out protocol.FileDispatch
	e := s.callWithTimeout(ctx, "/api/v1/agent/files/poll", struct{}{}, &out, fileTransferTimeout)
	return out, e
}

func (s *heartbeatSession) sendFileResult(ctx context.Context, r protocol.FileResult) error {
	var receipt protocol.HeartbeatReceipt
	if e := s.callWithTimeout(ctx, "/api/v1/agent/files/result", r, &receipt, fileTransferTimeout); e != nil {
		return e
	}
	return s.checkReceipt(receipt)
}

// Server commits dispatch before delivery; never replay a mutation. Only its
// bounded result is retried in memory, with a finite retry deadline.
func runFileJobs(ctx context.Context, a filetransfer.Adapter, poll func(context.Context) (protocol.FileDispatch, error), send func(context.Context, protocol.FileResult) error, wait func(context.Context, time.Duration) bool, logger *slog.Logger) {
	var pending *protocol.FileResult
	var until time.Time
	var pace pacer
	for ctx.Err() == nil {
		var failure error
		if pending != nil {
			e := send(ctx, *pending)
			failure = e
			if e == nil || errors.Is(e, ErrRequestRejected) || time.Now().After(until) {
				pending, failure = nil, nil
			}
		}
		if pending == nil && failure == nil {
			d, e := poll(ctx)
			failure = e
			if e == nil && d.Job != nil {
				q := *d.Job
				if !filetransfer.JobValid(q) {
					logger.Warn("invalid file job discarded")
					failure = errInvalidDispatch
				} else {
					opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
					r := a.Execute(opCtx, q)
					cancel()
					if !filetransfer.ResultValid(q, r) {
						r = protocol.FileResult{ID: q.ID, Outcome: "unknown"}
					}
					pending = &r
					until = time.Now().Add(time.Minute)
					logger.Info("file operation finished", "job_id", q.ID, "outcome", r.Outcome)
					continue
				}
			}
		}
		if !wait(ctx, pace.next(failure, 5*time.Second)) {
			return
		}
	}
}
