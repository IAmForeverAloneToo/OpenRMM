package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

func (s *heartbeatSession) pollUpdateJob(ctx context.Context) (protocol.UpdateDispatch, error) {
	var d protocol.UpdateDispatch
	e := s.call(ctx, "/api/v1/agent/updates/poll", struct{}{}, &d)
	return d, e
}

// Persist the received job BEFORE submitting it locally. On restart only query
// broker status: never resubmit an installation across an ambiguous boundary.
func runUpdateJobs(ctx context.Context, state string, a windowsupdate.Adapter, poll func(context.Context) (protocol.UpdateDispatch, error), send func(context.Context, protocol.UpdateProgress) error, wait func(context.Context, time.Duration) bool, logger *slog.Logger) {
	path := filepath.Join(state, "update-job.json")
	var active *protocol.UpdateJob
	if raw, e := os.ReadFile(path); e == nil {
		var q protocol.UpdateJob
		if len(raw) > 8192 || windowsupdate.Decode(raw, &q) != nil || !windowsupdate.JobValid(q) {
			logger.Error("invalid local update journal; operator action required")
			return
		}
		active = &q
	} else if !errors.Is(e, os.ErrNotExist) {
		logger.Error("update journal unavailable")
		return
	}
	var pending *protocol.UpdateProgress
	var pace pacer
	for ctx.Err() == nil {
		var failure error
		if active == nil {
			d, e := poll(ctx)
			failure = e
			if e == nil && d.Job != nil && !windowsupdate.JobValid(*d.Job) {
				logger.Error("invalid update job discarded")
				failure = errInvalidDispatch
			} else if e == nil && d.Job != nil {
				q := *d.Job
				raw, _ := json.Marshal(q)
				f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
				if e != nil {
					return
				}
				_, e = f.Write(raw)
				if e == nil {
					e = f.Sync()
				}
				closeErr := f.Close()
				if e != nil || closeErr != nil || os.Rename(path+".tmp", path) != nil {
					return
				}
				active = &q
				var p protocol.UpdateProgress
				e = nil
				if !windowsupdate.WindowAllows(q, time.Now()) {
					p = windowsupdate.Failure(q, "blocked")
				} else {
					p, e = a.Submit(ctx, q)
				}
				if e == nil {
					pending = &p
				}
			}
		}
		if active != nil {
			if pending == nil {
				p, e := a.Status(ctx, active.ID)
				if e == nil {
					pending = &p
				} else if errors.Is(e, windowsupdate.ErrInvalid) {
					p = windowsupdate.Failure(*active, "unknown")
					pending = &p
				}
			}
			if pending != nil {
				if !windowsupdate.ProgressValid(*pending, *active) {
					p := windowsupdate.Failure(*active, "unknown")
					pending = &p
				}
				e := send(ctx, *pending)
				if e != nil && !errors.Is(e, ErrRequestRejected) {
					failure = e
				}
				if e == nil || errors.Is(e, ErrRequestRejected) {
					if windowsupdate.Terminal(*pending) || errors.Is(e, ErrRequestRejected) {
						if os.Remove(path) != nil {
							return
						}
						active = nil
					}
					pending = nil
				}
			}
		}
		if !wait(ctx, pace.next(failure, 5*time.Second)) {
			return
		}
	}
}
