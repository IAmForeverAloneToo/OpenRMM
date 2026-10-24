package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

type scriptJournal struct {
	Job    protocol.ScriptJob    `json:"job"`
	Result protocol.ScriptResult `json:"result"`
}

func saveScriptJournal(path string, v scriptJournal) error {
	b, _ := json.Marshal(v)
	f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e == nil {
		e = c
	}
	if e == nil {
		e = os.Rename(path+".tmp", path)
	}
	return e
}
func (s *heartbeatSession) pollScript(ctx context.Context) (protocol.ScriptDispatch, error) {
	var d protocol.ScriptDispatch
	e := s.call(ctx, "/api/v1/agent/scripts/poll", struct{}{}, &d)
	return d, e
}
func (s *heartbeatSession) scriptProgress(ctx context.Context, p protocol.ScriptResult) (bool, error) {
	s.transportMu.RLock()
	id := s.value.Credential.DeviceID
	s.transportMu.RUnlock()
	var r protocol.ScriptReceipt
	e := s.call(ctx, "/api/v1/agent/scripts/result", p, &r)
	if e == nil && (r.DeviceID != id || r.ReceivedAt <= 0) {
		return false, ErrRequestRejected
	}
	return r.Cancel, e
}
func runScripts(ctx context.Context, state string, poll func(context.Context) (protocol.ScriptDispatch, error), send func(context.Context, protocol.ScriptResult) (bool, error), execute func(context.Context, protocol.ScriptJob) protocol.ScriptResult, wait func(context.Context, time.Duration) bool, logger *slog.Logger) {
	path := filepath.Join(state, "script-run.json")
	var active *scriptJournal
	if f, e := os.Open(path); e == nil {
		raw, e := io.ReadAll(io.LimitReader(f, 2*scripting.MaxBytes+1))
		_ = f.Close()
		var j scriptJournal
		if e != nil || len(raw) > 2*scripting.MaxBytes || decodeScriptJournal(raw, &j) != nil || !scripting.JobValid(j.Job) || !scripting.ResultValid(j.Result) || j.Result.ID != j.Job.ID {
			logger.Error("invalid script journal; local recovery required")
			return
		}
		// Scripts run inside this process, so a run still marked running was
		// interrupted by a restart. Report Unknown; never execute it again.
		if j.Result.Outcome == "running" {
			j.Result = scripting.Failure(j.Job.ID, "unknown")
			if saveScriptJournal(path, j) != nil {
				return
			}
		}
		active = &j
	} else if !errors.Is(e, os.ErrNotExist) {
		return
	}
	var result <-chan protocol.ScriptResult
	var cancel context.CancelFunc
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()
	var pace pacer
	for ctx.Err() == nil {
		var failure error
		if active == nil {
			d, e := poll(ctx)
			failure = e
			if e == nil && d.Job != nil && !scripting.JobValid(*d.Job) {
				logger.Warn("invalid script job discarded")
				failure = errInvalidDispatch
			} else if e == nil && d.Job != nil {
				q := *d.Job
				j := scriptJournal{q, scripting.Failure(q.ID, "running")}
				if saveScriptJournal(path, j) != nil {
					logger.Error("script journal unavailable; script runs stopped")
					return
				}
				active = &j
				runCtx, stop := context.WithTimeout(ctx, time.Duration(q.Version.Definition.Timeout)*time.Second)
				cancel = stop
				done := make(chan protocol.ScriptResult, 1)
				result = done
				go func() {
					defer stop()
					done <- execute(runCtx, q)
				}()
			}
		}
		if active != nil {
			if result != nil {
				select {
				case r := <-result:
					if !scripting.ResultValid(r) || r.ID != active.Job.ID || r.Outcome == "running" {
						r = scripting.Failure(active.Job.ID, "unknown")
					}
					active.Result = r
					result = nil
					if cancel != nil {
						cancel()
						cancel = nil
					}
					if saveScriptJournal(path, *active) != nil {
						return
					}
				default:
				}
			}
			cancelled, e := send(ctx, active.Result)
			if e != nil && !errors.Is(e, ErrRequestRejected) {
				failure = e
			}
			if cancelled && active.Result.Outcome == "running" && cancel != nil {
				cancel()
			}
			if e == nil && active.Result.Outcome != "running" || errors.Is(e, ErrRequestRejected) {
				if cancel != nil {
					cancel()
					cancel = nil
				}
				if os.Remove(path) != nil {
					return
				}
				active = nil
				result = nil
			}
		}
		if !wait(ctx, pace.next(failure, 2*time.Second)) {
			return
		}
	}
}

func decodeScriptJournal(raw []byte, j *scriptJournal) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(j) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return scripting.ErrInvalid
	}
	return nil
}
