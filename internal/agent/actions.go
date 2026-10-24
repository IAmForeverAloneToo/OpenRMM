package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/response"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

// Response actions run through the evidence upload: the agent runs
// the action once, keeps its result document in the private state folder
// until the upload has finished, and uploads it like a collected file. A
// resumed job uploads the kept document again and never runs the action
// twice; a kill whose document is gone is reported as unknown.

const actionResultsDir = "evidence-actions"

func (s *heartbeatSession) actionResultPath(job string) string {
	return filepath.Join(s.config.State, actionResultsDir, job+".json")
}

// cleanActionResults removes result documents older than a week (left by a
// job the server ended meanwhile).
func (s *heartbeatSession) cleanActionResults(now time.Time) {
	dir := filepath.Join(s.config.State, actionResultsDir)
	entries, e := os.ReadDir(dir)
	if e != nil {
		return
	}
	for _, v := range entries {
		if i, e := v.Info(); e == nil && strings.HasSuffix(v.Name(), ".json") && now.Sub(i.ModTime()) > 7*24*time.Hour {
			_ = os.Remove(filepath.Join(dir, v.Name()))
		}
	}
}

// actionEvidence runs the job's action (unless its result is kept from an
// interrupted earlier run) and opens the result document for upload.
func (s *heartbeatSession) actionEvidence(ctx context.Context, q protocol.EvidenceJob, resumed bool, deny []string) (filetransfer.Evidence, string) {
	a := *q.Action
	path := s.actionResultPath(q.ID)
	if _, e := os.Stat(path); e != nil {
		if resumed && a.Mutating() {
			// It may have run before the agent stopped; never run it again.
			return filetransfer.Evidence{}, "unknown"
		}
		var result protocol.ActionResult
		var err error
		switch a.Kind {
		case "script":
			result, err = s.runScript(ctx, q.ID, a)
		case "drop":
			result = s.drop(ctx, q.ID, a, deny)
		case "events":
			result = s.searchEvents(ctx, q.ID, a)
		case "isolate", "release":
			result = s.isolate(ctx, q.ID, a)
		default:
			result, err = response.Run(ctx, a, &s.hashes)
		}
		if errors.Is(err, response.ErrNotFound) {
			return filetransfer.Evidence{}, "not_found"
		}
		if err != nil && !a.Mutating() {
			return filetransfer.Evidence{}, "failed"
		}
		b, e := json.Marshal(result)
		if e != nil {
			return filetransfer.Evidence{}, "failed"
		}
		if e = os.MkdirAll(filepath.Dir(path), 0700); e == nil {
			temp := path + ".tmp"
			if e = os.WriteFile(temp, b, 0600); e == nil {
				e = os.Rename(temp, path)
			}
		}
		if e != nil {
			if a.Mutating() {
				return filetransfer.Evidence{}, "unknown"
			}
			return filetransfer.Evidence{}, "failed"
		}
	}
	f, e := os.Open(path)
	if e != nil {
		return filetransfer.Evidence{}, "failed"
	}
	i, e := f.Stat()
	if e != nil {
		f.Close()
		return filetransfer.Evidence{}, "failed"
	}
	return filetransfer.Evidence{File: f, Info: i, Resolved: "action:" + a.Kind, Meta: protocol.EvidenceMeta{Method: "action"}}, ""
}

// searchEvents runs an event log search with the event log
// reader: the newest events matching the filter. The device's Event logs
// switch governs it like the viewer; when it is off the result says so.
func (s *heartbeatSession) searchEvents(ctx context.Context, job string, a protocol.ResponseAction) protocol.ActionResult {
	result := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: a, DeviceTime: time.Now().UTC().Format(time.RFC3339Nano)}
	r := protocol.EventResult{ID: job, Outcome: "unsupported", Events: []protocol.WindowsEvent{}}
	if s.config.EventLogs {
		readCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		r = eventlogs.NewAdapter().Query(readCtx, protocol.EventQuery{ID: job, Filter: *a.Events})
		cancel()
	}
	result.EventLog = &r
	return result
}

// runScript runs a case response script as SYSTEM through the
// contained script runner; the result records the body's hash and output.
func (s *heartbeatSession) runScript(ctx context.Context, job string, a protocol.ResponseAction) (protocol.ActionResult, error) {
	r := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: a, DeviceTime: time.Now().UTC().Format(time.RFC3339Nano)}
	q, ok := scripting.ResponseJob(job, a, time.Now().Add(time.Hour).Unix())
	run := &protocol.ScriptRun{Name: a.Name, SHA256: scripting.BodyHash(a.Script), Arguments: a.Arguments, Started: r.DeviceTime}
	r.Script = run
	if !ok {
		run.Outcome, run.Finished = "denied", run.Started
		return r, nil
	}
	v := scripting.RunContained(ctx, s.config.State, q)
	run.Outcome, run.ExitCode, run.Stdout, run.Stderr, run.Truncated = v.Outcome, v.ExitCode, v.Stdout, v.Stderr, v.Truncated
	run.Finished = time.Now().UTC().Format(time.RFC3339Nano)
	return r, nil
}

// drop writes a file from the server.
func (s *heartbeatSession) drop(ctx context.Context, job string, a protocol.ResponseAction, deny []string) protocol.ActionResult {
	r := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: a, DeviceTime: time.Now().UTC().Format(time.RFC3339Nano)}
	d := filetransfer.DropFile(a.Path, a.Overwrite, deny, a.Size, a.SHA256, func(w io.Writer) error { return s.payload(ctx, job, a.Size, w) })
	r.Drop = &d
	return r
}

// payload downloads a drop's file, continuing an interrupted download with
// a Range request.
func (s *heartbeatSession) payload(ctx context.Context, job string, size int64, w io.Writer) error {
	var n int64
	delay := 2 * time.Second
	for attempt := 0; n < size && attempt < 12; attempt++ {
		if attempt > 0 && !waitContext(ctx, delay) {
			return ctx.Err()
		}
		delay = min(delay*2, time.Minute)
		s.transportMu.RLock()
		transport, origin := s.transport, s.value.DeviceURL
		s.transportMu.RUnlock()
		client := &http.Client{Transport: transport, Timeout: 6 * time.Hour, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(origin, "/")+"/api/v1/agent/evidence/"+job+"/payload", nil)
		if e != nil {
			return e
		}
		want := http.StatusOK
		if n > 0 {
			request.Header.Set("Range", "bytes="+strconv.FormatInt(n, 10)+"-")
			want = http.StatusPartialContent
		}
		reply, e := client.Do(request)
		if e != nil {
			continue
		}
		if reply.StatusCode != want {
			reply.Body.Close()
			if reply.StatusCode == http.StatusConflict || reply.StatusCode == http.StatusForbidden || reply.StatusCode == http.StatusNotFound {
				return errEvidenceRefused
			}
			continue
		}
		copied, e := io.Copy(w, io.LimitReader(reply.Body, size-n))
		reply.Body.Close()
		n += copied
		if e != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if n != size {
		return errors.New("the file could not be downloaded")
	}
	return nil
}
