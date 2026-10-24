package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Evidence collection: the agent reads the requested file once,
// in order, hashing every chunk and the whole file, and uploads the chunks
// the server does not hold yet. A lost connection is retried chunk by chunk;
// the server re-checks every chunk and the whole file.

var errEvidenceRefused = errors.New("evidence job refused by the server")

const evidenceRetryBudget = 10 * time.Minute

func (s *heartbeatSession) runEvidence(ctx context.Context, deny []string, logger *slog.Logger) {
	journal, err := openJournal(s.config.State)
	if err != nil {
		// Without the journal a job could run twice: stay off until repaired.
		logger.Error("response journal unreadable; incident response is off until it is repaired or removed", "file", responseJournalFile)
		return
	}
	// Shadow copies and saved hives a previous run left behind are removed.
	options := s.evidenceOptions(deny)
	filetransfer.CleanupShadows(options.Ledger)
	_ = os.RemoveAll(options.Temp)
	s.cleanActionResults(time.Now())
	// Triage packages and indicator hunts take long:
	// they run one at a time in their own worker, so other jobs and live
	// response keep running.
	long := make(chan protocol.EvidenceJob, 12)
	defer close(long)
	// The server hands a dispatched action out again while it runs (it
	// cannot tell a long job from a restarted agent): those copies are
	// ignored.
	var longMu sync.Mutex
	inLong := map[string]bool{}
	go func() {
		for q := range long {
			outcome := s.handleEvidence(ctx, journal, q, deny, logger)
			logger.Info("long evidence job finished", "job_id", q.ID, "outcome", outcome)
			longMu.Lock()
			delete(inLong, q.ID)
			longMu.Unlock()
		}
	}()
	// Isolate and release never wait behind other work.
	urgent := make(chan protocol.EvidenceJob, 4)
	defer close(urgent)
	go func() {
		for q := range urgent {
			outcome := s.handleEvidence(ctx, journal, q, deny, logger)
			logger.Info("isolation job finished", "job_id", q.ID, "outcome", outcome)
			longMu.Lock()
			delete(inLong, q.ID)
			longMu.Unlock()
		}
	}()
	var pace pacer
	for ctx.Err() == nil {
		var d protocol.EvidenceDispatch
		err := s.call(ctx, "/api/v1/agent/evidence/poll", struct{}{}, &d)
		if err == nil && d.Job != nil {
			if evidenceJobValid(*d.Job) && s.boundHere(d.Job.DeviceID) && d.Job.Action != nil && (d.Job.Action.Kind == "isolate" || d.Job.Action.Kind == "release") {
				longMu.Lock()
				if !inLong[d.Job.ID] {
					select {
					case urgent <- *d.Job:
						inLong[d.Job.ID] = true
					default:
						logger.Warn("isolation job not started: too many waiting", "job_id", d.Job.ID)
					}
				}
				longMu.Unlock()
				continue
			}
			if evidenceJobValid(*d.Job) && s.boundHere(d.Job.DeviceID) && (d.Job.Source == "triage" || d.Job.Action != nil && d.Job.Action.Kind == "hunt") {
				longMu.Lock()
				if !inLong[d.Job.ID] {
					select {
					case long <- *d.Job:
						inLong[d.Job.ID] = true
					default:
						logger.Warn("long evidence job not started: too many waiting", "job_id", d.Job.ID)
					}
				}
				longMu.Unlock()
				continue
			}
			if evidenceJobValid(*d.Job) && s.boundHere(d.Job.DeviceID) {
				outcome := s.handleEvidence(ctx, journal, *d.Job, deny, logger)
				logger.Info("evidence collection finished", "job_id", d.Job.ID, "outcome", outcome)
				continue
			}
			logger.Warn("invalid or foreign evidence job discarded")
			err = errInvalidDispatch
		}
		if !waitContext(ctx, pace.next(err, 15*time.Second)) {
			return
		}
	}
}

// boundHere accepts a job addressed to this device. Older servers send no
// device ID.
func (s *heartbeatSession) boundHere(device string) bool {
	s.transportMu.RLock()
	id := s.value.Credential.DeviceID
	s.transportMu.RUnlock()
	return device == "" || device == id
}

// handleEvidence runs a job at most once: a finished job's recorded result
// is sent again, a started one resumes (the server holds its chunks).
func (s *heartbeatSession) handleEvidence(ctx context.Context, journal *responseJournal, q protocol.EvidenceJob, deny []string, logger *slog.Logger) string {
	kind := "evidence"
	if q.Source == "action" {
		kind = "action"
	}
	entry, seen, err := journal.begin(q.ID, kind, true, time.Now())
	if err != nil {
		logger.Error("evidence job refused: the response journal could not record it", "job_id", q.ID)
		return "journal_refused"
	}
	if seen && entry.State == "finished" {
		var f protocol.EvidenceFinish
		if json.Unmarshal(entry.Result, &f) != nil {
			return "journal_refused"
		}
		if f.Outcome != "" {
			s.finishEvidence(ctx, q.ID, f)
		}
		return "resent_" + f.Outcome
	}
	// The server marks a job it hands out again: without the journal entry
	// (a reinstalled agent) a mutating action must still not run twice.
	f, send := s.collectEvidence(ctx, q, deny, seen || q.Resumed)
	if ctx.Err() != nil {
		// The agent is stopping (restart, update): the job stays started, any
		// kept action result stays, and the server hands the job out again.
		return "interrupted"
	}
	if q.Source == "action" && q.Action.Mutating() && f.Outcome == "failed" {
		// The device may have been changed even though the result is lost.
		f.Outcome = "unknown"
	}
	if err := journal.finish(q.ID, f, time.Now()); err != nil {
		logger.Error("cannot record the evidence result in the response journal", "job_id", q.ID)
	}
	if send {
		s.finishEvidence(ctx, q.ID, f)
	}
	if q.Source == "action" {
		_ = os.Remove(s.actionResultPath(q.ID))
	}
	return f.Outcome
}

func triageQuery(q string) bool {
	_, ok := protocol.ParseTriageQuery(q)
	return ok
}

func evidenceJobValid(q protocol.EvidenceJob) bool {
	return protocol.ValidID(q.ID) && q.ChunkSize > 0 && q.ChunkSize <= 64<<20 && q.MaxSize > 0 && len(q.Path) <= 4096 && q.Path != "" && (q.Source == "" && q.Action == nil || q.Source == "hive" && q.Action == nil && protocol.ValidHive(q.Path) || q.Source == "evtx" && q.Action == nil && eventlogs.ValidChannel(q.Path) && eventlogs.ValidExportQuery(q.Query) || q.Source == "triage" && q.Action == nil && len(q.Path) <= 100 && triageQuery(q.Query) || q.Source == "action" && q.Action != nil && q.Action.Valid())
}

// evidenceOptions keeps the shadow copy ledger and saved hives in the
// agent's private state folder.
func (s *heartbeatSession) evidenceOptions(deny []string) filetransfer.EvidenceOptions {
	return filetransfer.EvidenceOptions{Deny: deny, Ledger: filepath.Join(s.config.State, "evidence-shadows.json"), Temp: filepath.Join(s.config.State, "evidence-temp")}
}

// retry repeats a request until it succeeds, the server refuses it, or the
// retry budget runs out.
func retry(ctx context.Context, f func() error) error {
	deadline := time.Now().Add(evidenceRetryBudget)
	delay := 2 * time.Second
	for {
		err := f()
		if err == nil || errors.Is(err, errEvidenceRefused) || errors.Is(err, ErrRequestRejected) || errors.Is(err, ErrDeviceRejected) || errors.Is(err, ErrDeviceRevoked) || time.Now().After(deadline) {
			return err
		}
		if !waitContext(ctx, delay) {
			return ctx.Err()
		}
		delay = min(delay*2, time.Minute)
	}
}

func (s *heartbeatSession) finishEvidence(ctx context.Context, job string, v protocol.EvidenceFinish) string {
	_ = retry(ctx, func() error { return s.evidenceCall(ctx, http.MethodPost, job, "/finish", v, nil, "") })
	return v.Outcome
}

// collectEvidence reads and uploads the file and returns the result to
// report; send is false when the server already ended the job. The server
// enforces the job's deadlines with its own clock; a device clock that is off
// must not drop jobs.
func (s *heartbeatSession) collectEvidence(ctx context.Context, q protocol.EvidenceJob, deny []string, resumed bool) (protocol.EvidenceFinish, bool) {
	var ev filetransfer.Evidence
	var outcome string
	switch q.Source {
	case "hive":
		ev, outcome = filetransfer.OpenHive(q.Path, s.evidenceOptions(deny))
	case "evtx":
		ev, outcome = filetransfer.OpenEventLog(q.Path, q.Query, s.evidenceOptions(deny))
	case "triage":
		items, _ := protocol.ParseTriageQuery(q.Query)
		ev, outcome = filetransfer.OpenTriage(ctx, q.Path, items, q.MaxSize, s.evidenceOptions(deny))
	case "action":
		ev, outcome = s.actionEvidence(ctx, q, resumed, deny)
	default:
		ev, outcome = filetransfer.OpenEvidence(q.Path, s.evidenceOptions(deny))
	}
	if outcome != "" {
		return protocol.EvidenceFinish{Outcome: outcome}, true
	}
	defer ev.Close()
	size := ev.Info.Size()
	if size > q.MaxSize {
		return protocol.EvidenceFinish{Outcome: "too_large"}, true
	}
	modified, created := fileTimes(ev.Info)
	if ev.Meta.Method == "registry_save" || ev.Meta.Method == "export" || ev.Meta.Method == "triage" {
		// The saved copy's times say nothing about the hive or log.
		modified, created = 0, 0
	}
	meta := ev.Meta
	start := protocol.EvidenceStart{Size: size, Modified: modified, Created: created, Resolved: ev.Resolved, Meta: &meta}
	var progress protocol.EvidenceProgress
	if err := retry(ctx, func() error { return s.evidenceCall(ctx, http.MethodPost, q.ID, "/start", start, &progress, "") }); err != nil {
		// Report the failure to free the device's collection slot.
		return protocol.EvidenceFinish{Outcome: "failed"}, !errors.Is(err, errEvidenceRefused)
	}
	held := map[int64]bool{}
	for _, i := range progress.Received {
		held[i] = true
	}
	whole := sha256.New()
	buf := make([]byte, q.ChunkSize)
	count := (size + q.ChunkSize - 1) / q.ChunkSize
	for i := int64(0); i < count; i++ {
		want := min(q.ChunkSize, size-i*q.ChunkSize)
		if _, err := io.ReadFull(ev.File, buf[:want]); err != nil {
			return protocol.EvidenceFinish{Outcome: "changed"}, true
		}
		whole.Write(buf[:want])
		if held[i] {
			continue
		}
		sum := sha256.Sum256(buf[:want])
		chunk := buf[:want]
		path := "/chunks/" + strconv.FormatInt(i, 10)
		if err := retry(ctx, func() error {
			return s.evidenceCall(ctx, http.MethodPut, q.ID, path, chunk, nil, hex.EncodeToString(sum[:]))
		}); err != nil {
			return protocol.EvidenceFinish{Outcome: "failed"}, !errors.Is(err, errEvidenceRefused)
		}
	}
	// A file that changed while it was read is not evidence of one state.
	after, err := ev.File.Stat()
	if err != nil || after.Size() != size || !after.ModTime().Equal(ev.Info.ModTime()) {
		return protocol.EvidenceFinish{Outcome: "changed"}, true
	}
	if n, _ := ev.File.Read(buf[:1]); n != 0 {
		return protocol.EvidenceFinish{Outcome: "changed"}, true
	}
	return protocol.EvidenceFinish{Outcome: "ok", Size: size, SHA256: hex.EncodeToString(whole.Sum(nil))}, true
}

// evidenceCall sends one evidence request with a two-minute deadline: a JSON
// body, or (with hash set) a raw chunk.
func (s *heartbeatSession) evidenceCall(ctx context.Context, method, job, suffix string, input any, output any, hash string) error {
	if hash == "" {
		if output == nil {
			var ignored struct{}
			output = &ignored
		}
		return s.callWithTimeout(ctx, "/api/v1/agent/evidence/"+job+suffix, input, output, 2*time.Minute)
	}
	if s.revoked.Load() {
		return ErrDeviceRevoked
	}
	s.transportMu.RLock()
	transport, origin := s.transport, s.value.DeviceURL
	s.transportMu.RUnlock()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(origin, "/")+"/api/v1/agent/evidence/"+job+suffix, bytes.NewReader(input.([]byte)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-OpenRMM-SHA256", hash)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch code := response.StatusCode; {
	case code == http.StatusNoContent:
		return nil
	case code == http.StatusForbidden && response.Header.Get(protocol.DeviceStatusHeader) == "revoked":
		s.revoked.Store(true)
		return ErrDeviceRevoked
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return ErrDeviceRejected
	case code == http.StatusConflict:
		return errEvidenceRefused
	case code == http.StatusTooManyRequests:
		return ErrDeviceThrottled
	case code >= 400 && code < 500:
		return ErrRequestRejected
	}
	return errors.New("evidence upload returned an unexpected status")
}
