package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
)

// Terminal transcripts: a terminal opened from a case records every
// input and output chunk, with its UTC time, as JSON lines in the evidence
// directory. When the session ends the file is hashed, compared with the
// recorder's running hash, stored by SHA-256 and recorded in the case's
// custody log. Transcripts are evidence jobs of kind "transcript": they share
// the case's evidence list and download, but are never handed to an agent,
// swept or cancelled. One that could not be stored (or was cut short by a
// server stop) is stored by FinishTranscripts, which runs at start-up and
// every minute.

const TranscriptFormat = "openrmm-terminal-transcript"

// transcriptReserve is the quota room a recording needs before it starts:
// the terminal's 16 MiB output limit plus input and JSON overhead.
const transcriptReserve = 48 << 20

// ErrRecording means the transcript could not be written; the session must
// end rather than continue unrecorded.
var ErrRecording = errors.New("the terminal transcript could not be written")

// Transcript records one terminal session. Its methods are safe for
// concurrent use and are called while the terminal hub is locked, so they
// only append to the file; syncing, hashing and storing run afterwards.
type Transcript struct {
	store                   *Store
	job                     string
	mu                      sync.Mutex
	file                    *os.File
	sum                     hash.Hash
	inputs, dropped, output int64
	broken                  bool
}

// line appends one JSON line; the running hash covers exactly the lines that
// were written in full.
func (t *Transcript) line(v any) error {
	if t.broken {
		return ErrRecording
	}
	b, e := json.Marshal(v)
	if e == nil {
		b = append(b, '\n')
		_, e = t.file.Write(b)
	}
	if e != nil {
		t.broken = true
		return ErrRecording
	}
	t.sum.Write(b)
	return nil
}

// Write records one chunk: "in" (input delivered to the device), "dropped"
// (input queued but never delivered because the session ended) or "out".
// Valid UTF-8 is stored as text, anything else as base64.
func (t *Transcript) Write(direction string, at time.Time, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil || len(data) == 0 {
		return nil
	}
	v := map[string]string{"at": custody.Stamp(at), "dir": direction}
	if utf8.Valid(data) {
		v["text"] = string(data)
	} else {
		v["b64"] = base64.StdEncoding.EncodeToString(data)
	}
	if e := t.line(v); e != nil {
		return e
	}
	switch direction {
	case "in":
		t.inputs++
	case "dropped":
		t.dropped++
	default:
		t.output += int64(len(data))
	}
	return nil
}

// transcriptEnd is the last line of a finished transcript.
type transcriptEnd struct {
	At      string `json:"at"`
	End     string `json:"end"`
	Inputs  int64  `json:"inputs"`
	Dropped int64  `json:"dropped"`
	Output  int64  `json:"output_bytes"`
}

// Finish writes the end line and hands the transcript to the background
// store; Store.Close waits for it.
func (t *Transcript) Finish(reason string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return
	}
	_ = t.line(transcriptEnd{At: custody.Stamp(at), End: reason, Inputs: t.inputs, Dropped: t.dropped, Output: t.output})
	f, recorder := t.file, hex.EncodeToString(t.sum.Sum(nil))
	t.file = nil
	s, job := t.store, t.job
	s.transcripts.Add(1)
	go func() {
		defer s.transcripts.Done()
		_ = f.Sync()
		_ = f.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		// The recorder's hash and the end reason are kept before storing, so a
		// retry after a failure or a server stop still has them.
		_, e := s.db.ExecContext(ctx, `UPDATE evidence_jobs SET device_sha256=?,outcome=? WHERE id=? AND kind='transcript' AND status='uploading'`, recorder, reason, job)
		s.setRecording(job, false)
		if e == nil {
			_ = s.finishTranscript(ctx, job, at)
		}
	}()
}

func (s *Store) setRecording(job string, on bool) {
	s.recordingMu.Lock()
	defer s.recordingMu.Unlock()
	if s.recording == nil {
		s.recording = map[string]bool{}
	}
	if on {
		s.recording[job] = true
	} else {
		delete(s.recording, job)
	}
}

func (s *Store) isRecording(job string) bool {
	s.recordingMu.Lock()
	defer s.recordingMu.Unlock()
	return s.recording[job]
}

// StartTranscript opens a transcript for a terminal session bound to an open
// case and records the opening in the custody log. The evidence quota must
// have room for a full session.
func (s *Store) StartTranscript(ctx context.Context, caseID, device, actor, session string, now time.Time) (*Transcript, error) {
	if s.evidence == "" {
		return nil, ErrEvidence
	}
	if caseID == LiveCase {
		return nil, ErrCase
	}
	job, e := evidenceID()
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(s.incoming(job), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, errors.New("cannot create the transcript")
	}
	fail := func(e error) (*Transcript, error) {
		f.Close()
		os.Remove(s.incoming(job))
		return nil, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return fail(e)
	}
	defer tx.Rollback()
	used, e := s.quotaUsed(ctx, tx)
	if e != nil {
		return fail(e)
	}
	if s.evidenceQuota > 0 && used+transcriptReserve > s.evidenceQuota {
		return fail(ErrEvidence)
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO evidence_jobs(id,case_id,device_id,actor,path,status,kind,chunk_size,created_at,expires_at,activity_at,resolved_path) VALUES(?,?,?,?,?,'uploading','transcript',1,?,?,?,?)`, job, caseID, device, actor, "Terminal transcript (session "+session+")", now.Unix(), now.Unix(), now.Unix(), "terminal:"+session); e != nil {
		return fail(ErrCase)
	}
	if _, e = AppendCustody(ctx, tx, caseID, actor, device, "terminal_opened", map[string]string{"session": session, "job": job}, nil, "success", now); e != nil {
		return fail(e)
	}
	t := &Transcript{store: s, job: job, file: f, sum: sha256.New()}
	if e = t.line(map[string]any{"format": TranscriptFormat, "version": 1, "case_id": caseID, "device_id": device, "session": session, "actor": actor, "started": custody.Stamp(now)}); e != nil {
		return fail(e)
	}
	s.setRecording(job, true)
	if e = tx.Commit(); e != nil {
		s.setRecording(job, false)
		return fail(e)
	}
	return t, nil
}

// readEnd returns the transcript's end line, if its last line is one.
func readEnd(path string) (transcriptEnd, bool) {
	var v transcriptEnd
	f, e := os.Open(path)
	if e != nil {
		return v, false
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return v, false
	}
	n := min(i.Size(), 4096)
	b := make([]byte, n)
	if _, e = f.ReadAt(b, i.Size()-n); e != nil && e != io.EOF {
		return v, false
	}
	last := strings.TrimRight(string(b), "\n")
	last = last[strings.LastIndexByte(last, '\n')+1:]
	if json.Unmarshal([]byte(last), &v) != nil || v.End == "" {
		return transcriptEnd{}, false
	}
	return v, true
}

// finishTranscript stores a closed transcript by hash and records it. The
// file is moved into the store before the database commit; a retry finds it
// there by the recorder's hash. A transcript whose file is gone is recorded
// as failed. Calls are serialized.
func (s *Store) finishTranscript(ctx context.Context, job string, now time.Time) error {
	s.transcriptMu.Lock()
	defer s.transcriptMu.Unlock()
	var j EvidenceJob
	var recorder, reason string
	if e := s.db.QueryRowContext(ctx, `SELECT id,case_id,device_id,path,status,device_sha256,outcome FROM evidence_jobs WHERE id=? AND kind='transcript'`, job).Scan(&j.ID, &j.CaseID, &j.DeviceID, &j.Path, &j.Status, &recorder, &reason); e != nil {
		return ErrEvidence
	}
	if j.Status != "uploading" {
		return nil // already finished
	}
	source := s.incoming(job)
	if _, e := os.Stat(source); errors.Is(e, os.ErrNotExist) && len(recorder) == 64 {
		source = s.stored(recorder)
	}
	hash, size, e := hashFile(ctx, source)
	if errors.Is(e, os.ErrNotExist) {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		return s.failEvidence(ctx, tx, j, "missing_upload", now)
	}
	if e != nil {
		return e
	}
	details := map[string]string{"job": job, "reason": "interrupted"}
	if end, ok := readEnd(source); ok {
		details["reason"] = end.End
		details["inputs"] = strconv.FormatInt(end.Inputs, 10)
		details["dropped_inputs"] = strconv.FormatInt(end.Dropped, 10)
		details["output_bytes"] = strconv.FormatInt(end.Output, 10)
	} else if reason != "" {
		details["reason"] = reason
		details["recording"] = "incomplete: the end of the transcript could not be written"
	}
	outcome := "success"
	switch {
	case recorder == "":
		outcome = "unverified"
		details["verification"] = "none: the recorder's hash was not saved (server stop)"
	case recorder != hash:
		outcome = "hash_mismatch"
		details["recorder_sha256"] = recorder
		details["verification"] = "failed: the stored file differs from what the recorder wrote"
	default:
		details["verification"] = "the stored file matches the recorder's running hash"
	}
	target := s.stored(hash)
	if source != target {
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		if stored, n, err := hashFile(ctx, target); err == nil && stored == hash && n == size {
			_ = os.Remove(source)
		} else {
			_ = os.Chmod(target, 0600)
			if e = os.Rename(source, target); e != nil {
				return errors.New("cannot store the transcript")
			}
		}
	}
	_ = os.Chmod(target, 0400)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	stored := outcome
	if outcome == "success" {
		stored = "ok" // as for collected files
	}
	result, e := tx.ExecContext(ctx, `UPDATE evidence_jobs SET status='succeeded',outcome=?,size=?,server_sha256=?,finished_at=? WHERE id=? AND status='uploading'`, stored, size, hash, now.Unix(), job)
	if e != nil {
		return e
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO evidence_files(sha256,size,stored_at) VALUES(?,?,?)`, hash, size, now.Unix()); e != nil {
		return e
	}
	// Recorded even if the case was closed meanwhile.
	if _, e = appendCustodyAnyStatus(ctx, tx, j.CaseID, "system", j.DeviceID, "terminal_transcript", details, []custody.Evidence{{SHA256: hash, Size: size, Name: transcriptName(job)}}, outcome, now); e != nil {
		return e
	}
	return tx.Commit()
}

func transcriptName(job string) string { return "terminal-" + job + ".jsonl" }

// FinishTranscripts stores transcripts that are no longer recording but were
// not stored: after a failed attempt, or left by a server stop (at start-up
// nothing is recording). Each failure is retried on the next call.
func (s *Store) FinishTranscripts(ctx context.Context, now time.Time) error {
	if s.evidence == "" {
		return nil
	}
	rows, e := s.db.QueryContext(ctx, `SELECT id FROM evidence_jobs WHERE kind='transcript' AND status='uploading'`)
	if e != nil {
		return e
	}
	var jobs []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			jobs = append(jobs, id)
		}
	}
	rows.Close()
	var first error
	for _, job := range jobs {
		if s.isRecording(job) {
			continue
		}
		if e := s.finishTranscript(ctx, job, now); e != nil && first == nil {
			first = e
		}
	}
	return first
}
