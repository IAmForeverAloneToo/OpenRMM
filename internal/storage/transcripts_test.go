package storage

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A case-bound terminal session is recorded line by line and
// stored as hashed case evidence with custody entries; transcripts are never
// handed to agents, swept or cancelled, and an interrupted one is finished at
// the next start.
func TestTerminalTranscript(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	tr, e := s.StartTranscript(ctx, caseID, device, "owner", "session1", now)
	if e != nil {
		t.Fatal(e)
	}
	tr.Write("in", now, []byte("whoami\r"))
	tr.Write("out", now.Add(time.Second), []byte("nt authority\\system\r\n"))
	tr.Write("out", now.Add(time.Second), []byte{0xff, 0xfe})
	tr.Write("out", now, nil)
	tr.Write("dropped", now, []byte("exit"))
	// Not handed to the agent, swept as stalled or cancellable.
	if d, e := s.DispatchEvidence(ctx, device, "fp", now.Add(time.Hour)); e != nil || d.Job != nil {
		t.Fatal("transcript dispatched", d, e)
	}
	if e = s.SweepEvidence(ctx, now.Add(48*time.Hour)); e != nil {
		t.Fatal(e)
	}
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	if len(jobs) != 1 || jobs[0].Status != "uploading" || jobs[0].Kind != "transcript" {
		t.Fatalf("transcript job %+v", jobs)
	}
	if e = s.CancelEvidence(ctx, caseID, jobs[0].ID, "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("transcript cancelled", e)
	}
	// A recording does not count against the device's two collections.
	for i := range 2 {
		if _, e = s.QueueEvidence(ctx, caseID, device, `C:\f`+string(rune('a'+i)), "owner", now); e != nil {
			t.Fatal(i, e)
		}
	}
	tr.Finish("administrator_stopped", now.Add(2*time.Second))
	tr.Write("in", now, []byte("late"))
	tr.Finish("again", now)
	s.transcripts.Wait()

	jobs, _ = s.EvidenceJobs(ctx, caseID)
	var j EvidenceJob
	for _, x := range jobs {
		if x.Kind == "transcript" {
			j = x
		}
	}
	if j.Status != "succeeded" || len(j.ServerSHA256) != 64 || j.Name() != "terminal-"+j.ID+".jsonl" {
		t.Fatalf("finished transcript %+v", j)
	}
	f, got, e := s.OpenCaseEvidence(ctx, caseID, j.ID, "owner", true, now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if digest(b) != got.ServerSHA256 {
		t.Fatal("stored transcript does not match its hash")
	}
	var lines []map[string]any
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		var v map[string]any
		if json.Unmarshal(sc.Bytes(), &v) != nil {
			t.Fatal("invalid line", sc.Text())
		}
		lines = append(lines, v)
	}
	if len(lines) != 6 || lines[0]["format"] != TranscriptFormat || lines[0]["case_id"] != caseID || lines[1]["dir"] != "in" || lines[1]["text"] != "whoami\r" || lines[2]["text"] != "nt authority\\system\r\n" || lines[3]["b64"] != "//4=" || lines[4]["dir"] != "dropped" || lines[5]["end"] != "administrator_stopped" {
		t.Fatalf("transcript lines %v", lines)
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	actions := []string{}
	for _, x := range detail.Entries {
		actions = append(actions, x.Action)
	}
	if !detail.Verified || strings.Join(actions, ",") != "case_opened,terminal_opened,collection_requested,collection_requested,terminal_transcript,evidence_downloaded" {
		t.Fatal("custody", actions)
	}
	recorded := detail.Entries[4]
	if recorded.Outcome != "success" || recorded.Details["dropped_inputs"] != "1" || !strings.Contains(recorded.Details["verification"], "matches") || recorded.Details["inputs"] != "1" || recorded.Details["output_bytes"] != "23" || recorded.Details["reason"] != "administrator_stopped" || len(recorded.Evidence) != 1 || recorded.Evidence[0].SHA256 != got.ServerSHA256 {
		t.Fatalf("transcript entry %+v", recorded)
	}
}

// stop simulates a server stop: the file is closed without an end line and
// the recording is no longer active.
func stop(s *Store, tr *Transcript) {
	tr.mu.Lock()
	tr.file.Close()
	tr.file = nil
	tr.mu.Unlock()
	s.setRecording(tr.job, false)
}

func lastEntry(t *testing.T, s *Store, caseID string) CustodyEntry {
	t.Helper()
	detail, _ := s.CaseDetail(context.Background(), caseID)
	if !detail.Verified {
		t.Fatal("custody chain", detail.Problem)
	}
	return detail.Entries[len(detail.Entries)-1]
}

func jobStatus(s *Store, caseID, job string) EvidenceJob {
	jobs, _ := s.EvidenceJobs(context.Background(), caseID)
	for _, j := range jobs {
		if j.ID == job {
			return j
		}
	}
	return EvidenceJob{}
}

func TestTerminalTranscriptRefusalsAndRecovery(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	if _, e := s.StartTranscript(ctx, "ffffffffffffffffffffffffffffffff", device, "owner", "x", now); !errors.Is(e, ErrCase) {
		t.Fatal("unknown case accepted", e)
	}
	entries, _ := os.ReadDir(filepath.Join(s.evidence, "incoming"))
	if len(entries) != 0 {
		t.Fatal("refused transcript left a file")
	}
	// A recording needs quota room for a whole session.
	s.evidenceQuota = transcriptReserve - 1
	if _, e := s.StartTranscript(ctx, caseID, device, "owner", "q", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("recording started without quota room", e)
	}
	s.evidenceQuota = 0

	// A server stop leaves a transcript open; the next start stores it,
	// unverified because the recorder's hash was never saved. A transcript
	// still recording is left alone.
	tr, e := s.StartTranscript(ctx, caseID, device, "owner", "s2", now)
	if e != nil {
		t.Fatal(e)
	}
	tr.Write("in", now, []byte("dir\r"))
	if e = s.FinishTranscripts(ctx, now); e != nil || jobStatus(s, caseID, tr.job).Status != "uploading" {
		t.Fatal("active recording finished", e)
	}
	stop(s, tr)
	if e = s.FinishTranscripts(ctx, now); e != nil {
		t.Fatal(e)
	}
	if j := jobStatus(s, caseID, tr.job); j.Status != "succeeded" || j.Outcome != "unverified" {
		t.Fatalf("recovered %+v", j)
	}
	if last := lastEntry(t, s, caseID); last.Action != "terminal_transcript" || last.Details["reason"] != "interrupted" || last.Outcome != "unverified" {
		t.Fatalf("recovery entry %+v", last)
	}

	// A file changed outside the recorder is stored but flagged.
	tr, _ = s.StartTranscript(ctx, caseID, device, "owner", "s3", now)
	tr.Write("out", now, []byte("genuine"))
	written, _ := os.ReadFile(s.incoming(tr.job))
	f, _ := os.OpenFile(s.incoming(tr.job), os.O_WRONLY, 0)
	f.WriteAt([]byte("forgery"), int64(strings.Index(string(written), "genuine")))
	f.Close()
	tr.Finish("idle", now)
	s.transcripts.Wait()
	if last := lastEntry(t, s, caseID); last.Outcome != "hash_mismatch" || len(last.Details["recorder_sha256"]) != 64 || last.Details["reason"] != "idle" {
		t.Fatalf("tampered transcript %+v", last)
	}

	// Stopped after the file was moved into the store but before the
	// database commit: the retry finds it by the recorder's hash.
	tr, _ = s.StartTranscript(ctx, caseID, device, "owner", "s4", now)
	tr.Write("out", now, []byte("moved"))
	tr.mu.Lock()
	tr.line(transcriptEnd{At: "x", End: "expired"})
	recorder := hex.EncodeToString(tr.sum.Sum(nil))
	tr.mu.Unlock()
	stop(s, tr)
	if _, e = s.db.Exec(`UPDATE evidence_jobs SET device_sha256=?,outcome='expired' WHERE id=?`, recorder, tr.job); e != nil {
		t.Fatal(e)
	}
	os.MkdirAll(filepath.Dir(s.stored(recorder)), 0700)
	if e = os.Rename(s.incoming(tr.job), s.stored(recorder)); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishTranscripts(ctx, now); e != nil {
		t.Fatal(e)
	}
	if j := jobStatus(s, caseID, tr.job); j.Status != "succeeded" || j.ServerSHA256 != recorder {
		t.Fatalf("moved transcript %+v", j)
	}
	if last := lastEntry(t, s, caseID); last.Outcome != "success" || last.Details["reason"] != "expired" {
		t.Fatalf("moved transcript entry %+v", last)
	}

	// A transcript whose file is gone is recorded as failed.
	tr, _ = s.StartTranscript(ctx, caseID, device, "owner", "s5", now)
	stop(s, tr)
	os.Remove(s.incoming(tr.job))
	if e = s.FinishTranscripts(ctx, now); e != nil {
		t.Fatal(e)
	}
	if j := jobStatus(s, caseID, tr.job); j.Status != "failed" || j.Outcome != "missing_upload" {
		t.Fatalf("missing transcript %+v", j)
	}

	// A write error is reported, so the hub can end the session.
	tr, _ = s.StartTranscript(ctx, caseID, device, "owner", "s6", now)
	tr.mu.Lock()
	tr.file.Close()
	tr.mu.Unlock()
	if e = tr.Write("out", now, []byte("lost")); !errors.Is(e, ErrRecording) {
		t.Fatal("write error hidden", e)
	}
	tr.Finish("recording_failed", now)
	s.transcripts.Wait()

	// A closed case accepts no new recording; without an evidence store
	// nothing can be recorded.
	if e = s.SetCaseStatus(ctx, caseID, "closed", "owner", "", now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.StartTranscript(ctx, caseID, device, "owner", "s7", now); !errors.Is(e, ErrCase) {
		t.Fatal("closed case accepted", e)
	}
	s.evidence = ""
	if _, e = s.StartTranscript(ctx, caseID, device, "owner", "s8", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("recorded without an evidence store", e)
	}
}
