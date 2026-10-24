package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func evidenceFixture(t *testing.T) (*Store, string, string, time.Time) {
	t.Helper()
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if e = s.UseEvidence(filepath.Join(t.TempDir(), "evidence"), 64<<20); e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	d := Device{ID: "0123456789abcdef0123456789abcdef", Hostname: "pc", OS: "windows", Architecture: "amd64", Certificate: "cert", Fingerprint: "fp"}
	if e = s.NewEnrollmentToken(ctx, "t", now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = s.EnrollDevice(ctx, "t", d, now); e != nil {
		t.Fatal(e)
	}
	c, e := s.CreateCase(ctx, "Evidence test", "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	return s, c.ID, d.ID, now
}

// A collection runs from request to verified, content-addressed
// evidence; every chunk and the whole file are checked; each step is in the
// case's custody log, including downloads.
func TestEvidenceCollectionLifecycle(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	for _, bad := range []string{"relative\\file", `C:\dir\`, `C:\a\\b`, "C:\\x\x01", `C:\a/b`, `\\server\share\f`} {
		if _, e := s.QueueEvidence(ctx, caseID, device, bad, "owner", now); !errors.Is(e, ErrEvidence) {
			t.Fatalf("path %q accepted", bad)
		}
	}
	job, e := s.QueueEvidence(ctx, caseID, device, `C:\Users\alice\notes.txt`, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SetCaseStatus(ctx, caseID, "closed", "owner", "", now); !errors.Is(e, ErrCase) {
		t.Fatal("case closed with a collection running", e)
	}
	d, e := s.DispatchEvidence(ctx, device, "fp", now)
	if e != nil || d.Job == nil || d.Job.ID != job || d.Job.ChunkSize != EvidenceChunk {
		t.Fatal("dispatch", d, e)
	}
	if again, _ := s.DispatchEvidence(ctx, device, "fp", now); again.Job != nil {
		t.Fatal("dispatched twice")
	}
	if _, e = s.DispatchEvidence(ctx, device, "wrong", now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong device accepted", e)
	}

	data := bytes.Repeat([]byte("evidence!"), (EvidenceChunk*2+1000)/9)
	start := protocol.EvidenceStart{Size: int64(len(data)), Modified: now.UnixNano(), Created: now.Add(-time.Hour).UnixNano(), Resolved: `C:\Users\alice\notes.txt`}
	p, e := s.StartEvidence(ctx, device, "fp", job, start, now)
	if e != nil || len(p.Received) != 0 {
		t.Fatal("start", p, e)
	}
	chunk := func(i int) []byte { return data[i*EvidenceChunk : min((i+1)*EvidenceChunk, len(data))] }
	if e = s.PutEvidenceChunk(ctx, device, "fp", job, 0, digest(chunk(1)), bytes.NewReader(chunk(0)), now); !errors.Is(e, ErrEvidence) {
		t.Fatal("chunk with the wrong hash accepted", e)
	}
	if e = s.PutEvidenceChunk(ctx, device, "fp", job, 0, digest(chunk(0)), bytes.NewReader(chunk(0)[:10]), now); !errors.Is(e, ErrEvidence) {
		t.Fatal("short chunk accepted", e)
	}
	if e = s.PutEvidenceChunk(ctx, device, "fp", job, 0, digest(chunk(0)), bytes.NewReader(chunk(0)), now); e != nil {
		t.Fatal(e)
	}
	// After a lost connection the agent starts again and resumes.
	if p, e = s.StartEvidence(ctx, device, "fp", job, start, now); e != nil || len(p.Received) != 1 || p.Received[0] != 0 {
		t.Fatal("resume", p, e)
	}
	if e = s.FinishEvidence(ctx, device, "fp", job, protocol.EvidenceFinish{Outcome: "ok", Size: start.Size, SHA256: digest(data)}, now); !errors.Is(e, ErrEvidence) {
		t.Fatal("finished with chunks missing", e)
	}
	for i := 1; i < 3; i++ {
		if e = s.PutEvidenceChunk(ctx, device, "fp", job, int64(i), digest(chunk(i)), bytes.NewReader(chunk(i)), now); e != nil {
			t.Fatal(i, e)
		}
	}
	if e = s.FinishEvidence(ctx, device, "fp", job, protocol.EvidenceFinish{Outcome: "ok", Size: start.Size, SHA256: digest(data)}, now); e != nil {
		t.Fatal(e)
	}
	if handled, e := s.VerifyEvidence(ctx, func() time.Time { return now }); !handled || e != nil {
		t.Fatal("verify", handled, e)
	}
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	if len(jobs) != 1 || jobs[0].Status != "succeeded" || jobs[0].ServerSHA256 != digest(data) || jobs[0].Hostname != "pc" {
		t.Fatalf("job %+v", jobs)
	}
	f, j, e := s.OpenCaseEvidence(ctx, caseID, job, "owner", true, now)
	if e != nil {
		t.Fatal(e)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, data) || j.ServerSHA256 != digest(data) {
		t.Fatal("stored evidence differs")
	}
	if e = s.SetCaseStatus(ctx, caseID, "closed", "owner", "", now); e != nil {
		t.Fatal(e)
	}
	if f, _, e = s.OpenCaseEvidence(ctx, caseID, job, "auditor", true, now); e != nil {
		t.Fatal("download from a closed case", e)
	}
	f.Close()
	detail, _ := s.CaseDetail(ctx, caseID)
	actions := []string{}
	for _, x := range detail.Entries {
		actions = append(actions, x.Action)
	}
	if !detail.Verified || strings.Join(actions, ",") != "case_opened,collection_requested,evidence_collected,evidence_downloaded,case_closed,evidence_downloaded" {
		t.Fatal("custody", actions, detail.Problem)
	}
	collected := detail.Entries[2]
	if collected.DeviceID != device || len(collected.Evidence) != 1 || collected.Evidence[0] != (custody.Evidence{SHA256: digest(data), Size: start.Size, Name: "notes.txt"}) || collected.Details["device_sha256"] != digest(data) || collected.Details["chunks"] != "3" {
		t.Fatalf("collected entry %+v", collected)
	}
}

func TestEvidenceFailuresAndSweep(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	// A whole-file hash that differs from the device's fails the job.
	job, _ := s.QueueEvidence(ctx, caseID, device, `C:\a.bin`, "owner", now)
	s.DispatchEvidence(ctx, device, "fp", now)
	data := []byte("small file")
	if _, e := s.StartEvidence(ctx, device, "fp", job, protocol.EvidenceStart{Size: int64(len(data)), Resolved: `C:\a.bin`}, now); e != nil {
		t.Fatal(e)
	}
	if e := s.PutEvidenceChunk(ctx, device, "fp", job, 0, digest(data), bytes.NewReader(data), now); e != nil {
		t.Fatal(e)
	}
	if e := s.FinishEvidence(ctx, device, "fp", job, protocol.EvidenceFinish{Outcome: "ok", Size: int64(len(data)), SHA256: digest([]byte("other"))}, now); e != nil {
		t.Fatal(e)
	}
	if handled, e := s.VerifyEvidence(ctx, func() time.Time { return now }); !handled || e != nil {
		t.Fatal(handled, e)
	}
	// Quota: a file larger than what is left fails at start.
	big, _ := s.QueueEvidence(ctx, caseID, device, `C:\b.bin`, "owner", now)
	s.DispatchEvidence(ctx, device, "fp", now)
	if _, e := s.StartEvidence(ctx, device, "fp", big, protocol.EvidenceStart{Size: 65 << 20, Resolved: `C:\b.bin`}, now); !errors.Is(e, ErrEvidence) {
		t.Fatal("quota not enforced", e)
	}
	// The agent reports it could not read a file.
	denied, _ := s.QueueEvidence(ctx, caseID, device, `C:\c.bin`, "owner", now)
	s.DispatchEvidence(ctx, device, "fp", now)
	if e := s.FinishEvidence(ctx, device, "fp", denied, protocol.EvidenceFinish{Outcome: "denied"}, now); e != nil {
		t.Fatal(e)
	}
	// Queued too long, and dispatched without a start.
	waiting, _ := s.QueueEvidence(ctx, caseID, device, `C:\d.bin`, "owner", now)
	if e := s.SweepEvidence(ctx, now.Add(2*time.Hour)); e != nil {
		t.Fatal(e)
	}
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	outcomes := map[string]string{}
	for _, j := range jobs {
		outcomes[j.ID] = j.Status + "/" + j.Outcome
	}
	if outcomes[job] != "failed/hash_mismatch" || outcomes[big] != "failed/quota" || outcomes[denied] != "failed/denied" || outcomes[waiting] != "expired/expired" {
		t.Fatal(outcomes)
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	if !detail.Verified || detail.Entries[len(detail.Entries)-1].Action != "collection_expired" {
		t.Fatal("custody", detail.Problem)
	}
	// Response switched off on the device refuses new collections.
	if _, e := s.db.Exec(`UPDATE devices SET feature_locks_json='["response"]' WHERE id=?`, device); e != nil {
		t.Fatal(e)
	}
	if _, e := s.QueueEvidence(ctx, caseID, device, `C:\e.bin`, "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("collection queued on a device with response locked off", e)
	}
}

// An idle upload is handed out again for resuming; a held chunk
// cannot be replaced; chunks after a cancel are refused; dispatch re-checks
// that response is still on; verification accepts an upload that an earlier
// attempt already moved into the store.
func TestEvidenceResumeCancelAndRechecks(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	data := bytes.Repeat([]byte("r"), EvidenceChunk+100)
	chunk := func(i int) []byte { return data[i*EvidenceChunk : min((i+1)*EvidenceChunk, len(data))] }
	job, _ := s.QueueEvidence(ctx, caseID, device, `C:\r.bin`, "owner", now)
	s.DispatchEvidence(ctx, device, "fp", now)
	start := protocol.EvidenceStart{Size: int64(len(data)), Modified: 1, Resolved: `C:\r.bin`}
	if _, e := s.StartEvidence(ctx, device, "fp", job, start, now); e != nil {
		t.Fatal(e)
	}
	if e := s.PutEvidenceChunk(ctx, device, "fp", job, 0, digest(chunk(0)), bytes.NewReader(chunk(0)), now); e != nil {
		t.Fatal(e)
	}
	other := bytes.Repeat([]byte("x"), EvidenceChunk)
	if e := s.PutEvidenceChunk(ctx, device, "fp", job, 0, digest(other), bytes.NewReader(other), now); !errors.Is(e, ErrEvidence) {
		t.Fatal("held chunk replaced", e)
	}
	// The agent restarted: after a few idle minutes the job is handed out again.
	if d, _ := s.DispatchEvidence(ctx, device, "fp", now.Add(time.Minute)); d.Job != nil {
		t.Fatal("busy upload handed out again")
	}
	later := now.Add(4 * time.Minute)
	d, e := s.DispatchEvidence(ctx, device, "fp", later)
	if e != nil || d.Job == nil || d.Job.ID != job {
		t.Fatal("idle upload not handed out for resuming", d, e)
	}
	if p, e := s.StartEvidence(ctx, device, "fp", job, start, later); e != nil || len(p.Received) != 1 {
		t.Fatal("resume", p, e)
	}
	if e = s.CancelEvidence(ctx, caseID, job, "owner", later); e != nil {
		t.Fatal(e)
	}
	if e = s.PutEvidenceChunk(ctx, device, "fp", job, 1, digest(chunk(1)), bytes.NewReader(chunk(1)), later); !errors.Is(e, ErrEvidence) {
		t.Fatal("chunk accepted after cancel", e)
	}

	// Response switched off after the request: the job fails at dispatch.
	off, _ := s.QueueEvidence(ctx, caseID, device, `C:\off.bin`, "owner", now)
	if _, e = s.db.Exec(`UPDATE devices SET feature_locks_json='["response"]' WHERE id=?`, device); e != nil {
		t.Fatal(e)
	}
	if d, e = s.DispatchEvidence(ctx, device, "fp", now); e != nil || d.Job != nil {
		t.Fatal("dispatched with response off", d, e)
	}
	if _, e = s.db.Exec(`UPDATE devices SET feature_locks_json='[]' WHERE id=?`, device); e != nil {
		t.Fatal(e)
	}

	// An earlier verification moved the upload but did not commit.
	small := []byte("verify again")
	moved, _ := s.QueueEvidence(ctx, caseID, device, `C:\m.bin`, "owner", now)
	s.DispatchEvidence(ctx, device, "fp", now)
	s.StartEvidence(ctx, device, "fp", moved, protocol.EvidenceStart{Size: int64(len(small)), Resolved: `C:\m.bin`}, now)
	s.PutEvidenceChunk(ctx, device, "fp", moved, 0, digest(small), bytes.NewReader(small), now)
	if e = s.FinishEvidence(ctx, device, "fp", moved, protocol.EvidenceFinish{Outcome: "ok", Size: int64(len(small)), SHA256: digest(small)}, now); e != nil {
		t.Fatal(e)
	}
	target := s.stored(digest(small))
	if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(s.incoming(moved), target); e != nil {
		t.Fatal(e)
	}
	if handled, e := s.VerifyEvidence(ctx, func() time.Time { return now }); !handled || e != nil {
		t.Fatal(handled, e)
	}
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	states := map[string]string{}
	for _, j := range jobs {
		states[j.ID] = j.Status + "/" + j.Outcome
	}
	if states[job] != "cancelled/cancelled" || states[off] != "failed/response_off" || states[moved] != "succeeded/ok" {
		t.Fatal(states)
	}
	if detail, _ := s.CaseDetail(ctx, caseID); !detail.Verified {
		t.Fatal("custody chain", detail.Problem)
	}
}

// An event log export is a collection of source "evtx" whose
// channel and query reach the agent; the case-less record needs a session.
func TestEventExportJobs(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	query := "*[System[EventID=4624]]"
	if _, e := s.QueueEventExport(ctx, caseID, device, "", `C:\Windows\System32\winevt\Logs\Security.evtx`, "", "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("file path accepted as a channel", e)
	}
	if _, e := s.QueueEventExport(ctx, LiveCase, device, "", "Security", "", "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("case-less export without a session", e)
	}
	if _, e := s.QueueEventExport(ctx, caseID, device, "", "Security", "*[System] or *[System]", "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("invalid query accepted", e)
	}
	if _, e := s.QueueEventExport(ctx, caseID, device, "", "Security", "", "owner", now); !errors.Is(e, ErrEventExport) {
		t.Fatal("export to an agent without the capability", e)
	}
	support, _ := json.Marshal(protocol.EventLogSupport{System: "readable", Application: "readable"})
	if e := s.RecordEventLogs(ctx, device, "fp", protocol.FeatureReport{Capability: eventlogs.Capability, Status: "ok", Data: support}, now); e != nil {
		t.Fatal(e)
	}
	id, e := s.QueueEventExport(ctx, caseID, device, "", "Microsoft-Windows-PowerShell/Operational", query, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	d, e := s.DispatchEvidence(ctx, device, "fp", now)
	if e != nil || d.Job == nil || d.Job.ID != id || d.Job.Source != "evtx" || d.Job.Query != query || d.Job.Path != "Microsoft-Windows-PowerShell/Operational" {
		t.Fatalf("dispatch %+v %v", d.Job, e)
	}
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	if len(jobs) != 1 || jobs[0].Query != query || jobs[0].Name() != "eventlog-Microsoft-Windows-PowerShell-Operational.evtx" {
		t.Fatalf("job %+v %s", jobs, jobs[0].Name())
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	if last := detail.Entries[len(detail.Entries)-1]; last.Details["source"] != "event log" || last.Details["query"] != query {
		t.Fatalf("custody %+v", last)
	}
}
