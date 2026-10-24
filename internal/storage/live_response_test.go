package storage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// A live response session without a case runs its commands as
// jobs of the built-in LiveCase record: the audit log records them instead
// of a custody log, results are kept 24 hours outside the evidence store,
// and the record never shows up as a case.
func TestLiveResponseWithoutCase(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	session := strings.Repeat("5", 32)
	cases, _ := s.Cases(ctx)
	for _, c := range cases {
		if c.ID == LiveCase {
			t.Fatal("the live record is listed as a case")
		}
	}
	if _, e := s.CaseDetail(ctx, LiveCase); !errors.Is(e, ErrCase) {
		t.Fatal("the live record has a case page", e)
	}
	if e := s.AddCaseNote(ctx, LiveCase, "owner", "x", now); !errors.Is(e, ErrCase) {
		t.Fatal("note on the live record", e)
	}
	if _, e := s.QueueEvidence(ctx, LiveCase, device, `C:\x`, "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("collection into the live record through the case path", e)
	}
	ps := &protocol.ResponseAction{Kind: "processes"}
	id, e := s.QueueSessionJob(ctx, LiveCase, device, session, "", "", ps, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	result := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: *ps, Processes: []protocol.ProcessDetail{{PID: 4242, Name: "evil.exe", Start: "1337"}}}
	data, _ := json.Marshal(result)
	collect(t, s, device, now, data, &protocol.EvidenceMeta{Method: "action"})
	jobs, _ := s.SessionJobs(ctx, session, "owner")
	if len(jobs) != 1 || jobs[0].ID != id || jobs[0].Status != "succeeded" || jobs[0].CaseID != LiveCase {
		t.Fatalf("session jobs %+v", jobs)
	}
	// Kept outside the evidence store, not counted as evidence.
	if _, e = os.Stat(s.scratch(id)); e != nil {
		t.Fatal("result not in scratch", e)
	}
	var files int
	s.db.QueryRow(`SELECT COUNT(*) FROM evidence_files WHERE sha256=?`, digest(data)).Scan(&files)
	if files != 0 {
		t.Fatal("case-less result stored as evidence")
	}
	var custody, audits int
	s.db.QueryRow(`SELECT COUNT(*) FROM custody_entries WHERE case_id=?`, LiveCase).Scan(&custody)
	s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action LIKE 'live_%'`).Scan(&audits)
	if custody != 0 || audits < 2 {
		t.Fatal("custody entries", custody, "audit events", audits)
	}
	// The result can be read, and kill finds the process identity in it.
	f, _, e := s.OpenCaseEvidence(ctx, LiveCase, id, "owner", true, now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != string(data) {
		t.Fatal("result content")
	}
	if start, name, e := s.ListedProcess(ctx, device, 4242, now); e != nil || start != "1337" || name != "evil.exe" {
		t.Fatal("listed process", start, name, e)
	}
	if _, _, e = s.ListedProcess(ctx, device, 4242, now.Add(time.Hour)); e == nil {
		t.Fatal("a stale process list was used")
	}
	if c, dev, e := s.SessionJobCase(ctx, session, "owner", id); e != nil || c != LiveCase || dev != device {
		t.Fatal("session job case", c, e)
	}
	if _, _, e = s.SessionJobCase(ctx, strings.Repeat("6", 32), "owner", id); e == nil {
		t.Fatal("another session's job")
	}
	if _, _, e = s.SessionJobCase(ctx, session, "technician:x", id); e == nil {
		t.Fatal("another account's job")
	}
	// After 24 hours the result is removed.
	if e = s.SweepEvidence(ctx, now.Add(25*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(s.scratch(id)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("result kept after 24 hours")
	}
	if jobs, _ = s.SessionJobs(ctx, session, "owner"); jobs[0].Status != "expired" || jobs[0].Outcome != "purged" {
		t.Fatalf("purged job %+v", jobs[0])
	}
	// A session with a case records its commands there.
	if _, e = s.QueueSessionJob(ctx, caseID, device, session, "file", `C:\x\y.txt`, nil, "owner", now); e != nil {
		t.Fatal(e)
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	if last := detail.Entries[len(detail.Entries)-1]; last.Action != "collection_requested" || last.Details["path"] != `C:\x\y.txt` {
		t.Fatalf("case entry %+v", last)
	}
}

// Kept case-less results count against the quota;
// case-less jobs can be cancelled by their actor; live_* audit events stay
// out of the rolling audit trim and are removed after a year; run finds a
// script by name.
func TestLiveResponseLimits(t *testing.T) {
	ctx := context.Background()
	s, _, device, now := evidenceFixture(t)
	session := strings.Repeat("7", 32)
	used := func() int64 {
		tx, _ := s.db.BeginTx(ctx, nil)
		defer tx.Rollback()
		n, e := s.quotaUsed(ctx, tx)
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	before := used()
	ps := &protocol.ResponseAction{Kind: "processes"}
	if _, e := s.QueueSessionJob(ctx, LiveCase, device, session, "", "", ps, "owner", now); e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: *ps})
	collect(t, s, device, now, data, &protocol.EvidenceMeta{Method: "action"})
	if used() != before+int64(len(data)) {
		t.Fatal("a kept result does not count against the quota", before, used())
	}
	if e := s.SweepEvidence(ctx, now.Add(25*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if used() != before {
		t.Fatal("a purged result still counts", used())
	}
	// Cancel: only the account that ran the command.
	id, e := s.QueueSessionJob(ctx, LiveCase, device, session, "", "", &protocol.ResponseAction{Kind: "tasks"}, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	if s.CancelSessionJob(ctx, session, "technician:x", id, now) == nil {
		t.Fatal("another account cancelled the command")
	}
	if e = s.CancelSessionJob(ctx, session, "owner", id, now); e != nil {
		t.Fatal(e)
	}
	jobs, _ := s.SessionJobs(ctx, session, "owner")
	for _, j := range jobs {
		if j.ID == id && j.Status != "cancelled" {
			t.Fatalf("cancelled job %+v", j)
		}
	}
	// Audit retention.
	tx, _ := s.db.BeginTx(ctx, nil)
	if e = liveAudit(ctx, tx, "owner", device, "action_requested", nil, "success", now.Add(-400*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	for range 1100 {
		if e = audit(ctx, tx, now, "owner", "test_event", "success"); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	count := func(like string) (n int) {
		s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action LIKE ?`, like).Scan(&n)
		return n
	}
	live := count("live_%")
	if count("test_event") > 1000 || live < 4 {
		t.Fatal("audit trim", count("test_event"), live)
	}
	if e = s.SweepEvidence(ctx, now); e != nil {
		t.Fatal(e)
	}
	if count("live_%") != live-1 {
		t.Fatal("a live event older than a year was kept", count("live_%"), live)
	}
	// run finds the newest version of a script by name.
	v, e := s.CreateScriptVersion(ctx, ScriptVersion{ScriptVersion: protocol.ScriptVersion{ID: strings.Repeat("b", 32), ScriptID: strings.Repeat("c", 32), Definition: protocol.ScriptDefinition{Name: "Triage", Body: "param($Path) Get-Item $Path", Parameters: []protocol.ScriptParameter{{Name: "Path", Required: true}}, Timeout: 120, RunAs: "system"}}, Actor: "owner"}, now)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := s.ScriptNamed(ctx, "triage"); e != nil || got != v.ID {
		t.Fatal("script by name", got, e)
	}
	if _, e := s.ScriptNamed(ctx, "missing"); !errors.Is(e, ErrScript) {
		t.Fatal("unknown script", e)
	}
}
