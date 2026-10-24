package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// A response action is dispatched with its spec, its result
// document is collected and verified like a file, and its custody entries
// are named action_*; a kill's result lists the processes in the custody
// entry; an action handed to the device cannot be cancelled; an unknown
// outcome is recorded.
func TestResponseActions(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	if _, e := s.QueueAction(ctx, caseID, device, protocol.ResponseAction{Kind: "format"}, "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("invalid action queued", e)
	}
	kill := protocol.ResponseAction{Kind: "kill", PID: 1234, Start: "133", Name: "evil.exe", Tree: true}
	id, e := s.QueueAction(ctx, caseID, device, kill, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	result := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: kill, Killed: []protocol.KillResult{{PID: 1300, ParentPID: 1234, Name: "child.exe", Start: "140", Outcome: "succeeded", SHA256: digest([]byte("c"))}, {PID: 1234, Name: "evil.exe", Start: "133", Outcome: "succeeded", SHA256: digest([]byte("e"))}}}
	data, _ := json.Marshal(result)
	job := collect(t, s, device, now, data, &protocol.EvidenceMeta{Method: "action"})
	if job.ID != id || job.Source != "action" || job.Action == nil || job.Action.Text() != kill.Text() || job.Path != kill.Label() {
		t.Fatalf("dispatched %+v", job)
	}
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	if len(jobs) != 1 || jobs[0].Source != "action" || jobs[0].Action != kill.Text() || jobs[0].Name() != "action-kill-"+id+".json" {
		t.Fatalf("listed %+v", jobs)
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	actions := []string{}
	for _, x := range detail.Entries {
		actions = append(actions, x.Action)
	}
	last := detail.Entries[len(detail.Entries)-1]
	if strings.Join(actions, ",") != "case_opened,action_requested,action_completed" || !strings.Contains(last.Details["killed"], "1300 child.exe started 140 succeeded") || last.Details["spec"] != kill.Text() {
		t.Fatalf("custody %v %+v", actions, last.Details)
	}

	// Handed to the device, an action cannot be cancelled; an unknown
	// outcome is recorded.
	id, _ = s.QueueAction(ctx, caseID, device, kill, "owner", now)
	d, _ := s.DispatchEvidence(ctx, device, "fp", now)
	if d.Job == nil || d.Job.ID != id {
		t.Fatal("dispatch", d)
	}
	if e = s.CancelEvidence(ctx, caseID, id, "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("dispatched action cancelled", e)
	}
	if e = s.FinishEvidence(ctx, device, "fp", id, protocol.EvidenceFinish{Outcome: "unknown"}, now); e != nil {
		t.Fatal(e)
	}
	if last = lastEntry(t, s, caseID); last.Action != "action_failed" || last.Outcome != "unknown" {
		t.Fatalf("unknown outcome %+v", last)
	}
	// A queued action can be cancelled.
	id, _ = s.QueueAction(ctx, caseID, device, protocol.ResponseAction{Kind: "registry", Key: `HKLM\SOFTWARE`}, "owner", now)
	if e = s.CancelEvidence(ctx, caseID, id, "owner", now); e != nil {
		t.Fatal(e)
	}
	if last = lastEntry(t, s, caseID); last.Action != "action_cancelled" {
		t.Fatalf("cancel %+v", last)
	}
	// An action gets 30 minutes to start uploading; a kill that never reports
	// may have run, so it ends as unknown.
	id, _ = s.QueueAction(ctx, caseID, device, kill, "owner", now)
	d, _ = s.DispatchEvidence(ctx, device, "fp", now)
	if d.Job == nil || d.Job.ID != id || d.Job.ExpiresAt != now.Add(30*time.Minute).Unix() {
		t.Fatal("action start window", d.Job)
	}
	if e = s.SweepEvidence(ctx, now.Add(31*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if last = lastEntry(t, s, caseID); last.Action != "action_failed" || last.Outcome != "unknown" {
		t.Fatalf("swept kill %+v", last)
	}
	// A dispatched action is handed out again, marked resumed, to an agent
	// that asks for work again (it restarted).
	id, _ = s.QueueAction(ctx, caseID, device, kill, "owner", now)
	if d, _ = s.DispatchEvidence(ctx, device, "fp", now); d.Job == nil || d.Job.ID != id || d.Job.Resumed {
		t.Fatal("first dispatch", d.Job)
	}
	if d, _ = s.DispatchEvidence(ctx, device, "fp", now.Add(time.Minute)); d.Job != nil {
		t.Fatal("handed out again too soon")
	}
	if d, _ = s.DispatchEvidence(ctx, device, "fp", now.Add(4*time.Minute)); d.Job == nil || d.Job.ID != id || !d.Job.Resumed {
		t.Fatal("resumed dispatch", d.Job)
	}
	// Refused on a later hand-out, a kill that may have run is unknown.
	if _, e = s.db.Exec(`UPDATE devices SET feature_locks_json='["response"]' WHERE id=?`, device); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DispatchEvidence(ctx, device, "fp", now.Add(8*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if last = lastEntry(t, s, caseID); last.Action != "action_failed" || last.Outcome != "unknown" {
		t.Fatalf("refused resumed kill %+v", last)
	}
	if !protocol.ValidRegistryKey(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run `) || protocol.ValidRegistryKey("HKLM\\x\ty") {
		t.Fatal("registry key names")
	}
}
