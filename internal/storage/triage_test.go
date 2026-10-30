package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The built-in Full triage profile plus owner-made ones; a triage
// package is queued only for agents that report the ability, and reaches the
// agent with its artifact types.
func TestTriageProfilesAndJobs(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	list, e := s.TriageProfiles(ctx)
	if e != nil || len(list) != 1 || list[0].ID != FullTriage || len(list[0].Items) != len(protocol.TriageItems) {
		t.Fatalf("built-in %+v %v", list, e)
	}
	quick, e := s.AddTriageProfile(ctx, "Quick", []string{"wmi", "prefetch"}, "owner", now)
	if e != nil || quick.Items[0] != "prefetch" {
		t.Fatalf("add %+v %v", quick, e)
	}
	for _, bad := range []struct {
		name  string
		items []string
	}{{"quick", []string{"prefetch"}}, {"Full triage", []string{"prefetch"}}, {"Other", []string{"nonsense"}}, {"Other", nil}, {"", []string{"prefetch"}}} {
		if _, e := s.AddTriageProfile(ctx, bad.name, bad.items, "owner", now); !errors.Is(e, ErrTriage) {
			t.Fatal("invalid profile accepted", bad)
		}
	}
	if p, e := s.TriageProfileNamed(ctx, "QUICK"); e != nil || p.ID != quick.ID {
		t.Fatal("by name", p, e)
	}
	if _, e := s.QueueTriage(ctx, caseID, device, "", quick, "owner", now); !errors.Is(e, ErrTriageUnsupported) {
		t.Fatal("triage for an agent without the ability", e)
	}
	if e := s.RecordHeartbeat(ctx, device, "fp", protocol.Heartbeat{Hostname: "pc", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityTriage}}, now); e != nil {
		t.Fatal(e)
	}
	if _, e := s.QueueTriage(ctx, LiveCase, device, "", quick, "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("case-less triage without a session", e)
	}
	id, e := s.QueueTriage(ctx, caseID, device, "", quick, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	d, e := s.DispatchEvidence(ctx, device, "fp", now)
	if e != nil || d.Job == nil || d.Job.ID != id || d.Job.Source != "triage" || d.Job.Query != "prefetch,wmi" || d.Job.Path != "Quick" || d.Job.ExpiresAt != now.Add(triageStartWindow).Unix() {
		t.Fatalf("dispatch %+v %v", d.Job, e)
	}
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	if jobs[0].Name() != "triage-Quick-"+id[:8]+".zip" {
		t.Fatal("name", jobs[0].Name())
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	if last := detail.Entries[len(detail.Entries)-1]; last.Details["source"] != "triage package" || last.Details["items"] != "prefetch,wmi" {
		t.Fatalf("custody %+v", last)
	}
	if e = s.WithdrawTriageProfile(ctx, quick.ID, "owner", now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.TriageProfileByID(ctx, quick.ID); !errors.Is(e, ErrTriage) {
		t.Fatal("withdrawn profile usable")
	}
	if _, e = s.AddTriageProfile(ctx, "Quick", []string{"prefetch"}, "owner", now); e != nil {
		t.Fatal("name of a withdrawn profile not reusable", e)
	}
}

// NTFS artifact packages are queued for agents that report the ability and
// reach the agent with their volumes.
func TestNTFSJobs(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	if _, e := s.QueueNTFS(ctx, caseID, device, "", nil, false, "owner", now); !errors.Is(e, ErrNTFSUnsupported) {
		t.Fatal("NTFS for an agent without the ability", e)
	}
	if e := s.RecordHeartbeat(ctx, device, "fp", protocol.Heartbeat{Hostname: "pc", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityNTFS}}, now); e != nil {
		t.Fatal(e)
	}
	if _, e := s.QueueNTFS(ctx, LiveCase, device, "", nil, false, "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("case-less package without a session", e)
	}
	if _, e := s.QueueNTFS(ctx, caseID, device, "", []string{"C:", "C:"}, false, "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal("repeated volume accepted", e)
	}
	id, e := s.QueueNTFS(ctx, caseID, device, "", []string{"C:", "D:"}, false, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	d, e := s.DispatchEvidence(ctx, device, "fp", now)
	if e != nil || d.Job == nil || d.Job.ID != id || d.Job.Source != "ntfs" || d.Job.Query != "C:,D:" || d.Job.ExpiresAt != now.Add(triageStartWindow).Unix() {
		t.Fatalf("dispatch %+v %v", d.Job, e)
	}
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	if jobs[0].Name() != "ntfs-"+id[:8]+".zip" {
		t.Fatal("name", jobs[0].Name())
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	if last := detail.Entries[len(detail.Entries)-1]; last.Details["source"] != "NTFS artifacts" || last.Details["volumes"] != "C:, D:" {
		t.Fatalf("custody %+v", last)
	}
}
