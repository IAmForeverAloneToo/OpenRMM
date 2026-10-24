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

// An indicator hunt reaches the devices whose agent reports the
// hunt ability, dispatches the spec, and summarises the matches; saved lists
// are created, renamed, refused when invalid or repeated, and deleted.
func TestIndicatorHunt(t *testing.T) {
	ctx := context.Background()
	s, _, device, now := evidenceFixture(t)
	old := Device{ID: "fedcba9876543210fedcba9876543210", Hostname: "old", OS: "windows", Architecture: "amd64", Certificate: "cert2", Fingerprint: "fp2"}
	if e := s.NewEnrollmentToken(ctx, "t2", now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e := s.EnrollDevice(ctx, "t2", old, now); e != nil {
		t.Fatal(e)
	}
	spec := protocol.HuntSpec{Files: true, Indicators: []protocol.Indicator{{Type: "sha256", Value: strings.Repeat("a", 64)}, {Type: "name", Value: "evil*.exe"}}}
	// No device can run it yet.
	if _, e := s.StartIndicatorHunt(ctx, LiveCase, []string{device}, nil, spec, "owner", now); !errors.Is(e, ErrHunt) {
		t.Fatal("hunt sent to an agent without the ability", e)
	}
	if e := s.RecordHeartbeat(ctx, device, "fp", protocol.Heartbeat{Hostname: "pc", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityHunt}}, now); e != nil {
		t.Fatal(e)
	}
	h, e := s.StartIndicatorHunt(ctx, LiveCase, []string{device, old.ID}, nil, spec, "owner", now)
	if e != nil || len(h.Targets) != 1 || h.Targets[0].DeviceID != device || len(h.Problems) != 1 || !strings.Contains(h.Problems[0].Reason, "indicator hunts") || h.Kind != "indicators" {
		t.Fatalf("hunt %+v %v", h, e)
	}
	result := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: protocol.ResponseAction{Kind: "hunt", Hunt: &spec},
		Hunt: &protocol.HuntResult{Outcome: "partial", Matches: []protocol.HuntMatch{{Area: "file", Indicator: spec.Indicators[1], Path: `C:\Users\a\Downloads\evil1.exe`}, {Area: "process", Indicator: spec.Indicators[0], PID: 8}}, Skipped: 3}}
	data, _ := json.Marshal(result)
	job := collect(t, s, device, now, data, &protocol.EvidenceMeta{Method: "action"})
	if job.Action == nil || job.Action.Kind != "hunt" || len(job.Action.Hunt.Indicators) != 2 || !job.Action.Hunt.Files {
		t.Fatalf("dispatched %+v", job.Action)
	}
	d, e := s.HuntDetail(ctx, h.ID)
	if e != nil || d.Spec == nil || len(d.Spec.Indicators) != 2 || len(d.Targets) != 1 || d.Targets[0].Events != 2 || d.Targets[0].Searched != "partial" || d.Targets[0].Skipped != 3 {
		t.Fatalf("detail %+v %+v %v", d.Spec, d.Targets, e)
	}
	list, _ := s.Hunts(ctx, "owner", true)
	if len(list) != 1 || list[0].Kind != "indicators" || list[0].Indicators != 2 || !list[0].Files {
		t.Fatalf("summary %+v", list)
	}
	// One search at a time per device (review fix): the second waits while
	// the first runs, the running one is handed out again only after the
	// resume interval (the agent ignores copies of a job it still runs), and
	// a hunt may wait behind a triage package.
	second, e := s.StartIndicatorHunt(ctx, LiveCase, []string{device}, nil, spec, "owner", now)
	third, e2 := s.StartIndicatorHunt(ctx, LiveCase, []string{device}, nil, spec, "owner", now.Add(time.Second))
	if e != nil || e2 != nil {
		t.Fatal(e, e2)
	}
	first, e := s.DispatchEvidence(ctx, device, "fp", now.Add(time.Minute))
	if e != nil || first.Job == nil || first.Job.ID != second.Targets[0].JobID {
		t.Fatalf("first %+v %v", first.Job, e)
	}
	var expires int64
	s.db.QueryRow(`SELECT expires_at FROM evidence_jobs WHERE id=?`, first.Job.ID).Scan(&expires)
	if expires != now.Add(time.Minute).Add(triageStartWindow+actionStartWindow).Unix() {
		t.Fatal("hunt start window", expires)
	}
	if d, e := s.DispatchEvidence(ctx, device, "fp", now.Add(2*time.Minute)); e != nil || d.Job != nil {
		t.Fatalf("second search handed out while one runs %+v %v", d.Job, e)
	}
	if d, e := s.DispatchEvidence(ctx, device, "fp", now.Add(10*time.Minute)); e != nil || d.Job == nil || d.Job.ID != first.Job.ID || !d.Job.Resumed {
		t.Fatalf("running search not handed out again %+v %v", d.Job, e)
	}
	if _, e = s.db.Exec(`UPDATE evidence_jobs SET status='succeeded' WHERE id=?`, first.Job.ID); e != nil {
		t.Fatal(e)
	}
	if d, e := s.DispatchEvidence(ctx, device, "fp", now.Add(11*time.Minute)); e != nil || d.Job == nil || d.Job.ID != third.Targets[0].JobID {
		t.Fatalf("next search %+v %v", d.Job, e)
	}
	// A single-device hunt (console) needs the ability too.
	if e := s.actionAbility(ctx, old.ID, protocol.ResponseAction{Kind: "hunt", Hunt: &spec}); !errors.Is(e, ErrActionUnsupported) {
		t.Fatal("console hunt on an old agent", e)
	}

	// Saved lists.
	l, e := s.SaveIOCList(ctx, "", "APT test", spec.Indicators, "alice", now)
	if e != nil || l.ID == "" || len(l.Indicators) != 2 || l.CreatedBy != "alice" {
		t.Fatal(l, e)
	}
	if _, e = s.SaveIOCList(ctx, "", "apt TEST", spec.Indicators, "bob", now); !errors.Is(e, ErrIOCList) {
		t.Fatal("repeated name accepted", e)
	}
	if _, e = s.SaveIOCList(ctx, "", "bad", []protocol.Indicator{{Type: "sha256", Value: "x"}}, "bob", now); !errors.Is(e, ErrIOCList) {
		t.Fatal("invalid indicator accepted", e)
	}
	l, e = s.SaveIOCList(ctx, l.ID, "APT renamed", spec.Indicators[:1], "bob", now.Add(time.Minute))
	if e != nil || l.Name != "APT renamed" || len(l.Indicators) != 1 || l.UpdatedBy != "bob" || l.CreatedBy != "alice" {
		t.Fatal(l, e)
	}
	if e = s.DeleteIOCList(ctx, l.ID, "bob", now); e != nil {
		t.Fatal(e)
	}
	if lists, e := s.IOCLists(ctx); e != nil || len(lists) != 0 {
		t.Fatal(lists, e)
	}
	if e = s.DeleteIOCList(ctx, l.ID, "bob", now); !errors.Is(e, ErrIOCList) {
		t.Fatal("deleted twice", e)
	}
	var audits int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action LIKE 'ioc_list_%'`).Scan(&audits)
	if audits != 3 {
		t.Fatal("audit", audits)
	}
}
