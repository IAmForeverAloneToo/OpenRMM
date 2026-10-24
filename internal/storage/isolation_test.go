package storage

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/isolation"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Isolation needs the agent's ability, goes before other work,
// carries only the release code's hash, follows the states the agent
// reports (isolated, released by the server, the break-glass code or a timed
// release), and closes isolations that failed or were released before the
// device took them.
func TestIsolationLifecycle(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	if _, e := s.IsolateDevice(ctx, LiveCase, device, "owner", 0, now); !errors.Is(e, ErrActionUnsupported) {
		t.Fatal("isolated without the ability", e)
	}
	beat := func(st *protocol.IsolationState, at time.Time) {
		t.Helper()
		if e := s.RecordHeartbeat(ctx, device, "fp", protocol.Heartbeat{Hostname: "pc", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityIsolation}, Isolation: st}, at); e != nil {
			t.Fatal(e)
		}
	}
	beat(nil, now)
	// A collection queued first still waits behind the isolation.
	if _, e := s.QueueEvidence(ctx, caseID, device, `C:\x.txt`, "owner", now); e != nil {
		t.Fatal(e)
	}
	v, e := s.IsolateDevice(ctx, caseID, device, "owner", 3600, now.Add(time.Second))
	if e != nil || v.Phase != "isolating" || !regexp.MustCompile(`^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$`).MatchString(v.Code) || v.ReleaseAfter != 3600 {
		t.Fatalf("isolate %+v %v", v, e)
	}
	if _, e = s.IsolateDevice(ctx, LiveCase, device, "owner", 0, now); !errors.Is(e, ErrIsolationBusy) {
		t.Fatal("isolated twice", e)
	}
	d, e := s.DispatchEvidence(ctx, device, "fp", now.Add(2*time.Second))
	if e != nil || d.Job == nil || d.Job.ID != v.IsolateJob || d.Job.Action.Kind != "isolate" || d.Job.Action.Isolate.CodeHash != isolation.HashCode(v.Code) || d.Job.Action.Isolate.ReleaseAfter != 3600 {
		t.Fatalf("dispatch %+v %v", d.Job, e)
	}
	phases, _ := s.IsolationPhases(ctx)
	if phases[device] != "isolating" {
		t.Fatal(phases)
	}
	st := &protocol.IsolationState{Isolated: true, Mode: "dry_run", Since: "2026-10-23T12:00:00Z", Job: v.IsolateJob, Rules: []protocol.IsolationRule{{Purpose: "server", Direction: "out", Protocol: "tcp", Remote: "192.0.2.10/32", Port: 8444}}}
	beat(st, now.Add(3*time.Second))
	if v, e = s.DeviceIsolation(ctx, device); e != nil || v.Phase != "isolated" || v.IsolatedAt == nil || v.Code == "" {
		t.Fatalf("isolated %+v %v", v, e)
	}
	if r, e := s.ReportedIsolation(ctx, device); e != nil || !r.Isolated || len(r.Rules) != 1 {
		t.Fatalf("reported %+v %v", r, e)
	}
	if v, e = s.ReleaseDevice(ctx, device, "tech", now.Add(4*time.Second)); e != nil || v.Phase != "releasing" || v.ReleaseJob == "" || v.ReleaseActor != "tech" {
		t.Fatalf("release %+v %v", v, e)
	}
	beat(&protocol.IsolationState{Released: "server", ReleasedAt: "2026-10-23T12:01:00Z", Job: v.IsolateJob}, now.Add(5*time.Second))
	if v, e = s.DeviceIsolation(ctx, device); e != nil || v.Phase != "released" || v.ReleaseReason != "server" || v.Code != "" {
		t.Fatalf("released %+v %v", v, e)
	}
	if _, e = s.ReleaseDevice(ctx, device, "tech", now); !errors.Is(e, ErrNotIsolated) {
		t.Fatal("released twice", e)
	}

	// Break-glass: recorded in the case when the device reports it.
	v, e = s.IsolateDevice(ctx, caseID, device, "owner", 0, now.Add(10*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	beat(&protocol.IsolationState{Isolated: true, Mode: "dry_run", Job: v.IsolateJob}, now.Add(11*time.Second))
	beat(&protocol.IsolationState{Released: "break_glass", ReleasedAt: "2026-10-23T12:02:00Z", Job: v.IsolateJob}, now.Add(12*time.Second))
	if v, e = s.DeviceIsolation(ctx, device); e != nil || v.ReleaseReason != "break_glass" {
		t.Fatalf("break glass %+v %v", v, e)
	}
	var custody int
	s.db.QueryRow(`SELECT COUNT(*) FROM custody_entries WHERE case_id=? AND action='isolation_released'`, caseID).Scan(&custody)
	if custody != 1 {
		t.Fatal("break glass not in the case", custody)
	}

	// Released before the device took it: the isolate action is cancelled.
	v, e = s.IsolateDevice(ctx, LiveCase, device, "owner", 0, now.Add(20*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if v, e = s.ReleaseDevice(ctx, device, "owner", now.Add(21*time.Second)); e != nil || v.Phase != "released" || v.ReleaseJob != "" {
		t.Fatalf("early release %+v %v", v, e)
	}

	// An isolate action that ran without isolating counts as failed after the
	// grace, and a new isolation is possible.
	v, e = s.IsolateDevice(ctx, LiveCase, device, "owner", 0, now.Add(30*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`UPDATE evidence_jobs SET status='succeeded',finished_at=? WHERE id=?`, now.Add(31*time.Second).Unix(), v.IsolateJob); e != nil {
		t.Fatal(e)
	}
	if _, e = s.IsolateDevice(ctx, LiveCase, device, "owner", 0, now.Add(5*time.Minute)); !errors.Is(e, ErrIsolationBusy) {
		t.Fatal("failed too early", e)
	}
	failedJob := v.IsolateJob
	v, e = s.IsolateDevice(ctx, LiveCase, device, "owner", 0, now.Add(20*time.Minute))
	if e != nil {
		t.Fatal("not retried after a failed isolation", e)
	}
	var failed int
	s.db.QueryRow(`SELECT COUNT(*) FROM device_isolations WHERE release_reason='failed'`).Scan(&failed)
	if failed != 1 {
		t.Fatal("failed", failed)
	}
	// Cancel the retry, then a late heartbeat reports the "failed" one
	// isolated after all: it is open again, with its code, and can be
	// released.
	if _, e = s.ReleaseDevice(ctx, device, "owner", now.Add(21*time.Minute)); e != nil {
		t.Fatal(e)
	}
	beat(&protocol.IsolationState{Isolated: true, Mode: "dry_run", Job: failedJob}, now.Add(22*time.Minute))
	var reopened string
	s.db.QueryRow(`SELECT release_reason FROM device_isolations WHERE isolate_job=?`, failedJob).Scan(&reopened)
	phases, _ = s.IsolationPhases(ctx)
	if reopened != "" || phases[device] != "isolated" {
		t.Fatal("late report", reopened, phases)
	}
	r, e := s.ReleaseDevice(ctx, device, "owner", now.Add(23*time.Minute))
	if e != nil || r.ReleaseJob == "" {
		t.Fatalf("release after a late report %+v %v", r, e)
	}
	// The release expired while the device was offline: it can be asked again.
	if _, e = s.db.Exec(`UPDATE evidence_jobs SET status='expired',finished_at=? WHERE id=?`, now.Add(90*time.Minute).Unix(), r.ReleaseJob); e != nil {
		t.Fatal(e)
	}
	again, e := s.ReleaseDevice(ctx, device, "owner", now.Add(91*time.Minute))
	if e != nil || again.ReleaseJob == "" || again.ReleaseJob == r.ReleaseJob {
		t.Fatalf("release not retried %+v %v", again, e)
	}
	// A job listing never shows the release code's hash.
	var job EvidenceJob
	job.Action = `{"kind":"isolate","isolate":{"allow":[],"code_hash":"` + isolation.HashCode("x") + `"}}`
	b, _ := json.Marshal(job)
	if strings.Contains(string(b), isolation.HashCode("x")) {
		t.Fatal("code hash in a job listing")
	}
}
