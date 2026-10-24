package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/patching"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func patchFixture(t *testing.T) (*Store, Device, time.Time, PatchPolicy) {
	t.Helper()
	s, d, now, _ := updateFixture(t)
	ctx := context.Background()
	if e := s.SetAdministrator(ctx, Administrator{Username: "admin", PasswordHash: "test", TOTPCipher: []byte("test")}, nil, false, now); e != nil {
		t.Fatal(e)
	}
	if e := s.ConfirmAdministrator(ctx, 1, 1, now); e != nil {
		t.Fatal(e)
	}
	patchSupport(t, s, d, now, true, true, true)
	c := PatchChange{Action: "save", ID: strings.Repeat("b", 32), Enabled: true, Definition: patching.Definition{Name: "Reviewed patches", Ring: "canary", Devices: []string{d.ID}, Weekday: int(now.Weekday()), Minute: now.Hour()*60 + now.Minute(), Duration: 120, Install: true, KB: []string{"12345"}, DeferHours: 24}}
	r, e := s.ChangePatchPolicy(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.ChangePatchPolicy(ctx, c, "admin", r.Digest, now)
	if e != nil {
		t.Fatal(e)
	}
	// Drive the scheduler with an explicit test clock; production never changes
	// a due time through the browser or catches up an elapsed start.
	if _, e = s.db.Exec("UPDATE patch_policies SET next_at=? WHERE id=?", now.Unix(), c.ID); e != nil {
		t.Fatal(e)
	}
	r.Policy.NextAt = now.Unix()
	return s, d, now, r.Policy
}
func patchSupport(t *testing.T, s *Store, d Device, now time.Time, windowed, install, restart bool) {
	t.Helper()
	ctx := context.Background()
	if e := s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: d.Hostname, OS: "windows", Architecture: "amd64", AgentVersion: "test"}, now); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(protocol.UpdateSupport{Broker: "available", Windowed: windowed, CanInstall: install, CanRestart: restart})
	if e := s.RecordUpdateSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: windowsupdate.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
}
func patchTick(t *testing.T, s *Store, now time.Time) {
	t.Helper()
	if e := s.EvaluatePatchPolicies(context.Background(), now, 120*time.Second); e != nil {
		t.Fatal(e)
	}
}
func patchOnlyRun(t *testing.T, s *Store) PatchRun {
	t.Helper()
	rows, e := s.PatchRuns(context.Background())
	if e != nil || len(rows) != 1 {
		t.Fatal("run count", len(rows), e)
	}
	return rows[0]
}
func patchDispatch(t *testing.T, s *Store, d Device, now time.Time, action string) protocol.UpdateJob {
	t.Helper()
	v, e := s.DispatchUpdateJob(context.Background(), d.ID, d.Fingerprint, now)
	if e != nil || v.Job == nil || v.Job.Action != action {
		t.Fatal("dispatch", action, e, v.Job)
	}
	return *v.Job
}
func patchScan(t *testing.T, s *Store, d Device, q protocol.UpdateJob, now time.Time, applicable, reboot bool) {
	t.Helper()
	p := windowsupdate.Failure(q, "ok")
	p.RebootKnown = true
	p.RebootRequired = reboot
	if applicable {
		p.Catalog = []protocol.WindowsUpdate{{UpdateIdentity: protocol.UpdateIdentity{ID: "11111111-2222-3333-4444-555555555555", Revision: 1}, Title: "Approved fixture", KB: []string{"12345"}}}
	}
	if e := s.RecordUpdateProgress(context.Background(), d.ID, d.Fingerprint, p, now); e != nil {
		t.Fatal(e)
	}
}
func TestPatchPolicyScanInstallVerifyAndNoReplay(t *testing.T) {
	s, d, now, _ := patchFixture(t)
	ctx := context.Background()
	patchTick(t, s, now)
	r := patchOnlyRun(t, s)
	if r.Status != "scanning" {
		t.Fatal(r.Status)
	}
	q := patchDispatch(t, s, d, now, "scan")
	if q.WindowStart != now.Unix() || q.WindowEnd != now.Add(2*time.Hour).Unix() {
		t.Fatal("missing window")
	}
	patchScan(t, s, d, q, now, true, false)
	patchTick(t, s, now)
	r = patchOnlyRun(t, s)
	if r.Status != "installing" || len(r.Selected) != 1 {
		t.Fatal("selection", r)
	}
	q = patchDispatch(t, s, d, now, "install")
	p := windowsupdate.Failure(q, "ok")
	p.RebootKnown = true
	p.Total = 1
	p.Completed = 1
	p.Items = []protocol.UpdateItemResult{{UpdateIdentity: q.Updates[0], Outcome: "ok"}}
	if e := s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, p, now); e != nil {
		t.Fatal(e)
	}
	patchTick(t, s, now)
	q = patchDispatch(t, s, d, now, "scan")
	if q.WindowStart != 0 {
		t.Fatal("post-install verification should be read only and may run later")
	}
	patchScan(t, s, d, q, now, false, false)
	patchTick(t, s, now)
	r = patchOnlyRun(t, s)
	if r.Status != "approved_complete" {
		t.Fatal(r.Status, r.Detail)
	}
	guards, e := s.PatchGuards(ctx)
	if e != nil || len(guards) != 1 || guards[0].Hold != "" {
		t.Fatal("hold not cleared", e, guards)
	}
	for i := 0; i < 3; i++ {
		patchTick(t, s, now)
	}
	jobs, e := s.UpdateJobs(ctx, d.ID, now)
	if e != nil || len(jobs) != 3 {
		t.Fatal("automatic replay", len(jobs), e)
	}
}
func TestPatchPolicyGuardsMissesAndDispatchRevocation(t *testing.T) {
	for _, mode := range []string{"old_broker", "offline", "install_denied", "truncated", "missed", "pause", "revoked", "window_closed", "unknown", "restart"} {
		t.Run(mode, func(t *testing.T) {
			s, d, now, policy := patchFixture(t)
			ctx := context.Background()
			if mode == "old_broker" {
				patchSupport(t, s, d, now, false, true, true)
			}
			if mode == "offline" {
				if _, e := s.db.Exec("UPDATE devices SET last_contact_at=?", now.Add(-3*time.Minute).Unix()); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "missed" {
				now = now.Add(61 * time.Second)
			}
			patchTick(t, s, now)
			r := patchOnlyRun(t, s)
			if mode == "old_broker" || mode == "offline" || mode == "missed" {
				if r.Status != "skipped" {
					t.Fatal(r.Status)
				}
				return
			}
			if mode == "pause" {
				c := PatchChange{ID: policy.ID, Revision: policy.Revision, Action: "pause"}
				v, e := s.ChangePatchPolicy(ctx, c, "admin", "", now)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = s.ChangePatchPolicy(ctx, c, "admin", v.Digest, now); e != nil {
					t.Fatal(e)
				}
				vjob, e := s.DispatchUpdateJob(ctx, d.ID, d.Fingerprint, now)
				if e != nil || vjob.Job != nil {
					t.Fatal("queued job survived pause", e)
				}
				if patchOnlyRun(t, s).Status != "paused" {
					t.Fatal("run survived pause")
				}
				return
			}
			if mode == "revoked" {
				if e := s.RevokeDevice(ctx, d.ID, now); e != nil {
					t.Fatal(e)
				}
				if _, e := s.DispatchUpdateJob(ctx, d.ID, d.Fingerprint, now); !errors.Is(e, ErrAuthentication) {
					t.Fatal("revocation", e)
				}
				return
			}
			q := patchDispatch(t, s, d, now, "scan")
			if mode == "truncated" {
				p := windowsupdate.Failure(q, "ok")
				p.RebootKnown = true
				p.Truncated = true
				if e := s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, p, now); e != nil {
					t.Fatal(e)
				}
				patchTick(t, s, now)
				if patchOnlyRun(t, s).Status != "unknown" {
					t.Fatal("partial scan compliant")
				}
				return
			}
			patchScan(t, s, d, q, now, true, false)
			if mode == "install_denied" {
				patchSupport(t, s, d, now, true, false, true)
			}
			if mode == "window_closed" {
				now = now.Add(2 * time.Hour)
				patchSupport(t, s, d, now, true, true, true)
			}
			patchTick(t, s, now)
			r = patchOnlyRun(t, s)
			if mode == "install_denied" || mode == "window_closed" {
				if r.Status != "blocked" && r.Status != "window_closed" {
					t.Fatal(r.Status)
				}
				return
			}
			q = patchDispatch(t, s, d, now, "install")
			if mode == "restart" {
				if e := s.InitializePatchPolicies(ctx, now); e != nil {
					t.Fatal(e)
				}
			} else {
				p := windowsupdate.Failure(q, "unknown")
				if e := s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, p, now); e != nil {
					t.Fatal(e)
				}
				patchTick(t, s, now)
			}
			r = patchOnlyRun(t, s)
			guards, e := s.PatchGuards(ctx)
			if e != nil || r.Status != "unknown" || guards[0].Hold != "needs_review" {
				t.Fatal("uncertainty lost", r.Status, guards, e)
			}
		})
	}
}
func TestPatchPolicySnapshotsReviewConflictAndMigration(t *testing.T) {
	s, d, now, p := patchFixture(t)
	ctx := context.Background()
	c := PatchChange{Action: "save", ID: p.ID, Revision: p.Revision, Enabled: true, Definition: p.Definition}
	r, e := s.ChangePatchPolicy(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	c.Definition.Name = "tampered"
	if _, e = s.ChangePatchPolicy(ctx, c, "admin", r.Digest, now); !errors.Is(e, patching.ErrInvalid) {
		t.Fatal("review tamper", e)
	}
	c.ID = strings.Repeat("c", 32)
	c.Revision = 0
	if _, e = s.ChangePatchPolicy(ctx, c, "admin", "", now); !errors.Is(e, patching.ErrInvalid) {
		t.Fatal("overlapping active ring")
	}
	c.Enabled = false
	if _, e = s.ChangePatchPolicy(ctx, c, "technician:fake", "", now); e == nil {
		t.Fatal("technician owner bypass")
	}
	if !strings.Contains(p.Definition.Devices[0], d.ID) {
		t.Fatal("snapshot")
	}
	path := filepath.Join(t.TempDir(), "private", "db")
	db, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := db.Info(ctx)
	rollbackFeatureSettings(t, db.db)
	for _, sql := range []string{"DROP TABLE IF EXISTS agent_ring_policy", "DELETE FROM schema_migrations WHERE version=27", "DROP TABLE IF EXISTS script_batches", "DELETE FROM schema_migrations WHERE version=26", "DROP TABLE IF EXISTS metric_buckets", "DROP TABLE IF EXISTS metric_receipts", "DELETE FROM schema_migrations WHERE version=25", "DROP TABLE patch_runs", "DROP TABLE patch_device_guards", "DROP TABLE patch_policies", "DELETE FROM schema_migrations WHERE version=24"} {
		if _, e = db.db.Exec(sql); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	db, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	after, _ := db.Info(ctx)
	if before != after {
		t.Fatal("schema-23 identity not retained")
	}
}

func TestPatchRestartDeferralAndFreshScanResolution(t *testing.T) {
	for _, deferred := range []bool{true, false} {
		t.Run(map[bool]string{true: "deferred", false: "requested"}[deferred], func(t *testing.T) {
			s, d, now, p := patchFixture(t)
			ctx := context.Background()
			c := PatchChange{Action: "save", ID: p.ID, Revision: p.Revision, Enabled: true, Definition: p.Definition}
			c.Definition.Restart = true
			r, e := s.ChangePatchPolicy(ctx, c, "admin", "", now)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.ChangePatchPolicy(ctx, c, "admin", r.Digest, now); e != nil {
				t.Fatal(e)
			}
			if _, e = s.db.Exec("UPDATE patch_policies SET next_at=?", now.Unix()); e != nil {
				t.Fatal(e)
			}
			tx, e := s.db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = patchGuardTx(ctx, tx, d.ID); e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec("UPDATE patch_device_guards SET reboot_since=?", now.Add(-25*time.Hour).Unix()); e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			if deferred {
				guards, _ := s.PatchGuards(ctx)
				g, digest, e := s.ChangePatchGuard(ctx, d.ID, "defer", guards[0].Revision, now.Add(time.Hour).Unix(), "admin", "", now)
				if e != nil {
					t.Fatal(e)
				}
				if _, _, e = s.ChangePatchGuard(ctx, d.ID, "defer", g.Revision, now.Add(time.Hour).Unix(), "admin", digest, now); e != nil {
					t.Fatal(e)
				}
			}
			patchTick(t, s, now)
			q := patchDispatch(t, s, d, now, "scan")
			patchScan(t, s, d, q, now, true, true)
			patchTick(t, s, now)
			run := patchOnlyRun(t, s)
			if deferred {
				if run.Status != "reboot_deferred" {
					t.Fatal(run.Status)
				}
				return
			}
			if run.Status != "restarting" {
				t.Fatal(run.Status, run.Detail)
			}
			q = patchDispatch(t, s, d, now, "restart")
			progress := windowsupdate.Failure(q, "restart_scheduled")
			progress.RebootKnown = true
			progress.RebootRequired = true
			if e = s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, progress, now); e != nil {
				t.Fatal(e)
			}
			patchTick(t, s, now)
			run = patchOnlyRun(t, s)
			guards, _ := s.PatchGuards(ctx)
			if run.Status != "restart_requested" || guards[0].Hold != "restart_requested" {
				t.Fatal("restart claimed complete", run.Status, guards)
			}
			scan := UpdateJob{UpdateJob: protocol.UpdateJob{ID: strings.Repeat("e", 32), Action: "scan", ExpiresAt: now.Add(time.Minute).Unix()}, DeviceID: d.ID, Actor: "admin"}
			if e = s.QueueUpdateJob(ctx, scan, now, time.Minute); e != nil {
				t.Fatal(e)
			}
			q = patchDispatch(t, s, d, now, "scan")
			patchScan(t, s, d, q, now, false, false)
			guards, _ = s.PatchGuards(ctx)
			if guards[0].Hold != "" || guards[0].RebootSince != nil {
				t.Fatal("fresh scan did not clear known restart episode")
			}
		})
	}
}
func TestPatchDispatchedEditHoldAcknowledgementAndAuditAtomicity(t *testing.T) {
	s, d, now, p := patchFixture(t)
	ctx := context.Background()
	patchTick(t, s, now)
	q := patchDispatch(t, s, d, now, "scan")
	patchScan(t, s, d, q, now, true, false)
	patchTick(t, s, now)
	q = patchDispatch(t, s, d, now, "install")
	c := PatchChange{Action: "pause", ID: p.ID, Revision: p.Revision}
	review, e := s.ChangePatchPolicy(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`CREATE TRIGGER deny_patch_audit BEFORE INSERT ON audit_events WHEN NEW.action LIKE 'patch_%' BEGIN SELECT RAISE(ABORT,'test'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ChangePatchPolicy(ctx, c, "admin", review.Digest, now); e == nil {
		t.Fatal("audit failure accepted")
	}
	rows, _ := s.PatchPolicies(ctx)
	if rows[0].State != "active" || patchOnlyRun(t, s).FinishedAt != nil {
		t.Fatal("failed audit changed policy or run")
	}
	s.db.Exec("DROP TRIGGER deny_patch_audit")
	if _, e = s.ChangePatchPolicy(ctx, c, "admin", review.Digest, now); e != nil {
		t.Fatal(e)
	}
	g, _ := s.PatchGuards(ctx)
	if g[0].Hold != "needs_review" {
		t.Fatal("dispatched mutation lost hold")
	}
	if _, _, e = s.ChangePatchGuard(ctx, d.ID, "acknowledge", g[0].Revision, 0, "admin", "", now); e == nil {
		t.Fatal("hold cleared while update running")
	}
	progress := windowsupdate.Failure(q, "unknown")
	if e = s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, progress, now); e != nil {
		t.Fatal(e)
	}
	guard, digest, e := s.ChangePatchGuard(ctx, d.ID, "acknowledge", g[0].Revision, 0, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ChangePatchGuard(ctx, d.ID, "acknowledge", guard.Revision, 0, "admin", digest, now); e != nil {
		t.Fatal(e)
	}
	g, _ = s.PatchGuards(ctx)
	if g[0].Hold != "" {
		t.Fatal("reviewed acknowledgement failed")
	}
}

func TestPatchLostUpdateRecordEndsUnknownWithoutReplay(t *testing.T) {
	s, d, now, _ := patchFixture(t)
	patchTick(t, s, now)
	q := patchDispatch(t, s, d, now, "scan")
	patchScan(t, s, d, q, now, true, false)
	patchTick(t, s, now)
	q = patchDispatch(t, s, d, now, "install")
	if _, e := s.db.Exec("DELETE FROM update_jobs WHERE id=?", q.ID); e != nil {
		t.Fatal(e)
	}
	patchTick(t, s, now)
	r := patchOnlyRun(t, s)
	g, e := s.PatchGuards(context.Background())
	if e != nil || r.Status != "unknown" || r.Detail != "update_job_unavailable" || len(g) != 1 || g[0].Hold != "needs_review" {
		t.Fatal(r.Status, g, e)
	}
}

func TestPatchPartialScanCannotClearRestartHold(t *testing.T) {
	s, d, now, _ := patchFixture(t)
	if _, e := s.db.Exec("INSERT INTO patch_device_guards(device_id,hold,reboot_since)VALUES(?,'restart_requested',?)", d.ID, now.Add(-24*time.Hour).Unix()); e != nil {
		t.Fatal(e)
	}
	patchTick(t, s, now)
	q := patchDispatch(t, s, d, now, "scan")
	p := windowsupdate.Failure(q, "ok")
	p.RebootKnown = true
	p.Truncated = true
	if e := s.RecordUpdateProgress(context.Background(), d.ID, d.Fingerprint, p, now); e != nil {
		t.Fatal(e)
	}
	patchTick(t, s, now)
	g, e := s.PatchGuards(context.Background())
	if e != nil || len(g) != 1 || g[0].Hold != "restart_requested" || g[0].RebootSince == nil || patchOnlyRun(t, s).Status != "unknown" {
		t.Fatal("partial observation cleared hold", g, e)
	}
}
