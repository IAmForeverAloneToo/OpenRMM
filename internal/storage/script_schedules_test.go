package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"strings"
	"sync"
	"testing"
	"time"
)

func scheduleFixture(t *testing.T) (*Store, Device, ScriptVersion, ScriptSchedule, time.Time) {
	s, d, v, now := scriptFixture(t)
	q := ScriptSchedule{ID: strings.Repeat("9", 32), DeviceID: d.ID, VersionID: v.ID, Name: "Fixture schedule", Arguments: map[string]string{"Message": "private parameter"}, StartAt: now.Add(10 * time.Second).Unix(), Interval: 300, Actor: "admin"}
	if e := s.SaveScriptSchedule(context.Background(), q, now); e != nil {
		t.Fatal(e)
	}
	return s, d, v, q, now
}
func freshScheduleDevice(t *testing.T, s *Store, d Device, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if e := s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: d.Hostname, OS: d.OS, Architecture: d.Architecture, AgentVersion: "test"}, now); e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "enabled"})
	if e := s.RecordScriptSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: data}, now); e != nil {
		t.Fatal(e)
	}
}
func TestScheduleAtomicDueDispatchPinnedVersionAndNoReplay(t *testing.T) {
	s, d, v, q, now := scheduleFixture(t)
	ctx := context.Background()
	v2 := v
	v2.ID = strings.Repeat("8", 32)
	v2.Definition.Body = "Write-Output changed"
	if _, e := s.CreateScriptVersion(ctx, v2, now); e != nil {
		t.Fatal(e)
	}
	due := time.Unix(q.StartAt, 0)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if e := s.EvaluateScriptSchedules(ctx, due, time.Minute); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	occurrences, e := s.ScriptOccurrences(ctx, d.ID, q.ID, due)
	if e != nil || len(occurrences) != 1 || occurrences[0].RunID == nil || occurrences[0].Outcome != "queued" {
		t.Fatal(occurrences, e)
	}
	run := *occurrences[0].RunID
	dispatched, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, due)
	if e != nil || dispatched.Job == nil || dispatched.Job.ID != run || dispatched.Job.Version.Hash != v.Hash || dispatched.Job.Arguments["Message"] != "private parameter" {
		t.Fatal("pinned dispatch", e)
	}
	if again, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, due); e != nil || again.Job != nil {
		t.Fatal("replayed")
	}
	if e = s.InitializeScriptSchedules(ctx, due.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if again, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, due.Add(time.Second)); e != nil || again.Job != nil {
		t.Fatal("restart replayed")
	}
	// Unknown execution is never retried, even while the next interval proceeds.
	next := due.Add(300 * time.Second)
	freshScheduleDevice(t, s, d, next)
	if e = s.EvaluateScriptSchedules(ctx, next, time.Minute); e != nil {
		t.Fatal(e)
	}
	occurrences, _ = s.ScriptOccurrences(ctx, d.ID, q.ID, next)
	if len(occurrences) != 2 || occurrences[0].RunID == nil || *occurrences[0].RunID == run {
		t.Fatal("next occurrence identity")
	}
	var leaked int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE target LIKE '%private parameter%' OR outcome LIKE '%private parameter%'").Scan(&leaked)
	if leaked != 0 {
		t.Fatal("private arguments audited")
	}
}
func TestScheduleMissedUnavailableAndDeliveryExpiry(t *testing.T) {
	for _, mode := range []string{"offline", "busy", "disabled", "system_disabled", "stale", "revoked", "missed", "restart", "delivery_expiry"} {
		t.Run(mode, func(t *testing.T) {
			s, d, v, q, now := scheduleFixture(t)
			ctx := context.Background()
			due := time.Unix(q.StartAt, 0)
			switch mode {
			case "offline":
				s.db.Exec("UPDATE devices SET last_contact_at=? WHERE id=?", due.Add(-5*time.Minute).Unix(), d.ID)
			case "busy":
				if e := s.QueueScriptRun(ctx, scriptRequest(d, v, strings.Repeat("7", 32)), now, time.Minute); e != nil {
					t.Fatal(e)
				}
			case "disabled":
				s.db.Exec("UPDATE device_script_support SET last_status='disabled'")
			case "system_disabled":
				v.ID = strings.Repeat("8", 32)
				v.Definition.RunAs = "system"
				if _, e := s.CreateScriptVersion(ctx, v, now); e != nil {
					t.Fatal(e)
				}
				s.db.Exec("UPDATE script_schedules SET version_id=?", v.ID)
				data, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "disabled"})
				if e := s.RecordScriptSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: data}, now); e != nil {
					t.Fatal(e)
				}
			case "stale":
				s.db.Exec("UPDATE device_script_support SET reported_at=?", due.Add(-3*time.Minute).Unix())
			case "revoked":
				s.db.Exec("UPDATE devices SET revoked_at=?", now.Unix())
			case "missed":
				due = due.Add(2 * time.Hour)
			}
			var e error
			if mode == "restart" {
				e = s.InitializeScriptSchedules(ctx, due)
			} else {
				e = s.EvaluateScriptSchedules(ctx, due, time.Minute)
			}
			if e != nil {
				t.Fatal(e)
			}
			items, e := s.ScriptOccurrences(ctx, d.ID, q.ID, due)
			if e != nil || len(items) != 1 {
				t.Fatal(items, e)
			}
			want := "skipped_unavailable"
			if mode == "missed" {
				want = "skipped_missed"
				if items[0].Count != 25 {
					t.Fatal("missed aggregate", items[0])
				}
			}
			if mode == "restart" {
				want = "skipped_restart"
			}
			if mode == "delivery_expiry" {
				want = "queued"
			}
			if items[0].Outcome != want {
				t.Fatal(items[0], want)
			}
			if mode == "delivery_expiry" {
				freshScheduleDevice(t, s, d, due.Add(31*time.Second))
				if p, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, due.Add(31*time.Second)); e != nil || p.Job != nil {
					t.Fatal("late delivery")
				}
			}
			stored, _ := s.ScriptSchedule(ctx, d.ID, q.ID)
			if stored.NextAt <= due.Unix() {
				t.Fatal("not advanced")
			}
			if e = s.EvaluateScriptSchedules(ctx, due, time.Minute); e != nil {
				t.Fatal(e)
			}
			if items, _ = s.ScriptOccurrences(ctx, d.ID, q.ID, due); len(items) != 1 {
				t.Fatal("duplicate occurrence")
			}
		})
	}
}
func TestSchedulePauseResumeEditCancelAndStaleRevision(t *testing.T) {
	s, d, _, q, now := scheduleFixture(t)
	ctx := context.Background()
	due := time.Unix(q.StartAt, 0)
	if e := s.EvaluateScriptSchedules(ctx, due, time.Minute); e != nil {
		t.Fatal(e)
	}
	if e := s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "pause", 1, due); e != nil {
		t.Fatal(e)
	}
	runs, _ := s.ScriptRuns(ctx, d.ID, due)
	if len(runs) != 1 || runs[0].Status != "cancelled" {
		t.Fatal("pause kept queue")
	}
	if e := s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "resume", 1, due); !errors.Is(e, ErrSchedule) {
		t.Fatal("stale form accepted")
	}
	future := due.Add(20 * time.Minute)
	if e := s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "resume", 2, future); e != nil {
		t.Fatal(e)
	}
	stored, _ := s.ScriptSchedule(ctx, d.ID, q.ID)
	if stored.State != "active" || stored.NextAt <= future.Unix() {
		t.Fatal("resume caught up")
	}
	if e := s.EvaluateScriptSchedules(ctx, future, time.Minute); e != nil {
		t.Fatal(e)
	}
	items, _ := s.ScriptOccurrences(ctx, d.ID, q.ID, future)
	if len(items) != 2 || items[0].Outcome != "skipped_paused" {
		t.Fatal("pause history", items)
	}
	// Edit requires review of a fresh start, preserves pause, invalidates stale revision.
	if e := s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "pause", 3, future); e != nil {
		t.Fatal(e)
	}
	q.Revision = 4
	q.StartAt = future.Add(time.Hour).Unix()
	q.Name = "Edited"
	for range 2 {
		if e := s.SaveScriptSchedule(ctx, q, future); e != nil {
			t.Fatal(e)
		}
	}
	stored, _ = s.ScriptSchedule(ctx, d.ID, q.ID)
	if stored.State != "paused" || stored.Revision != 5 || stored.Name != "Edited" {
		t.Fatal(stored)
	}
	if e := s.ChangeScriptSchedule(ctx, strings.Repeat("6", 32), q.ID, "admin", "cancel", 5, future); !errors.Is(e, ErrSchedule) {
		t.Fatal("wrong device accepted")
	}
	if e := s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "cancel", 5, future); e != nil {
		t.Fatal(e)
	}
	q.Revision = 6
	if e := s.SaveScriptSchedule(ctx, q, now); !errors.Is(e, ErrSchedule) {
		t.Fatal("cancelled resurrected")
	}
}
func TestScheduleOnceStartupCancelsQueuedAndPausedOnceCompletes(t *testing.T) {
	for _, mode := range []string{"queued_once", "paused_once", "dispatched_once"} {
		t.Run(mode, func(t *testing.T) {
			s, d, _, q, now := scheduleFixture(t)
			ctx := context.Background()
			q.Revision = 1
			q.Interval = 0
			if e := s.SaveScriptSchedule(ctx, q, now); e != nil {
				t.Fatal(e)
			}
			due := time.Unix(q.StartAt, 0)
			if mode == "paused_once" {
				if e := s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "pause", 2, now); e != nil {
					t.Fatal(e)
				}
				if e := s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "resume", 3, due); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := s.EvaluateScriptSchedules(ctx, due, time.Minute); e != nil {
					t.Fatal(e)
				}
				if mode == "dispatched_once" {
					if _, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, due); e != nil {
						t.Fatal(e)
					}
				}
				if e := s.InitializeScriptSchedules(ctx, due.Add(time.Second)); e != nil {
					t.Fatal(e)
				}
				runs, _ := s.ScriptRuns(ctx, d.ID, due)
				if len(runs) != 1 {
					t.Fatal(runs)
				}
				if mode == "queued_once" && runs[0].Status != "cancelled" {
					t.Fatal("startup kept once queue")
				}
				if mode == "dispatched_once" && runs[0].Status != "dispatched" {
					t.Fatal("startup rewrote dispatched job")
				}
			}
			stored, _ := s.ScriptSchedule(ctx, d.ID, q.ID)
			if stored.State != "completed" {
				t.Fatal("once not complete")
			}
			if p, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, due); e != nil || p.Job != nil {
				t.Fatal("once replayed")
			}
		})
	}
}
func TestScheduleValidationCapacityAndRetention(t *testing.T) {
	s, d, _, q, now := scheduleFixture(t)
	ctx := context.Background()
	for _, edit := range []func(*ScriptSchedule){func(v *ScriptSchedule) { v.Interval = 1 }, func(v *ScriptSchedule) { v.Interval = 2592001 }, func(v *ScriptSchedule) { v.StartAt = now.Unix() }, func(v *ScriptSchedule) { v.Arguments = map[string]string{} }, func(v *ScriptSchedule) { v.Actor = "" }} {
		v := q
		v.ID = strings.Repeat("8", 32)
		edit(&v)
		if e := s.SaveScriptSchedule(ctx, v, now); !errors.Is(e, ErrSchedule) {
			t.Fatal("invalid accepted", e)
		}
	}
	for i := 1; i < 100; i++ {
		q.ID = fmt.Sprintf("%032x", i)
		if e := s.SaveScriptSchedule(ctx, q, now); e != nil {
			t.Fatal(e)
		}
	}
	q.ID = strings.Repeat("8", 32)
	if e := s.SaveScriptSchedule(ctx, q, now); !errors.Is(e, ErrSchedule) {
		t.Fatal("capacity accepted")
	}
	// History eviction unlinks runs safely; schedule records remain for review.
	for i := range 2010 {
		if _, e := s.db.Exec("INSERT INTO script_schedule_occurrences(schedule_id,revision,due_at,recorded_at,outcome) VALUES(?,1,?,?,'skipped_missed')", qForRetention(), i, now.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.EvaluateScriptSchedules(ctx, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM script_schedule_occurrences").Scan(&count)
	if count != 2000 {
		t.Fatal("history cap", count)
	}
	if e := s.EvaluateScriptSchedules(ctx, now.Add(31*24*time.Hour), time.Minute); e != nil {
		t.Fatal(e)
	}
	items, _ := s.ScriptOccurrences(ctx, d.ID, qForRetention(), now.Add(31*24*time.Hour))
	if len(items) != 1 {
		t.Fatal("old history retained", len(items))
	}
}
func qForRetention() string { return strings.Repeat("9", 32) }

func TestScheduleTransactionFailureAndClockRollbackCannotDuplicate(t *testing.T) {
	s, d, _, q, now := scheduleFixture(t)
	ctx := context.Background()
	due := time.Unix(q.StartAt, 0)
	if _, e := s.db.Exec(`CREATE TRIGGER fail_occurrence BEFORE INSERT ON script_schedule_occurrences BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if e := s.EvaluateScriptSchedules(ctx, due, time.Minute); e == nil {
		t.Fatal("injected failure accepted")
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM script_runs").Scan(&count)
	stored, _ := s.ScriptSchedule(ctx, d.ID, q.ID)
	if count != 0 || stored.NextAt != q.StartAt {
		t.Fatal("partial transaction committed")
	}
	if _, e := s.db.Exec("DROP TRIGGER fail_occurrence"); e != nil {
		t.Fatal(e)
	}
	if e := s.EvaluateScriptSchedules(ctx, due, time.Minute); e != nil {
		t.Fatal(e)
	}
	for _, stamp := range []time.Time{now, due.Add(-time.Second), due} {
		if e := s.EvaluateScriptSchedules(ctx, stamp, time.Minute); e != nil {
			t.Fatal(e)
		}
	}
	items, _ := s.ScriptOccurrences(ctx, d.ID, q.ID, due)
	if len(items) != 1 || items[0].RunID == nil {
		t.Fatal("clock rollback duplicated")
	}
}
