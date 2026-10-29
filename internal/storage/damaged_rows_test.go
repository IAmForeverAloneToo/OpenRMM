package storage

import (
	"context"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func auditCount(t *testing.T, s *Store, action string) int {
	t.Helper()
	var n int
	if e := s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action=?", action).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

// A schedule whose stored arguments cannot be read is paused once and can be
// cancelled; the other schedules and the server start are not affected.
func TestDamagedScheduleIsPausedNotFatal(t *testing.T) {
	s, d, _, q, now := scheduleFixture(t)
	ctx := context.Background()
	if _, e := s.db.Exec("UPDATE script_schedules SET arguments_json='{damaged' WHERE id=?", q.ID); e != nil {
		t.Fatal(e)
	}
	if e := s.InitializeScriptSchedules(ctx, now); e != nil {
		t.Fatal("startup stopped by a damaged schedule", e)
	}
	if e := s.EvaluateScriptSchedules(ctx, now.Add(time.Minute), 120*time.Second); e != nil {
		t.Fatal("evaluation stopped by a damaged schedule", e)
	}
	if n := auditCount(t, s, "script_schedule_damaged"); n != 1 {
		t.Fatal("damage not audited exactly once", n)
	}
	list, e := s.ScriptSchedules(ctx, d.ID)
	if e != nil || len(list) != 1 || list[0].State != "paused" || list[0].Arguments == nil {
		t.Fatal("damaged schedule not listed as paused", list, e)
	}
	if e = s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "resume", list[0].Revision, now); e == nil {
		t.Fatal("damaged schedule resumed")
	}
	if e = s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "cancel", list[0].Revision, now); e != nil {
		t.Fatal("damaged schedule cannot be cancelled", e)
	}
}

// A damaged patch policy is paused and hidden; a damaged active run is ended.
// Patching continues and the server still starts.
func TestDamagedPatchRecordsAreSetAside(t *testing.T) {
	s, _, now, p := patchFixture(t)
	ctx := context.Background()
	patchTick(t, s, now)
	run := patchOnlyRun(t, s)
	if _, e := s.db.Exec("UPDATE patch_runs SET definition_json='[' WHERE id=?", run.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec("UPDATE patch_policies SET definition_json='[' WHERE id=?", p.ID); e != nil {
		t.Fatal(e)
	}
	patchTick(t, s, now.Add(5*time.Second))
	var status, detail, state string
	if e := s.db.QueryRow("SELECT status,detail FROM patch_runs WHERE id=?", run.ID).Scan(&status, &detail); e != nil || status != "unknown" || detail != "damaged_record" {
		t.Fatal("damaged run not ended", status, detail, e)
	}
	if e := s.db.QueryRow("SELECT state FROM patch_policies WHERE id=?", p.ID).Scan(&state); e != nil || state != "paused" {
		t.Fatal("damaged policy not paused", state, e)
	}
	patchTick(t, s, now.Add(10*time.Second))
	if n := auditCount(t, s, "patch_policy_damaged"); n != 1 {
		t.Fatal("damage not audited exactly once", n)
	}
	if list, e := s.PatchPolicies(ctx); e != nil || len(list) != 0 {
		t.Fatal("damaged policy listed", list, e)
	}
	if e := s.InitializePatchPolicies(ctx, now.Add(time.Minute)); e != nil {
		t.Fatal("startup stopped by a damaged policy", e)
	}
}

// A damaged alert state starts over, damaged tags read as none, and a
// damaged monitoring policy fails closed: every feature off for its devices.
func TestDamagedAlertAndOrganizationRows(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	o := organizationRead(t, s)
	organizationApply(t, s, clonePolicy(o, "watched", 50), now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, PolicyID: "watched", Tags: []string{"lab"}}, now)
	for _, q := range []string{
		"UPDATE alert_states SET state_json='{' WHERE device_id='" + d.ID + "'",
		// Columns with a JSON check hold valid JSON with wrong content.
		`UPDATE monitoring_policies SET features_json='{"unknown-feature":false}' WHERE id='watched'`,
		`UPDATE device_organization SET tags_json='{"tags":1}' WHERE device_id='` + d.ID + "'",
	} {
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.InitializeAlerts(ctx, 120*time.Second, "test-mail", now); e != nil {
		t.Fatal("startup stopped by a damaged alert state", e)
	}
	if e := s.EvaluateAlerts(ctx, now.Add(15*time.Second)); e != nil {
		t.Fatal("evaluation stopped by damaged rows", e)
	}
	o = organizationRead(t, s)
	var policy MonitoringPolicy
	for _, p := range o.Policies {
		if p.ID == "watched" {
			policy = p
		}
	}
	if !policy.Damaged || len(policy.Rules) != len(o.Defaults) {
		t.Fatal("damaged policy not flagged", policy)
	}
	for _, dev := range o.Devices {
		if dev.ID == d.ID && (len(dev.Tags) != 0 || len(o.EffectiveDisabled(dev)) != len(protocol.AgentFeatures)) {
			t.Fatal("damaged policy did not fail closed", dev, o.EffectiveDisabled(dev))
		}
	}
}
