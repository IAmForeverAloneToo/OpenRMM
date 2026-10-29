package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func rowCount(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if e := s.db.QueryRow(query, args...).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

// A script keeps its newest ten versions and older ones only while
// something uses them, so editing never runs into the version limit.
func TestScriptVersionsArePruned(t *testing.T) {
	s, d, first, now := scriptFixture(t)
	ctx := context.Background()
	// The first version stays in use by a schedule.
	q := ScriptSchedule{ID: strings.Repeat("9", 32), DeviceID: d.ID, VersionID: first.ID, Name: "Uses v1", Arguments: map[string]string{"Message": "x"}, StartAt: now.Add(time.Hour).Unix(), Interval: 300, Actor: "admin"}
	if e := s.SaveScriptSchedule(ctx, q, now); e != nil {
		t.Fatal(e)
	}
	for i := 2; i <= 25; i++ {
		v := first
		v.ID = fmt.Sprintf("%032x", i)
		v.Definition.Body = fmt.Sprintf("Write-Output %d", i)
		if _, e := s.CreateScriptVersion(ctx, v, now); e != nil {
			t.Fatal("version", i, e)
		}
	}
	if n := rowCount(t, s, "SELECT COUNT(*) FROM script_versions WHERE script_id=?", first.ScriptID); n != keptScriptVersions+1 {
		t.Fatal("versions kept", n)
	}
	if n := rowCount(t, s, "SELECT COUNT(*) FROM script_versions WHERE id=?", first.ID); n != 1 {
		t.Fatal("version in use pruned")
	}
	if n := rowCount(t, s, "SELECT MIN(version) FROM script_versions WHERE script_id=? AND id<>?", first.ScriptID, first.ID); n != 25-keptScriptVersions+1 {
		t.Fatal("wrong versions kept", n)
	}
}

// Finished schedules go after 30 days, archived patch policies after 90.
func TestFinishedSchedulesAndArchivedPoliciesArePruned(t *testing.T) {
	s, d, _, q, now := scheduleFixture(t)
	ctx := context.Background()
	if e := s.ChangeScriptSchedule(ctx, d.ID, q.ID, "admin", "cancel", 1, now); e != nil {
		t.Fatal(e)
	}
	if e := s.EvaluateScriptSchedules(ctx, now.Add(29*24*time.Hour), 120*time.Second); e != nil {
		t.Fatal(e)
	}
	if n := rowCount(t, s, "SELECT COUNT(*) FROM script_schedules"); n != 1 {
		t.Fatal("finished schedule pruned early")
	}
	if e := s.EvaluateScriptSchedules(ctx, now.Add(31*24*time.Hour), 120*time.Second); e != nil {
		t.Fatal(e)
	}
	if n := rowCount(t, s, "SELECT COUNT(*) FROM script_schedules"); n != 0 {
		t.Fatal("finished schedule kept after 30 days")
	}

	p, _, pnow, policy := patchFixture(t)
	if _, e := p.db.Exec("UPDATE patch_policies SET state='archived',updated_at=? WHERE id=?", pnow.Unix(), policy.ID); e != nil {
		t.Fatal(e)
	}
	if e := p.EvaluatePatchPolicies(ctx, pnow.Add(89*24*time.Hour), 120*time.Second); e != nil {
		t.Fatal(e)
	}
	if n := rowCount(t, p, "SELECT COUNT(*) FROM patch_policies"); n != 1 {
		t.Fatal("archived policy pruned early")
	}
	if e := p.EvaluatePatchPolicies(ctx, pnow.Add(91*24*time.Hour), 120*time.Second); e != nil {
		t.Fatal(e)
	}
	if n := rowCount(t, p, "SELECT COUNT(*) FROM patch_policies"); n != 0 {
		t.Fatal("archived policy kept after 90 days")
	}
}

// Only live checks count toward the limits; checks of a device revoked for
// 30 days are removed.
func TestHealthCheckLimitsCountLiveChecks(t *testing.T) {
	s, d, c, now := healthFixture(t, false)
	ctx := context.Background()
	c.Enabled = false
	healthSave(t, s, HealthChange{Check: c}, now)
	for i := 0; i < 10; i++ {
		v := c
		v.ID, v.Revision, v.Enabled = fmt.Sprintf("%032x", i+1), 0, true
		healthSave(t, s, HealthChange{Check: v}, now)
	}
	extra := c
	extra.ID, extra.Revision, extra.Enabled = strings.Repeat("f", 32), 0, true
	if _, e := s.ChangeHealthCheck(ctx, HealthChange{Check: extra}, "admin", "", now); e == nil {
		t.Fatal("eleventh live check on a device accepted")
	}
	if _, e := s.db.Exec("UPDATE devices SET revoked_at=? WHERE id=?", now.Unix(), d.ID); e != nil {
		t.Fatal(e)
	}
	healthSweep(t, s, now.Add(15*time.Second))
	if n := rowCount(t, s, "SELECT COUNT(*) FROM health_checks"); n != 11 {
		t.Fatal("checks of a just revoked device removed", n)
	}
	healthSweep(t, s, now.Add(31*24*time.Hour))
	if n := rowCount(t, s, "SELECT COUNT(*) FROM health_checks"); n != 0 {
		t.Fatal("checks of a long revoked device kept", n)
	}
}
