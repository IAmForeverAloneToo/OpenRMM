package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
)

func rollbackHealthSchema(t *testing.T, s *Store) {
	t.Helper()
	rollbackApplicationSchema(t, s)
	for _, q := range []string{"DROP TRIGGER health_action_result", "ALTER TABLE alerts DROP COLUMN label", "DROP TABLE health_samples", "DROP TABLE health_states", "DROP TABLE health_attempts", "DROP TABLE health_guards", "DROP TABLE health_checks", "DELETE FROM schema_migrations WHERE version=20"} {
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
}

func healthFixture(t *testing.T, response bool) (*Store, Device, HealthCheck, time.Time) {
	t.Helper()
	s, d, now := actionFixture(t)
	ctx := context.Background()
	if e := s.SetAdministrator(ctx, Administrator{Username: "admin", PasswordHash: "hash", TOTPCipher: []byte("cipher")}, nil, false, now); e != nil {
		t.Fatal(e)
	}
	if e := s.ConfirmAdministrator(ctx, 1, 1, now); e != nil {
		t.Fatal(e)
	}
	c := HealthCheck{ID: strings.Repeat("a", 32), DeviceID: d.ID, Name: "Example must run", Kind: "service_running", Service: "Example", Enabled: true, HoldSeconds: 60, RecoverySeconds: 60, Severity: "critical", Email: true, Response: response, CooldownSeconds: 3600}
	healthSave(t, s, HealthChange{Check: c}, now)
	c.Revision = 1
	if e := s.InitializeAlerts(ctx, 120*time.Second, "mail", now); e != nil {
		t.Fatal(e)
	}
	return s, d, c, now
}

func healthSave(t *testing.T, s *Store, c HealthChange, now time.Time) {
	t.Helper()
	ctx := context.Background()
	digest, e := s.ChangeHealthCheck(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ChangeHealthCheck(ctx, c, "admin", digest, now); e != nil {
		t.Fatal(e)
	}
}

func healthReport(t *testing.T, s *Store, d Device, at time.Time, state string, start bool) {
	t.Helper()
	ctx := context.Background()
	if e := s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: d.Hostname, OS: d.OS, Architecture: d.Architecture, AgentVersion: "test"}, at); e != nil {
		t.Fatal(e)
	}
	v := protocol.Services{Visibility: "queryable_services_only", Items: []protocol.WindowsService{}}
	if state != "missing" {
		v.Items = append(v.Items, protocol.WindowsService{Name: "Example", DisplayName: "Example", State: state, CanStart: start, CanStop: true})
	}
	raw, _ := json.Marshal(v)
	if e := s.RecordServices(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: winservices.Capability, Status: "ok", Data: raw}, at); e != nil {
		t.Fatal(e)
	}
}

func healthSweep(t *testing.T, s *Store, at time.Time) {
	t.Helper()
	if e := s.EvaluateAlerts(context.Background(), at); e != nil {
		t.Fatal(e)
	}
}

func healthRun(t *testing.T, s *Store, d Device, from time.Time, seconds int, state string, start bool) {
	t.Helper()
	for sec := 0; sec <= seconds; sec += 15 {
		at := from.Add(time.Duration(sec) * time.Second)
		if sec%60 == 0 {
			healthReport(t, s, d, at, state, start)
		}
		healthSweep(t, s, at)
	}
}

func healthStatus(t *testing.T, s *Store, at time.Time) HealthStatus {
	t.Helper()
	rows, e := s.HealthChecksForSession(context.Background(), Session{}, "", at)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	return rows[0]
}

func TestHealthResponseOnceRecoveryMailAndCooldown(t *testing.T) {
	s, d, c, now := healthFixture(t, true)
	ctx := context.Background()
	healthRun(t, s, d, now, 60, "stopped", true)
	at := now.Add(time.Minute)
	r := healthStatus(t, s, at)
	if r.State.Incident == "" || r.AttemptID == "" || !r.Blocked {
		t.Fatalf("not qualified/guarded: %+v", r)
	}
	id, notice, e := s.ClaimAlertMail(ctx, "mail", at)
	if e != nil || id == 0 || notice.Title != c.Name || !strings.Contains(notice.Condition, "Required-service") {
		t.Fatal("check mail", notice, e)
	}
	if e = s.FinishAlertMail(ctx, id, alerting.MailResult{Status: "sent", Reason: "accepted"}, at); e != nil {
		t.Fatal(e)
	}
	if v, e := s.DispatchServiceAction(ctx, d.ID, "wrong", at); !errors.Is(e, ErrAuthentication) || v.Action != nil {
		t.Fatal("device authorization")
	}
	v, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, at)
	if e != nil || v.Action == nil || v.Action.Action != "start" {
		t.Fatal(v, e)
	}
	if v, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, at); e != nil || v.Action != nil {
		t.Fatal("redelivery", e)
	}
	if e = s.CompleteServiceAction(ctx, d.ID, d.Fingerprint, protocol.ServiceResult{ID: r.AttemptID, Outcome: "succeeded", State: "running"}, at); e != nil {
		t.Fatal(e)
	}
	if healthStatus(t, s, at).State.Incident == "" {
		t.Fatal("action result inferred recovery")
	}
	healthRun(t, s, d, at.Add(15*time.Second), 60, "running", true)
	r = healthStatus(t, s, at.Add(75*time.Second))
	if r.State.Incident != "" || r.Blocked {
		t.Fatal("no confirmed recovery", r)
	}
	id, notice, e = s.ClaimAlertMail(ctx, "mail", at.Add(75*time.Second))
	if e != nil || id == 0 || notice.Event != "resolved" {
		t.Fatal("recovery notice", notice, e)
	}
	healthRun(t, s, d, at.Add(90*time.Second), 60, "stopped", true)
	r = healthStatus(t, s, at.Add(150*time.Second))
	if r.State.Incident == "" || r.AttemptID != "" {
		t.Fatal("cooldown bypassed", r)
	}
	// A second check for the same service shares the device/service cooldown.
	c.ID = strings.Repeat("b", 32)
	c.Revision = 0
	c.Service = "eXample"
	healthSave(t, s, HealthChange{Check: c}, at.Add(150*time.Second))
	healthRun(t, s, d, at.Add(165*time.Second), 60, "stopped", true)
	history, e := s.HealthAttemptsForSession(ctx, Session{}, "")
	if e != nil || len(history) != 1 {
		t.Fatal("cross-check cooldown bypass", history, e)
	}
	// Fresh qualification after the shared cooldown can produce a later attempt.
	later := now.Add(2 * time.Hour)
	if e = s.InitializeAlerts(ctx, 120*time.Second, "mail", later); e != nil {
		t.Fatal(e)
	}
	healthRun(t, s, d, later, 60, "stopped", true)
	history, e = s.HealthAttemptsForSession(ctx, Session{}, "")
	if e != nil || len(history) != 2 {
		t.Fatal("cooldown never released", history, e)
	}
}

func TestHealthUnknownAndInterveningReadings(t *testing.T) {
	s, d, _, now := healthFixture(t, false)
	healthReport(t, s, d, now, "stopped", true)
	healthSweep(t, s, now)
	healthReport(t, s, d, now.Add(10*time.Second), "running", true)
	healthReport(t, s, d, now.Add(20*time.Second), "stopped", true)
	healthSweep(t, s, now.Add(30*time.Second))
	healthSweep(t, s, now.Add(45*time.Second))
	healthReport(t, s, d, now.Add(60*time.Second), "stopped", true)
	healthSweep(t, s, now.Add(time.Minute))
	if healthStatus(t, s, now.Add(time.Minute)).State.Incident != "" {
		t.Fatal("intervening healthy observation lost")
	}
	healthReport(t, s, d, now.Add(80*time.Second), "stopped", true)
	healthSweep(t, s, now.Add(80*time.Second))
	r := healthStatus(t, s, now.Add(80*time.Second))
	if r.State.Incident == "" || r.AttemptID != "" {
		t.Fatal("observe-only qualification", r)
	}
	healthReport(t, s, d, now.Add(90*time.Second), "missing", true)
	healthSweep(t, s, now.Add(90*time.Second))
	r = healthStatus(t, s, now.Add(90*time.Second))
	if r.State.Condition != "unknown" || r.State.Incident == "" {
		t.Fatal("absence inferred recovery", r)
	}
	healthSweep(t, s, now.Add(105*time.Second))
	healthSweep(t, s, now.Add(120*time.Second))
	if healthStatus(t, s, now.Add(120*time.Second)).State.Incident == "" {
		t.Fatal("cached observations resolved")
	}
	for _, state := range []string{"missing", "start_pending", "stop_pending"} {
		healthReport(t, s, d, now.Add(130*time.Second), state, true)
		healthSweep(t, s, now.Add(130*time.Second))
		if healthStatus(t, s, now.Add(130*time.Second)).State.Condition != "unknown" {
			t.Fatal("transient/absence not unknown")
		}
	}
}

func TestHealthQueuedCancellationAndDispatchGuards(t *testing.T) {
	for _, mode := range []string{"healthy", "unknown", "disabled", "stale_engine", "offline", "local_permission", "revoked", "restart", "paused"} {
		t.Run(mode, func(t *testing.T) {
			s, d, c, now := healthFixture(t, true)
			ctx := context.Background()
			healthRun(t, s, d, now, 60, "stopped", true)
			at := now.Add(61 * time.Second)
			switch mode {
			case "healthy":
				healthReport(t, s, d, at, "running", true)
			case "unknown":
				healthReport(t, s, d, at, "missing", true)
			case "paused":
				healthReport(t, s, d, at, "paused", true)
			case "disabled":
				c.Enabled = false
				healthSave(t, s, HealthChange{Check: c}, at)
			case "stale_engine":
				at = at.Add(45 * time.Second)
			case "offline":
				if _, e := s.db.Exec("UPDATE devices SET last_contact_at=?", at.Add(-120*time.Second).Unix()); e != nil {
					t.Fatal(e)
				}
			case "local_permission":
				healthReport(t, s, d, at, "stopped", false)
			case "revoked":
				if _, e := s.db.Exec("UPDATE devices SET revoked_at=?", at.Unix()); e != nil {
					t.Fatal(e)
				}
			case "restart":
				if e := s.InitializeAlerts(ctx, 120*time.Second, "mail", at); e != nil {
					t.Fatal(e)
				}
			}
			v, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, at)
			if mode == "revoked" {
				if !errors.Is(e, ErrAuthentication) {
					t.Fatal(e)
				}
				healthSweep(t, s, at)
			} else if e != nil || v.Action != nil {
				t.Fatal("unsafe dispatch", v, e)
			}
			history, e := s.HealthAttemptsForSession(ctx, Session{}, "")
			if e != nil || len(history) != 1 || history[0].Status != "cancelled" && history[0].Status != "expired" {
				t.Fatal("cancellation not preserved", history, e)
			}
		})
	}
}

func TestHealthUncertainResponseSurvivesRestartAndNeedsReviewedRearm(t *testing.T) {
	s, d, c, now := healthFixture(t, true)
	ctx := context.Background()
	healthRun(t, s, d, now, 60, "stopped", true)
	at := now.Add(time.Minute)
	v, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, at)
	if e != nil || v.Action == nil {
		t.Fatal(v, e)
	}
	var seq int
	var dbName, path string
	if e = s.db.QueryRow("PRAGMA database_list").Scan(&seq, &dbName, &path); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if e = s.InitializeAlerts(ctx, 120*time.Second, "mail", at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	healthRun(t, s, d, at.Add(15*time.Second), 180, "stopped", true)
	r := healthStatus(t, s, at.Add(195*time.Second))
	if !r.Blocked || r.AttemptID == "" {
		t.Fatal("uncertainty guard lost", r)
	}
	history, e := s.HealthAttemptsForSession(ctx, Session{}, "")
	if e != nil || len(history) != 1 || history[0].Status != "unknown" {
		t.Fatal(history, e)
	}
	// Ordinary edits preserve the uncertainty latch and cooldown.
	healthSave(t, s, HealthChange{Check: c}, at.Add(200*time.Second))
	c.Revision++
	if !healthStatus(t, s, at.Add(200*time.Second)).Blocked {
		t.Fatal("edit cleared guard")
	}
	digest, e := s.ChangeHealthCheck(ctx, HealthChange{Check: c, Rearm: true}, "admin", "", at.Add(201*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ChangeHealthCheck(ctx, HealthChange{Check: c}, "admin", digest, at.Add(201*time.Second)); !errors.Is(e, ErrHealthCheck) {
		t.Fatal("review tampering accepted")
	}
	if _, e = s.ChangeHealthCheck(ctx, HealthChange{Check: c, Rearm: true}, "admin", digest, at.Add(201*time.Second)); e != nil {
		t.Fatal(e)
	}
	r = healthStatus(t, s, at.Add(201*time.Second))
	if r.Blocked || r.LastAttempt != at.Unix() {
		t.Fatal("rearm erased cooldown", r)
	}
	healthRun(t, s, d, at.Add(210*time.Second), 60, "stopped", true)
	history, _ = s.HealthAttemptsForSession(ctx, Session{}, "")
	if len(history) != 1 {
		t.Fatal("rearm bypassed cooldown")
	}
}

func TestHealthValidationScopeAndMigration(t *testing.T) {
	s, d, c, now := healthFixture(t, false)
	ctx := context.Background()
	for _, mutate := range []func(*HealthCheck){func(c *HealthCheck) { c.Kind = "shell" }, func(c *HealthCheck) { c.Service, c.Response = "OpenRMMAgent", true }, func(c *HealthCheck) { c.CooldownSeconds = 1 }, func(c *HealthCheck) { c.HoldSeconds = 0 }, func(c *HealthCheck) { c.Revision = 99 }, func(c *HealthCheck) { c.Name = "bad\nname" }} {
		bad := c
		mutate(&bad)
		if _, e := s.ChangeHealthCheck(ctx, HealthChange{Check: bad}, "admin", "", now); !errors.Is(e, ErrHealthCheck) {
			t.Fatal("invalid check accepted", bad, e)
		}
	}
	v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}})
	if _, e := s.ChangeHealthCheck(ctx, HealthChange{Check: c}, v.Actor(), "", now); !errors.Is(e, ErrForbidden) {
		t.Fatal("technician configured response", e)
	}
	rows, e := s.HealthChecksForSession(ctx, v, "", now)
	if e != nil || len(rows) != 1 {
		t.Fatal("scoped read", e)
	}
	if _, e = s.db.Exec("UPDATE technicians SET enabled=0"); e != nil {
		t.Fatal(e)
	}
	rows, e = s.HealthChecksForSession(ctx, v, "", now)
	if e != nil || len(rows) != 0 {
		t.Fatal("disabled scope read", e)
	}
	if healthServiceKey("exΣKample") != healthServiceKey("EXςkAMPLE") {
		t.Fatal("Unicode guard alias")
	}
	path := filepath.Join(t.TempDir(), "migration", "db")
	old, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := old.Info(ctx)
	rollbackHealthSchema(t, old)
	if e = old.Close(); e != nil {
		t.Fatal(e)
	}
	old, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	after, _ := old.Info(ctx)
	if before != after {
		t.Fatal("schema 19 upgrade changed identity")
	}
}

func TestHealthCheckCapacity(t *testing.T) {
	s, _, c, now := healthFixture(t, false)
	for i := 1; i <= 10; i++ {
		c.ID = fmt.Sprintf("%032x", i)
		c.Revision = 0
		digest, e := s.ChangeHealthCheck(context.Background(), HealthChange{Check: c}, "admin", "", now)
		if i == 10 {
			if !errors.Is(e, ErrHealthCheck) {
				t.Fatal("per-device capacity bypass", e)
			}
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.ChangeHealthCheck(context.Background(), HealthChange{Check: c}, "admin", digest, now); e != nil {
			t.Fatal(e)
		}
	}
}

func TestHealthAtomicAuditFailureAndFailedResponseLatch(t *testing.T) {
	s, d, _, now := healthFixture(t, true)
	ctx := context.Background()
	healthRun(t, s, d, now, 45, "stopped", true)
	if _, e := s.db.Exec(`CREATE TRIGGER health_test_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'audit unavailable'); END`); e != nil {
		t.Fatal(e)
	}
	healthReport(t, s, d, now.Add(time.Minute), "stopped", true)
	if e := s.EvaluateAlerts(ctx, now.Add(time.Minute)); e == nil {
		t.Fatal("audit failure ignored")
	}
	for _, table := range []string{"health_attempts", "health_guards", "service_actions", "alerts"} {
		var n int
		if e := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); e != nil || n != 0 {
			t.Fatal("partial queue after rollback", table, n, e)
		}
	}
	if _, e := s.db.Exec("DROP TRIGGER health_test_audit"); e != nil {
		t.Fatal(e)
	}
	healthSweep(t, s, now.Add(time.Minute))
	v, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, now.Add(time.Minute))
	if e != nil || v.Action == nil {
		t.Fatal(v, e)
	}
	if e = s.CompleteServiceAction(ctx, d.ID, d.Fingerprint, protocol.ServiceResult{ID: v.Action.ID, Outcome: "timed_out", State: "unknown"}, now.Add(61*time.Second)); e != nil {
		t.Fatal(e)
	}
	r := healthStatus(t, s, now.Add(61*time.Second))
	if !r.Blocked {
		t.Fatal("failed execution unlatched")
	}
	// Fresh service recovery does not erase uncertainty about future automation.
	healthRun(t, s, d, now.Add(75*time.Second), 60, "running", true)
	if !healthStatus(t, s, now.Add(135*time.Second)).Blocked {
		t.Fatal("recovery erased failed-response block")
	}
}

func TestHealthChecksMayMonitorButNotStartOpenRMMServices(t *testing.T) {
	c := HealthCheck{ID: strings.Repeat("a", 32), DeviceID: strings.Repeat("b", 32), Name: "Agent", Kind: "service_running", Service: "OpenRMMAgent", HoldSeconds: 120, RecoverySeconds: 60, Severity: "warning", CooldownSeconds: 3600}
	if !healthValid(c) {
		t.Fatal("monitoring an OpenRMM service refused")
	}
	c.Response = true
	if healthValid(c) {
		t.Fatal("automatic start of an OpenRMM service accepted")
	}
	c.Service = "Spooler"
	if !healthValid(c) {
		t.Fatal("ordinary service response refused")
	}
}
