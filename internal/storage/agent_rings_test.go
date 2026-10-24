package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func ringReport(t *testing.T, s *Store, d Device, highWater int64, hash, keyID string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if e := s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: d.Hostname, OS: "windows", Architecture: "amd64", AgentVersion: "test.1"}, now); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(protocol.AgentUpgradeSupport{Broker: "enabled", CurrentHash: hash, HighWater: highWater, KeyIDs: []string{keyID}})
	if e := s.RecordAgentUpgradeSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: agentupdate.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
}

func ringJobs(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, e := s.db.Query("SELECT device_id,actor FROM agent_upgrade_jobs")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var d, a string
		_ = rows.Scan(&d, &a)
		out[d] = a
	}
	return out
}

func TestAgentRingsPilotDelayFailurePauseAndResume(t *testing.T) {
	s, pilot, r, now := upgradeFixture(t)
	ctx := context.Background()
	offline := 120 * time.Second
	other := Device{ID: strings.Repeat("e", 32), Hostname: "fleet-device", OS: "windows", Architecture: "amd64", Certificate: "public", Fingerprint: "fp-e"}
	if e := s.NewEnrollmentToken(ctx, "ring-token", now, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := s.EnrollDevice(ctx, "ring-token", other, now); e != nil {
		t.Fatal(e)
	}
	key := r.Release.Manifest.KeyID
	ringReport(t, s, pilot, 0, strings.Repeat("c", 64), key, now)
	ringReport(t, s, other, 0, strings.Repeat("c", 64), key, now)

	// Off by default: nothing is queued.
	if n, e := s.AdvanceAgentRings(ctx, now, offline); e != nil || n != 0 {
		t.Fatal("disabled rings queued updates", n, e)
	}
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "pilot", Name: "Pilot"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: pilot.ID, GroupID: "pilot", Tags: []string{}}, now)
	if _, e := s.ChangeAgentRingPolicy(ctx, AgentRingChange{Enabled: true, PilotGroups: []string{"missing"}, DelayHours: 24, Revision: 1}, "admin", now); e == nil {
		t.Fatal("unknown pilot group accepted")
	}
	if _, e := s.ChangeAgentRingPolicy(ctx, AgentRingChange{Enabled: true, PilotGroups: []string{"pilot"}, DelayHours: 24, Revision: 1}, "technician:x", now); e == nil {
		t.Fatal("non-owner changed automatic updates")
	}
	p, e := s.ChangeAgentRingPolicy(ctx, AgentRingChange{Enabled: true, PilotGroups: []string{"pilot"}, DelayHours: 24, Revision: 1}, "admin", now)
	if e != nil || !p.Enabled {
		t.Fatal(e)
	}

	// The pilot updates at once; the rest of the fleet waits.
	if n, e := s.AdvanceAgentRings(ctx, now, offline); e != nil || n != 1 {
		t.Fatal("pilot not queued", n, e)
	}
	if jobs := ringJobs(t, s); jobs[pilot.ID] != RingsActor || jobs[other.ID] != "" {
		t.Fatal("wrong first ring", jobs)
	}

	// A failed pilot update pauses the rollout and opens an alert.
	later := now.Add(10 * time.Second)
	if _, e = s.db.Exec("UPDATE agent_upgrade_jobs SET status='rolled_back',finished_at=? WHERE device_id=?", later.Unix(), pilot.ID); e != nil {
		t.Fatal(e)
	}
	if n, e := s.AdvanceAgentRings(ctx, later, offline); e != nil || n != 0 {
		t.Fatal("rollout continued after a failure", n, e)
	}
	if p, _ = s.AgentRingPolicy(ctx); !p.Paused || !strings.Contains(p.PauseReason, "rolled_back") {
		t.Fatal("not paused", p)
	}
	var alerts int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM alerts WHERE kind='agent_update' AND status='active' AND device_id=?", pilot.ID).Scan(&alerts)
	if alerts != 1 {
		t.Fatal("no alert for the failed update", alerts)
	}
	if n, _ := s.AdvanceAgentRings(ctx, later.Add(time.Hour), offline); n != 0 {
		t.Fatal("paused rollout queued updates")
	}

	// Resuming forgets earlier failures and closes their alerts.
	resumed := later.Add(30 * time.Second)
	ringReport(t, s, pilot, 0, strings.Repeat("c", 64), key, resumed)
	ringReport(t, s, other, 0, strings.Repeat("c", 64), key, resumed)
	if p, e = s.ChangeAgentRingPolicy(ctx, AgentRingChange{Enabled: true, PilotGroups: []string{"pilot"}, DelayHours: 24, Resume: true, Revision: p.Revision}, "admin", resumed); e != nil || p.Paused {
		t.Fatal("resume", e, p)
	}
	_ = s.db.QueryRow("SELECT COUNT(*) FROM alerts WHERE kind='agent_update' AND status='active'").Scan(&alerts)
	if alerts != 0 {
		t.Fatal("alert left open after resume")
	}
	if n, e := s.AdvanceAgentRings(ctx, resumed, offline); e != nil || n != 1 {
		t.Fatal("pilot not retried after resume", n, e)
	}

	// The pilot succeeds: the delay starts; the fleet follows only after it.
	done := resumed.Add(time.Minute)
	if _, e = s.db.Exec("UPDATE agent_upgrade_jobs SET status='succeeded',finished_at=? WHERE device_id=? AND status='queued'", done.Unix(), pilot.ID); e != nil {
		t.Fatal(e)
	}
	ringReport(t, s, pilot, r.Release.Manifest.Sequence, r.Release.Manifest.Hash, key, done)
	ringReport(t, s, other, 0, strings.Repeat("c", 64), key, done)
	if n, e := s.AdvanceAgentRings(ctx, done, offline); e != nil || n != 0 {
		t.Fatal("fleet updated before the delay", n, e)
	}
	if p, _ = s.AgentRingPolicy(ctx); p.PilotDoneAt == nil {
		t.Fatal("pilot completion not recorded")
	}
	// The fixture release is only valid for an hour, so the 24-hour delay is
	// simulated by moving the recorded pilot completion back.
	if _, e = s.db.Exec("UPDATE agent_ring_policy SET pilot_done_at=?", done.Add(-24*time.Hour-time.Second).Unix()); e != nil {
		t.Fatal(e)
	}
	if n, e := s.AdvanceAgentRings(ctx, done, offline); e != nil || n != 1 {
		t.Fatal("fleet not updated after the delay", n, e)
	}
	if jobs := ringJobs(t, s); jobs[other.ID] != RingsActor {
		t.Fatal("fleet device not queued by rings", jobs)
	}
}
