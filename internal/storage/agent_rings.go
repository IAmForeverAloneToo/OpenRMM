package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Automatic agent rollouts in rings: the pilot groups update as soon as a new
// release is the latest; every other device follows once the pilot has settled
// and the delay has passed. Any failed update of that release pauses the
// rollout and opens an alert on the device. Rollouts go through the same
// reviewed queueing as manual ones, recorded as RingsActor.

const RingsActor = "system:rings"

var ErrAgentRings = errors.New("automatic update settings changed or are invalid")

type AgentRingPolicy struct {
	Enabled     bool     `json:"enabled"`
	PilotGroups []string `json:"pilot_groups"`
	DelayHours  int      `json:"delay_hours"`
	Paused      bool     `json:"paused"`
	PauseReason string   `json:"pause_reason"`
	ReleaseID   string   `json:"release_id"`
	PilotDoneAt *int64   `json:"pilot_done_at"`
	Revision    int64    `json:"revision"`
}

type AgentRingChange struct {
	Enabled     bool     `json:"enabled"`
	PilotGroups []string `json:"pilot_groups"`
	DelayHours  int      `json:"delay_hours"`
	// Resume clears a pause; failures before now no longer count.
	Resume   bool  `json:"resume"`
	Revision int64 `json:"revision"`
}

func (s *Store) AgentRingPolicy(ctx context.Context) (AgentRingPolicy, error) {
	return ringPolicy(ctx, s.db)
}

func ringPolicy(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (AgentRingPolicy, error) {
	var p AgentRingPolicy
	var groups string
	e := q.QueryRowContext(ctx, "SELECT enabled,pilot_groups,delay_hours,paused,pause_reason,release_id,pilot_done_at,revision FROM agent_ring_policy WHERE id=1").Scan(&p.Enabled, &groups, &p.DelayHours, &p.Paused, &p.PauseReason, &p.ReleaseID, &p.PilotDoneAt, &p.Revision)
	if e == nil && json.Unmarshal([]byte(groups), &p.PilotGroups) != nil {
		e = ErrAgentRings
	}
	if p.PilotGroups == nil {
		p.PilotGroups = []string{}
	}
	return p, e
}

func (s *Store) ChangeAgentRingPolicy(ctx context.Context, c AgentRingChange, actor string, now time.Time) (AgentRingPolicy, error) {
	if c.DelayHours < 1 || c.DelayHours > 720 || len(c.PilotGroups) > 10 {
		return AgentRingPolicy{}, ErrAgentRings
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return AgentRingPolicy{}, e
	}
	defer tx.Rollback()
	if e = applicationOwner(ctx, tx, actor); e != nil {
		return AgentRingPolicy{}, e
	}
	p, e := ringPolicy(ctx, tx)
	if e != nil {
		return p, e
	}
	if p.Revision != c.Revision {
		return p, ErrAgentRings
	}
	o, e := organizationTx(ctx, tx, false)
	if e != nil {
		return p, e
	}
	seen := map[string]bool{}
	for _, g := range c.PilotGroups {
		if seen[g] || !slices.ContainsFunc(o.Groups, func(x DeviceGroup) bool { return x.ID == g }) {
			return p, ErrAgentRings
		}
		seen[g] = true
	}
	groups, _ := json.Marshal(c.PilotGroups)
	paused, reason, since := p.Paused, p.PauseReason, int64(-1)
	if c.Resume {
		paused, reason, since = false, "", now.Unix()
	}
	if _, e = tx.ExecContext(ctx, "UPDATE agent_ring_policy SET enabled=?,pilot_groups=?,delay_hours=?,paused=?,pause_reason=?,failures_since=CASE WHEN ?>=0 THEN ? ELSE failures_since END,revision=revision+1 WHERE id=1", c.Enabled, string(groups), c.DelayHours, paused, reason, since, since); e != nil {
		return p, e
	}
	if c.Resume {
		if _, e = tx.ExecContext(ctx, "UPDATE alerts SET status='closed',finished_at=?,close_reason='rollout_resumed' WHERE kind='agent_update' AND status='active'", now.Unix()); e != nil {
			return p, e
		}
	}
	if e = auditDevice(ctx, tx, now, actor, "agent_rings_saved", "agent-rings", fmt.Sprintf("enabled=%t delay=%dh groups=%d resume=%t", c.Enabled, c.DelayHours, len(c.PilotGroups), c.Resume)); e != nil {
		return p, e
	}
	if e = tx.Commit(); e != nil {
		return p, e
	}
	return s.AgentRingPolicy(ctx)
}

// AdvanceAgentRings runs one scheduler step and returns the devices it queued.
func (s *Store) AdvanceAgentRings(ctx context.Context, now time.Time, offline time.Duration) (int, error) {
	p, e := s.AgentRingPolicy(ctx)
	if e != nil || !p.Enabled || p.Paused {
		return 0, e
	}
	latest, e := s.LatestAgentRelease(ctx, now)
	if e != nil || latest == nil {
		return 0, e
	}
	if p.ReleaseID != latest.ID {
		// A new release starts a new pilot.
		if _, e = s.db.ExecContext(ctx, "UPDATE agent_ring_policy SET release_id=?,pilot_done_at=NULL WHERE id=1", latest.ID); e != nil {
			return 0, e
		}
		p.ReleaseID, p.PilotDoneAt = latest.ID, nil
	}
	if stopped, e := s.pauseOnFailure(ctx, latest, now); e != nil || stopped {
		return 0, e
	}
	fleet, e := s.AgentFleet(ctx, now, offline)
	if e != nil {
		return 0, e
	}
	var pilot, rest []string
	pilotSettled, pilotSucceeded := true, false
	for _, d := range fleet.Devices {
		inPilot := slices.Contains(p.PilotGroups, d.GroupID)
		if inPilot && (d.Status == FleetAvailable || d.Status == FleetUpdating) {
			pilotSettled = false
		}
		if inPilot && d.Status == FleetUpToDate {
			pilotSucceeded = true
		}
		if d.Status != FleetAvailable {
			continue
		}
		if inPilot {
			pilot = append(pilot, d.ID)
		} else {
			rest = append(rest, d.ID)
		}
	}
	// With no pilot groups the delay starts when the release is seen; with
	// pilots it starts once none is still pending and at least one succeeded.
	if p.PilotDoneAt == nil && pilotSettled && (len(p.PilotGroups) == 0 || pilotSucceeded) {
		if _, e = s.db.ExecContext(ctx, "UPDATE agent_ring_policy SET pilot_done_at=? WHERE id=1 AND pilot_done_at IS NULL", now.Unix()); e != nil {
			return 0, e
		}
		at := now.Unix()
		p.PilotDoneAt = &at
	}
	targets := pilot
	if p.PilotDoneAt != nil && now.Unix() >= *p.PilotDoneAt+int64(p.DelayHours)*3600 {
		targets = append(targets, rest...)
	}
	queued := 0
	for i := 0; i < len(targets); i += 25 {
		batch := targets[i:min(i+25, len(targets))]
		sum := sha256.Sum256([]byte(fmt.Sprintf("rings:%s:%d:%v", latest.ID, now.Unix(), batch)))
		change := AgentRolloutChange{ID: hex.EncodeToString(sum[:16]), ReleaseID: latest.ID, Devices: batch, Groups: []string{}}
		review, e := s.QueueAgentRollout(ctx, change, RingsActor, "", now, offline)
		if e == nil {
			_, e = s.QueueAgentRollout(ctx, change, RingsActor, review.Digest, now, offline)
		}
		if e != nil {
			return queued, e // retried on the next step
		}
		queued += len(batch)
	}
	return queued, nil
}

// pauseOnFailure stops the rollout when any update to the latest release failed
// after the last resume, and opens one alert per failed update.
func (s *Store) pauseOnFailure(ctx context.Context, latest *AgentRelease, now time.Time) (bool, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	var since int64
	if e = tx.QueryRowContext(ctx, "SELECT failures_since FROM agent_ring_policy WHERE id=1").Scan(&since); e != nil {
		return false, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT j.id,j.device_id,d.hostname,j.status FROM agent_upgrade_jobs j JOIN devices d ON d.id=j.device_id
 WHERE j.release_id=? AND j.status IN('failed','rolled_back','denied','unknown','recovery_required') AND COALESCE(j.finished_at,j.created_at)>=? ORDER BY j.created_at,j.id LIMIT 100`, latest.ID, since)
	if e != nil {
		return false, e
	}
	type failure struct{ job, device, host, status string }
	var failures []failure
	for rows.Next() {
		var f failure
		if e = rows.Scan(&f.job, &f.device, &f.host, &f.status); e != nil {
			rows.Close()
			return false, e
		}
		failures = append(failures, f)
	}
	rows.Close()
	if e = rows.Err(); e != nil || len(failures) == 0 {
		return false, e
	}
	version := latest.Release.Manifest.Version
	reason := fmt.Sprintf("Update to %s ended %q on %s.", version, failures[0].status, failures[0].host)
	if _, e = tx.ExecContext(ctx, "UPDATE agent_ring_policy SET paused=1,pause_reason=?,revision=revision+1 WHERE id=1", reason); e != nil {
		return false, e
	}
	for _, f := range failures {
		sum := sha256.Sum256([]byte("agent-update-alert:" + f.job))
		id := hex.EncodeToString(sum[:16])
		r, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO alerts(id,device_id,hostname,kind,severity,threshold,hold_seconds,status,opened_at,last_seen,label) VALUES(?,?,?,'agent_update','warning',0,0,'active',?,?,?)`, id, f.device, f.host, now.Unix(), now.Unix(), "Agent update to "+version+": "+f.status)
		if e != nil {
			return false, e
		}
		if n, _ := r.RowsAffected(); n == 1 {
			if e = enqueueAlertMail(ctx, tx, id, "opened", now); e != nil {
				return false, e
			}
		}
	}
	if e = auditDevice(ctx, tx, now, RingsActor, "agent_rings_paused", "agent-rings", reason); e != nil {
		return false, e
	}
	return true, tx.Commit()
}
