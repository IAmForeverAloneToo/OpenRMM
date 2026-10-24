package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"sort"
	"time"
)

type AgentUpgradeSupport struct {
	Status     string                       `json:"status"`
	ReportedAt int64                        `json:"reported_at"`
	Support    protocol.AgentUpgradeSupport `json:"support"`
}

func (s *Store) RecordAgentUpgradeSupport(ctx context.Context, id, fp string, r protocol.FeatureReport, now time.Time) error {
	r, e := agentupdate.Normalize(r)
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO device_agent_upgrade_support VALUES(?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET last_status=excluded.last_status,reported_at=excluded.reported_at,support_json=excluded.support_json WHERE excluded.reported_at>=device_agent_upgrade_support.reported_at`, id, r.Status, now.Unix(), string(r.Data))
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) AgentUpgradeSupport(ctx context.Context, id string) (AgentUpgradeSupport, error) {
	v := AgentUpgradeSupport{Status: "not_reported"}
	var raw string
	e := s.db.QueryRowContext(ctx, "SELECT last_status,reported_at,support_json FROM device_agent_upgrade_support WHERE device_id=?", id).Scan(&v.Status, &v.ReportedAt, &raw)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	if e == nil && v.Status == "ok" && (agentupdate.Decode([]byte(raw), &v.Support) != nil || !agentupdate.SupportValid(v.Support)) {
		e = ErrAgentUpgrade
	}
	return v, e
}

type AgentRolloutChange struct {
	ID        string   `json:"id"`
	ReleaseID string   `json:"release_id"`
	Devices   []string `json:"devices"`
	Groups    []string `json:"groups"`
}
type AgentRolloutTarget struct {
	ID, Hostname, CurrentHash string
	HighWater                 int64
}
type AgentRolloutReview struct {
	Change  AgentRolloutChange
	Release AgentRelease
	Targets []AgentRolloutTarget
	Digest  string
}
type AgentUpgradeJob struct {
	ID           string                       `json:"id"`
	BatchID      string                       `json:"batch_id"`
	DeviceID     string                       `json:"device_id"`
	Hostname     string                       `json:"hostname"`
	ReleaseID    string                       `json:"release_id"`
	ExpectedHash string                       `json:"expected_sha256"`
	Actor        string                       `json:"actor"`
	Status       string                       `json:"status"`
	CreatedAt    int64                        `json:"created_at"`
	ExpiresAt    int64                        `json:"expires_at"`
	DispatchedAt *int64                       `json:"dispatched_at"`
	FinishedAt   *int64                       `json:"finished_at"`
	Result       *protocol.AgentUpgradeResult `json:"result,omitempty"`
}

func agentUpgradeSupportTx(ctx context.Context, tx *sql.Tx, id string, now time.Time, offline time.Duration) (protocol.AgentUpgradeSupport, error) {
	var raw string
	e := tx.QueryRowContext(ctx, `SELECT s.support_json FROM device_agent_upgrade_support s JOIN devices d ON d.id=s.device_id WHERE d.id=? AND d.revoked_at IS NULL AND d.os='windows' AND d.architecture='amd64' AND d.last_contact_at>? AND d.last_contact_at<=? AND s.last_status='ok' AND s.reported_at>? AND s.reported_at<=?`, id, now.Add(-offline).Unix(), now.Unix(), now.Add(-2*time.Minute).Unix(), now.Unix()).Scan(&raw)
	var cap protocol.AgentUpgradeSupport
	if e != nil || agentupdate.Decode([]byte(raw), &cap) != nil || !agentupdate.SupportValid(cap) || cap.Broker != "enabled" {
		return cap, ErrAgentUpgrade
	}
	return cap, nil
}
func upgradeAllowed(s protocol.AgentUpgradeSupport, r AgentRelease) bool {
	trusted := false
	for _, k := range s.KeyIDs {
		if k == r.Release.Manifest.KeyID {
			trusted = true
		}
	}
	// MSI packages need an agent that installs them itself; a
	// format-1 executable needs the earlier separate updater.
	if agentupdate.MSI(r.Release.Manifest) != (s.Installer == "msi") {
		return false
	}
	return trusted && s.HighWater < r.Release.Manifest.Sequence && s.CurrentHash != agentupdate.AgentHash(r.Release.Manifest)
}
func expireAgentUpgrades(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, e := tx.QueryContext(ctx, `SELECT id,device_id,status FROM agent_upgrade_jobs WHERE status IN('queued','dispatched') AND(expires_at<=? OR device_id IN(SELECT id FROM devices WHERE revoked_at IS NOT NULL))`, now.Unix())
	if e != nil {
		return e
	}
	type item struct{ id, device, status string }
	var items []item
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.id, &v.device, &v.status); e != nil {
			rows.Close()
			return e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range items {
		status := "expired"
		if v.status == "dispatched" {
			status = "unknown"
		}
		if _, e = tx.ExecContext(ctx, "UPDATE agent_upgrade_jobs SET status=?,finished_at=? WHERE id=?", status, now.Unix(), v.id); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, "server", "agent_upgrade_"+status, v.device+":"+v.id, status); e != nil {
			return e
		}
	}
	_, e = tx.ExecContext(ctx, `DELETE FROM agent_upgrade_jobs WHERE status NOT IN('queued','dispatched') AND(created_at<? OR id IN(SELECT id FROM agent_upgrade_jobs ORDER BY created_at DESC,id LIMIT -1 OFFSET 1975))`, now.Add(-30*24*time.Hour).Unix())
	return e
}
func (s *Store) SweepAgentUpgrades(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = expireAgentUpgrades(ctx, tx, now); e != nil {
		return e
	}
	return tx.Commit()
}
func rolloutReview(ctx context.Context, tx *sql.Tx, c AgentRolloutChange, actor string, now time.Time, offline time.Duration) (AgentRolloutReview, error) {
	r := AgentRolloutReview{Change: c}
	if !protocol.ValidID(c.ID) || !agentupdate.Hash(c.ReleaseID) || len(c.Devices) > 25 || len(c.Groups) > 25 || len(c.Devices)+len(c.Groups) == 0 {
		return r, ErrAgentUpgrade
	}
	// Automatic ring rollouts run as RingsActor, which no account can sign in as
	// (usernames cannot contain ':'); everything else needs the owner.
	if actor != RingsActor {
		if e := applicationOwner(ctx, tx, actor); e != nil {
			return r, e
		}
	}
	release, e := scanAgentRelease(tx.QueryRowContext(ctx, "SELECT "+agentReleaseColumns+" FROM agent_releases WHERE id=? AND withdrawn=0", c.ReleaseID))
	if e != nil || !agentupdate.Fresh(release.Release.Manifest, now) {
		return r, ErrAgentUpgrade
	}
	r.Release = release
	o, e := organizationTx(ctx, tx, true)
	if e != nil {
		return r, e
	}
	devices, groups := map[string]bool{}, map[string]bool{}
	for _, id := range c.Devices {
		if !protocol.ValidID(id) || devices[id] {
			return r, ErrAgentUpgrade
		}
		devices[id] = true
	}
	for _, id := range c.Groups {
		if !ValidOrganizationID(id) || groups[id] {
			return r, ErrAgentUpgrade
		}
		exists := false
		for _, g := range o.Groups {
			if g.ID == id {
				exists = true
			}
		}
		if !exists {
			return r, ErrAgentUpgrade
		}
		groups[id] = true
	}
	matched := map[string]bool{}
	for _, d := range o.Devices {
		if !devices[d.ID] && !groups[d.GroupID] {
			continue
		}
		support, e := agentUpgradeSupportTx(ctx, tx, d.ID, now, offline)
		if e != nil || !upgradeAllowed(support, release) {
			return r, ErrAgentUpgrade
		}
		r.Targets = append(r.Targets, AgentRolloutTarget{d.ID, d.Hostname, support.CurrentHash, support.HighWater})
		matched[d.ID] = true
	}
	for id := range devices {
		if !matched[id] {
			return r, ErrAgentUpgrade
		}
	}
	if len(r.Targets) == 0 || len(r.Targets) > 25 {
		return r, ErrAgentUpgrade
	}
	sort.Slice(r.Targets, func(i, j int) bool { return r.Targets[i].ID < r.Targets[j].ID })
	var revision int64
	if e = tx.QueryRowContext(ctx, "SELECT revision FROM agent_release_state WHERE id=1").Scan(&revision); e != nil {
		return r, e
	}
	raw, _ := json.Marshal(struct {
		Review                 AgentRolloutReview
		Revision, Organization int64
		Actor                  string
	}{r, revision, o.Revision, actor})
	r.Digest = agentupdate.Digest(raw)
	return r, nil
}
func (s *Store) QueueAgentRollout(ctx context.Context, c AgentRolloutChange, actor, digest string, now time.Time, offline time.Duration) (AgentRolloutReview, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return AgentRolloutReview{}, e
	}
	defer tx.Rollback()
	r, e := rolloutReview(ctx, tx, c, actor, now, offline)
	if e != nil {
		return r, e
	}
	if digest == "" {
		return r, nil
	}
	if digest != r.Digest {
		return r, ErrAgentUpgrade
	}
	var existing, matching int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN request_hash=? AND actor=? THEN 1 ELSE 0 END),0) FROM agent_upgrade_jobs WHERE batch_id=?", digest, actor, c.ID).Scan(&existing, &matching); e != nil {
		return r, e
	}
	if existing > 0 {
		if existing != len(r.Targets) || matching != existing {
			return r, ErrAgentUpgrade
		}
		return r, tx.Commit()
	}
	if e = expireAgentUpgrades(ctx, tx, now); e != nil {
		return r, e
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_upgrade_jobs").Scan(&count); e != nil || count+len(r.Targets) > 2000 {
		return r, ErrAgentUpgrade
	}
	for _, d := range r.Targets {
		var busy int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_upgrade_jobs WHERE device_id=? AND status IN('queued','dispatched')", d.ID).Scan(&busy); e != nil {
			return r, e
		}
		if busy != 0 {
			return r, ErrAgentUpgrade
		}
		id := applicationID("agent-upgrade:"+d.ID, c.ID)
		if _, e = tx.ExecContext(ctx, "INSERT INTO agent_upgrade_jobs(id,batch_id,device_id,release_id,expected_hash,actor,request_hash,created_at,expires_at)VALUES(?,?,?,?,?,?,?,?,?)", id, c.ID, d.ID, c.ReleaseID, d.CurrentHash, actor, digest, now.Unix(), now.Add(time.Minute).Unix()); e != nil {
			return r, e
		}
		if e = auditDevice(ctx, tx, now, actor, "agent_upgrade_queued", d.ID+":"+id, c.ReleaseID+":"+d.CurrentHash); e != nil {
			return r, e
		}
	}
	return r, tx.Commit()
}

const agentJobColumns = "j.id,j.batch_id,j.device_id,d.hostname,j.release_id,j.expected_hash,j.actor,j.status,j.created_at,j.expires_at,j.dispatched_at,j.finished_at,j.result_json"

func scanAgentJob(row interface{ Scan(...any) error }) (AgentUpgradeJob, error) {
	var v AgentUpgradeJob
	var raw string
	e := row.Scan(&v.ID, &v.BatchID, &v.DeviceID, &v.Hostname, &v.ReleaseID, &v.ExpectedHash, &v.Actor, &v.Status, &v.CreatedAt, &v.ExpiresAt, &v.DispatchedAt, &v.FinishedAt, &raw)
	if e == nil && raw != "" {
		v.Result = new(protocol.AgentUpgradeResult)
		if agentupdate.Decode([]byte(raw), v.Result) != nil || !agentupdate.ResultValid(*v.Result) {
			e = ErrAgentUpgrade
		}
	}
	return v, e
}
func (s *Store) AgentUpgradeJobs(ctx context.Context, v Session, device string, now time.Time) ([]AgentUpgradeJob, error) {
	if e := s.SweepAgentUpgrades(ctx, now); e != nil {
		return nil, e
	}
	scope, args := technicianScope(v, "j.device_id")
	args = append([]any{device, device}, args...)
	rows, e := s.db.QueryContext(ctx, "SELECT "+agentJobColumns+" FROM agent_upgrade_jobs j JOIN devices d ON d.id=j.device_id WHERE (?='' OR j.device_id=?) AND "+scope+" ORDER BY j.created_at DESC,j.id LIMIT 200", args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []AgentUpgradeJob{}
	for rows.Next() {
		v, e := scanAgentJob(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func (s *Store) DispatchAgentUpgrade(ctx context.Context, device, fp string, now time.Time) (protocol.AgentUpgradeDispatch, error) {
	out := protocol.AgentUpgradeDispatch{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, device, fp, now); e != nil {
		return out, e
	}
	if e = expireAgentUpgrades(ctx, tx, now); e != nil {
		return out, e
	}
	v, e := scanAgentJob(tx.QueryRowContext(ctx, "SELECT "+agentJobColumns+" FROM agent_upgrade_jobs j JOIN devices d ON d.id=j.device_id WHERE j.device_id=? AND j.status='queued' LIMIT 1", device))
	if errors.Is(e, sql.ErrNoRows) {
		return out, tx.Commit()
	}
	if e != nil {
		return out, e
	}
	r, e := scanAgentRelease(tx.QueryRowContext(ctx, "SELECT "+agentReleaseColumns+" FROM agent_releases WHERE id=? AND withdrawn=0", v.ReleaseID))
	if e != nil || !agentupdate.Fresh(r.Release.Manifest, now) {
		return out, ErrAgentUpgrade
	}
	support, e := agentUpgradeSupportTx(ctx, tx, device, now, 120*time.Second)
	if e != nil || !upgradeAllowed(support, r) || support.CurrentHash != v.ExpectedHash {
		return out, ErrAgentUpgrade
	}
	if _, e = tx.ExecContext(ctx, "UPDATE agent_upgrade_jobs SET status='dispatched',dispatched_at=?,expires_at=? WHERE id=?", now.Unix(), now.Add(10*time.Minute).Unix(), v.ID); e != nil {
		return out, e
	}
	if e = auditDevice(ctx, tx, now, "device:"+device, "agent_upgrade_dispatched", device+":"+v.ID, v.ReleaseID); e != nil {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	out.Job = &protocol.AgentUpgradeJob{ID: v.ID, Release: r.Release, PublicKey: r.PublicKey, ExpectedHash: v.ExpectedHash, ExpiresAt: now.Add(3 * time.Minute).Unix()}
	return out, nil
}
func (s *Store) CompleteAgentUpgrade(ctx context.Context, device, fp string, r protocol.AgentUpgradeResult, now time.Time) error {
	if !agentupdate.ResultValid(r) || r.Outcome == "running" {
		return ErrAgentUpgrade
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, device, fp, now); e != nil {
		return e
	}
	if e = expireAgentUpgrades(ctx, tx, now); e != nil {
		return e
	}
	v, e := scanAgentJob(tx.QueryRowContext(ctx, "SELECT "+agentJobColumns+" FROM agent_upgrade_jobs j JOIN devices d ON d.id=j.device_id WHERE j.id=? AND j.device_id=?", r.ID, device))
	if e != nil {
		return ErrAgentUpgrade
	}
	release, e := scanAgentRelease(tx.QueryRowContext(ctx, "SELECT "+agentReleaseColumns+" FROM agent_releases WHERE id=?", v.ReleaseID))
	if e != nil {
		return e
	}
	if r.Outcome == "succeeded" && (r.Hash != agentupdate.AgentHash(release.Release.Manifest) || r.Sequence != release.Release.Manifest.Sequence) || r.Outcome == "rolled_back" && (r.Hash != v.ExpectedHash || r.Sequence != release.Release.Manifest.Sequence) {
		return ErrAgentUpgrade
	}
	raw, _ := json.Marshal(r)
	if v.Status != "dispatched" {
		if v.Result != nil {
			old, _ := json.Marshal(v.Result)
			if string(old) == string(raw) {
				return tx.Commit()
			}
		}
		return ErrAgentUpgrade
	}
	if _, e = tx.ExecContext(ctx, "UPDATE agent_upgrade_jobs SET status=?,result_json=?,finished_at=? WHERE id=?", r.Outcome, string(raw), now.Unix(), r.ID); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, "device:"+device, "agent_upgrade_completed", device+":"+r.ID, r.Outcome+":"+r.Hash); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) CancelAgentUpgrade(ctx context.Context, id, actor string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = applicationOwner(ctx, tx, actor); e != nil {
		return e
	}
	var status, device string
	if e = tx.QueryRowContext(ctx, "SELECT status,device_id FROM agent_upgrade_jobs WHERE id=?", id).Scan(&status, &device); e != nil {
		return ErrAgentUpgrade
	}
	if status != "queued" {
		return ErrAgentUpgrade
	}
	if _, e = tx.ExecContext(ctx, "UPDATE agent_upgrade_jobs SET status='cancelled',finished_at=? WHERE id=?", now.Unix(), id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "agent_upgrade_cancelled", device+":"+id, "not_dispatched"); e != nil {
		return e
	}
	return tx.Commit()
}
