package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/patching"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"time"
)

type PatchRun struct {
	ID          string                    `json:"id"`
	PolicyID    string                    `json:"policy_id"`
	Revision    int64                     `json:"revision"`
	DeviceID    string                    `json:"device_id"`
	ScheduledAt int64                     `json:"scheduled_at"`
	WindowEnd   int64                     `json:"window_end"`
	Definition  patching.Definition       `json:"definition"`
	Status      string                    `json:"status"`
	Detail      string                    `json:"detail"`
	ScanID      string                    `json:"scan_id"`
	InstallID   string                    `json:"install_id"`
	VerifyID    string                    `json:"verify_id"`
	RestartID   string                    `json:"restart_id"`
	Selected    []protocol.UpdateIdentity `json:"selected"`
	FinishedAt  *int64                    `json:"finished_at"`
}

const patchRunColumns = "id,policy_id,revision,device_id,scheduled_at,window_end,definition_json,status,detail,scan_id,install_id,verify_id,restart_id,selected_json,finished_at"

func scanPatchRun(row interface{ Scan(...any) error }) (PatchRun, error) {
	var r PatchRun
	var definition, selected string
	e := row.Scan(&r.ID, &r.PolicyID, &r.Revision, &r.DeviceID, &r.ScheduledAt, &r.WindowEnd, &definition, &r.Status, &r.Detail, &r.ScanID, &r.InstallID, &r.VerifyID, &r.RestartID, &selected, &r.FinishedAt)
	if e == nil && (json.Unmarshal([]byte(definition), &r.Definition) != nil || !patching.Valid(r.Definition) || json.Unmarshal([]byte(selected), &r.Selected) != nil || len(r.Selected) > 25) {
		return r, patching.ErrInvalid
	}
	return r, e
}
func patchRunsTx(ctx context.Context, tx *sql.Tx, active bool) ([]PatchRun, error) {
	condition := ""
	if active {
		condition = " WHERE finished_at IS NULL"
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+patchRunColumns+" FROM patch_runs"+condition+" ORDER BY scheduled_at DESC,id LIMIT 2000")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PatchRun{}
	for rows.Next() {
		r, e := scanPatchRun(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) PatchRuns(ctx context.Context) ([]PatchRun, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	out, e := patchRunsTx(ctx, tx, false)
	if e != nil {
		return nil, e
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out, tx.Commit()
}
func finishPatchTx(ctx context.Context, tx *sql.Tx, r PatchRun, status, detail string, now time.Time) error {
	if _, e := tx.ExecContext(ctx, "UPDATE patch_runs SET status=?,detail=?,finished_at=? WHERE id=? AND finished_at IS NULL", status, detail, now.Unix(), r.ID); e != nil {
		return e
	}
	return auditDevice(ctx, tx, now, "server", "patch_run_ended", r.DeviceID+":"+r.ID, status+":"+detail)
}
func holdPatchTx(ctx context.Context, tx *sql.Tx, r PatchRun, reason string) error {
	if _, e := patchGuardTx(ctx, tx, r.DeviceID); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, "UPDATE patch_device_guards SET hold=?,owner_run=?,revision=revision+1 WHERE device_id=?", reason, r.ID, r.DeviceID)
	return e
}
func cancelPatchRunsTx(ctx context.Context, tx *sql.Tx, policy string, now time.Time, reason string) error {
	runs, e := patchRunsTx(ctx, tx, true)
	if e != nil {
		return e
	}
	for _, r := range runs {
		if policy != "" && r.PolicyID != policy {
			continue
		}
		for _, id := range []string{r.ScanID, r.InstallID, r.VerifyID, r.RestartID} {
			if id == "" {
				continue
			}
			if _, e = tx.ExecContext(ctx, "UPDATE update_jobs SET status='cancelled',finished_at=? WHERE id=? AND status='queued'", now.Unix(), id); e != nil {
				return e
			}
		}
		g, e := patchGuardTx(ctx, tx, r.DeviceID)
		if e != nil {
			return e
		}
		if g.OwnerRun == r.ID && g.Hold == "mutation_running" {
			if e = holdPatchTx(ctx, tx, r, "needs_review"); e != nil {
				return e
			}
		}
		status := "paused"
		if reason == "server_restart" {
			status = "unknown"
		}
		if e = finishPatchTx(ctx, tx, r, status, reason, now); e != nil {
			return e
		}
	}
	return nil
}

// Startup abandons active orchestration and skips elapsed starts. It never
// queues a missed installation or restarts an interrupted policy stage.
func (s *Store) InitializePatchPolicies(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = cancelPatchRunsTx(ctx, tx, "", now, "server_restart"); e != nil {
		return e
	}
	policies, e := patchPoliciesTx(ctx, tx)
	if e != nil {
		return e
	}
	for _, p := range policies {
		if p.State == "active" && p.NextAt <= now.Unix() {
			if _, e = tx.ExecContext(ctx, "UPDATE patch_policies SET next_at=? WHERE id=?", patching.Next(p.Definition, now.Add(time.Minute)).Unix(), p.ID); e != nil {
				return e
			}
			if e = auditDevice(ctx, tx, now, "server", "patch_window_skipped", p.ID, "server_restart"); e != nil {
				return e
			}
		}
	}
	return tx.Commit()
}
func patchObserveScanTx(ctx context.Context, tx *sql.Tx, id string, p protocol.UpdateProgress, now time.Time) error {
	// A partial or unknown observation cannot clear a known restart episode.
	if !p.RebootKnown || !p.RebootRequired && (p.Phase != "finished" || p.Outcome != "ok" || p.Truncated) {
		return nil
	}
	var exists int
	if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM patch_device_guards WHERE device_id=?", id).Scan(&exists); e != nil {
		return e
	}
	if exists == 0 {
		return nil
	}
	if p.RebootRequired {
		_, e := tx.ExecContext(ctx, "UPDATE patch_device_guards SET reboot_since=COALESCE(reboot_since,?),revision=revision+CASE WHEN reboot_since IS NULL THEN 1 ELSE 0 END WHERE device_id=?", now.Unix(), id)
		return e
	}
	_, e := tx.ExecContext(ctx, `UPDATE patch_device_guards SET reboot_since=NULL,hold=CASE WHEN hold='restart_requested' THEN '' ELSE hold END,owner_run=CASE WHEN hold='restart_requested' THEN '' ELSE owner_run END,revision=revision+CASE WHEN reboot_since IS NOT NULL OR hold='restart_requested' THEN 1 ELSE 0 END WHERE device_id=?`, id)
	return e
}
func patchDispatchTx(ctx context.Context, tx *sql.Tx, q UpdateJob, now time.Time) error {
	r, e := scanPatchRun(tx.QueryRowContext(ctx, "SELECT "+patchRunColumns+" FROM patch_runs WHERE scan_id=? OR install_id=? OR verify_id=? OR restart_id=?", q.ID, q.ID, q.ID, q.ID))
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	var state string
	var rev int64
	var actor string
	if e = tx.QueryRowContext(ctx, "SELECT state,revision,actor FROM patch_policies WHERE id=?", r.PolicyID).Scan(&state, &rev, &actor); e != nil {
		return e
	}
	if r.FinishedAt != nil || state != "active" || rev != r.Revision || patchOwner(ctx, tx, actor) != nil || q.Action != "scan" && now.Unix() >= r.WindowEnd || !windowsupdate.WindowAllows(q.UpdateJob, now) {
		return ErrUpdateJob
	}
	if q.Action != "scan" {
		g, e := patchGuardTx(ctx, tx, q.DeviceID)
		if e != nil {
			return e
		}
		if g.Hold != "" {
			return ErrUpdateJob
		}
		if q.Action == "restart" && (g.RebootSince == nil || now.Unix() < *g.RebootSince+int64(r.Definition.DeferHours)*3600 || now.Unix() < g.DeferUntil) {
			return ErrUpdateJob
		}
		if e = holdPatchTx(ctx, tx, r, "mutation_running"); e != nil {
			return e
		}
	}
	return nil
}
func queuePatchStageTx(ctx context.Context, tx *sql.Tx, r *PatchRun, action, stage string, now time.Time, offline time.Duration) error {
	id, e := healthID()
	if e != nil {
		return e
	}
	q := UpdateJob{UpdateJob: protocol.UpdateJob{ID: id, Action: action, ExpiresAt: now.Add(time.Minute).Unix()}, DeviceID: r.DeviceID, Actor: "patch-policy:" + r.PolicyID}
	if stage != "verifying" {
		q.WindowStart = r.ScheduledAt
		q.WindowEnd = r.WindowEnd
		q.ExpiresAt = min(q.ExpiresAt, q.WindowEnd)
	}
	if action == "install" {
		q.ScanID = r.ScanID
		q.Updates = r.Selected
	}
	if e = queueUpdateJobTx(ctx, tx, q, now, offline); e != nil {
		return e
	}
	switch stage {
	case "scanning":
		r.ScanID = id
	case "installing":
		r.InstallID = id
	case "verifying":
		r.VerifyID = id
	case "restarting":
		r.RestartID = id
	default:
		return patching.ErrInvalid
	}
	r.Status = stage
	selected, _ := json.Marshal(r.Selected)
	_, e = tx.ExecContext(ctx, "UPDATE patch_runs SET status=?,scan_id=?,install_id=?,verify_id=?,restart_id=?,selected_json=? WHERE id=?", r.Status, r.ScanID, r.InstallID, r.VerifyID, r.RestartID, string(selected), r.ID)
	return e
}
func patchNextTx(ctx context.Context, tx *sql.Tx, r PatchRun, p protocol.UpdateProgress, now time.Time, offline time.Duration) error {
	if e := patchObserveScanTx(ctx, tx, r.DeviceID, p, now); e != nil {
		return e
	}
	g, e := patchGuardTx(ctx, tx, r.DeviceID)
	if e != nil {
		return e
	}
	selected, e := patching.Selection(r.Definition, p)
	if e != nil {
		if r.Status == "verifying" {
			if e = holdPatchTx(ctx, tx, r, "needs_review"); e != nil {
				return e
			}
		}
		return finishPatchTx(ctx, tx, r, "unknown", "incomplete_or_blocked_scan", now)
	}
	if r.Status == "verifying" {
		if len(selected) > 0 {
			if e = holdPatchTx(ctx, tx, r, "needs_review"); e != nil {
				return e
			}
			return finishPatchTx(ctx, tx, r, "verification_failed", "approved_updates_still_applicable", now)
		}
		if g.OwnerRun == r.ID && g.Hold == "mutation_running" {
			if _, e = tx.ExecContext(ctx, "UPDATE patch_device_guards SET hold='',owner_run='',revision=revision+1 WHERE device_id=?", r.DeviceID); e != nil {
				return e
			}
			g.Hold = ""
		}
	}
	if p.RebootRequired {
		if !r.Definition.Restart {
			return finishPatchTx(ctx, tx, r, "pending_restart", "manual_restart_policy", now)
		}
		if g.Hold != "" {
			return finishPatchTx(ctx, tx, r, "blocked", "mutation_requires_review", now)
		}
		if g.RebootSince == nil || now.Unix() < *g.RebootSince+int64(r.Definition.DeferHours)*3600 || now.Unix() < g.DeferUntil {
			return finishPatchTx(ctx, tx, r, "reboot_deferred", "deferral_active", now)
		}
		if now.Unix()+120 >= r.WindowEnd {
			return finishPatchTx(ctx, tx, r, "window_closed", "restart_window_closed", now)
		}
		if e = queuePatchStageTx(ctx, tx, &r, "restart", "restarting", now, offline); e != nil {
			if errors.Is(e, ErrUpdateJob) {
				return finishPatchTx(ctx, tx, r, "blocked", "restart_unavailable", now)
			}
			return e
		}
		return nil
	}
	if !r.Definition.Install {
		return finishPatchTx(ctx, tx, r, "scan_only", "scan_complete", now)
	}
	if len(selected) == 0 {
		return finishPatchTx(ctx, tx, r, "approved_complete", "no_approved_updates_applicable", now)
	}
	if g.Hold != "" {
		return finishPatchTx(ctx, tx, r, "blocked", "mutation_requires_review", now)
	}
	if now.Unix() >= r.WindowEnd {
		return finishPatchTx(ctx, tx, r, "window_closed", "install_window_closed", now)
	}
	r.Selected = selected
	if e = queuePatchStageTx(ctx, tx, &r, "install", "installing", now, offline); e != nil {
		if errors.Is(e, ErrUpdateJob) {
			return finishPatchTx(ctx, tx, r, "blocked", "install_unavailable", now)
		}
		return e
	}
	return nil
}
func stepPatchRunTx(ctx context.Context, tx *sql.Tx, r PatchRun, now time.Time, offline time.Duration) error {
	id := ""
	switch r.Status {
	case "scanning":
		id = r.ScanID
	case "installing":
		id = r.InstallID
	case "verifying":
		id = r.VerifyID
	case "restarting":
		id = r.RestartID
	default:
		return patching.ErrInvalid
	}
	q, e := scanUpdate(tx.QueryRowContext(ctx, "SELECT "+updateColumns+" FROM update_jobs WHERE id=?", id))
	if errors.Is(e, sql.ErrNoRows) {
		guard, err := patchGuardTx(ctx, tx, r.DeviceID)
		if err != nil {
			return err
		}
		if guard.OwnerRun == r.ID && guard.Hold == "mutation_running" {
			if err = holdPatchTx(ctx, tx, r, "needs_review"); err != nil {
				return err
			}
		}
		return finishPatchTx(ctx, tx, r, "unknown", "update_job_unavailable", now)
	}
	if e != nil {
		return e
	}
	if q.Status == "queued" || q.Status == "dispatched" {
		return nil
	}
	if q.Status != "succeeded" || q.Progress == nil || q.Progress.Outcome != "ok" && q.Progress.Outcome != "restart_scheduled" {
		guard, err := patchGuardTx(ctx, tx, r.DeviceID)
		if err != nil {
			return err
		}
		if guard.OwnerRun == r.ID && guard.Hold == "mutation_running" {
			if e = holdPatchTx(ctx, tx, r, "needs_review"); e != nil {
				return e
			}
		}
		return finishPatchTx(ctx, tx, r, "unknown", "update_job_"+q.Status, now)
	}
	if r.Status == "restarting" {
		if q.Progress.Outcome != "restart_scheduled" {
			if e = holdPatchTx(ctx, tx, r, "needs_review"); e != nil {
				return e
			}
			return finishPatchTx(ctx, tx, r, "unknown", "unexpected_restart_outcome", now)
		}
		if e = holdPatchTx(ctx, tx, r, "restart_requested"); e != nil {
			return e
		}
		return finishPatchTx(ctx, tx, r, "restart_requested", "restart_not_yet_verified", now)
	}
	if r.Status == "installing" {
		if e = queuePatchStageTx(ctx, tx, &r, "scan", "verifying", now, offline); e != nil {
			if errors.Is(e, ErrUpdateJob) {
				if e = holdPatchTx(ctx, tx, r, "needs_review"); e != nil {
					return e
				}
				return finishPatchTx(ctx, tx, r, "unknown", "verification_unavailable", now)
			}
			return e
		}
		return nil
	}
	return patchNextTx(ctx, tx, r, *q.Progress, now, offline)
}
func (s *Store) EvaluatePatchPolicies(ctx context.Context, now time.Time, offline time.Duration) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = expireUpdates(ctx, tx, now); e != nil {
		return e
	}
	policies, e := patchPoliciesTx(ctx, tx)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM patch_runs WHERE finished_at IS NOT NULL AND (scheduled_at<? OR id IN(SELECT id FROM patch_runs WHERE finished_at IS NOT NULL ORDER BY scheduled_at,id LIMIT(SELECT MAX(COUNT(*)-1900,0) FROM patch_runs)))", now.Add(-90*24*time.Hour).Unix()); e != nil {
		return e
	}
	created := 0
	for _, p := range policies {
		if p.State != "active" || p.NextAt > now.Unix() {
			continue
		}
		if created+len(p.Definition.Devices) > 25 {
			break
		}
		created += len(p.Definition.Devices)
		slot := p.NextAt
		end := slot + int64(p.Definition.Duration)*60
		if _, e = tx.ExecContext(ctx, "UPDATE patch_policies SET next_at=? WHERE id=?", patching.Next(p.Definition, now.Add(time.Minute)).Unix(), p.ID); e != nil {
			return e
		}
		for _, device := range p.Definition.Devices {
			id, e := healthID()
			if e != nil {
				return e
			}
			raw, _ := json.Marshal(p.Definition)
			r := PatchRun{ID: id, PolicyID: p.ID, Revision: p.Revision, DeviceID: device, ScheduledAt: slot, WindowEnd: end, Definition: p.Definition, Status: "scanning"}
			var count int
			if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM patch_runs").Scan(&count); e != nil {
				return e
			}
			if count >= 2000 {
				return patching.ErrInvalid
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO patch_runs(id,policy_id,revision,device_id,scheduled_at,window_end,definition_json,status)VALUES(?,?,?,?,?,?,?,'scanning')", id, p.ID, p.Revision, device, slot, end, string(raw)); e != nil {
				return e
			}
			if slot < now.Add(-time.Minute).Unix() {
				if e = finishPatchTx(ctx, tx, r, "skipped", "missed_start", now); e != nil {
					return e
				}
				continue
			}
			if patchOwner(ctx, tx, p.Actor) != nil {
				if e = finishPatchTx(ctx, tx, r, "blocked", "owner_unavailable", now); e != nil {
					return e
				}
				continue
			}
			if _, e = patchGuardTx(ctx, tx, device); e != nil {
				return e
			}
			if e = queuePatchStageTx(ctx, tx, &r, "scan", "scanning", now, offline); e != nil {
				if errors.Is(e, ErrUpdateJob) {
					if e = finishPatchTx(ctx, tx, r, "skipped", "offline_busy_or_broker_unavailable", now); e != nil {
						return e
					}
				} else {
					return e
				}
			}
		}
	}
	runs, e := patchRunsTx(ctx, tx, true)
	if e != nil {
		return e
	}
	for _, r := range runs {
		if e = stepPatchRunTx(ctx, tx, r, now, offline); e != nil {
			return e
		}
	}
	return tx.Commit()
}
