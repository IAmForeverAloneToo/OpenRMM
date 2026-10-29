package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"time"
)

var ErrUpdateJob = errors.New("update operation unavailable; check connectivity, broker permissions, pending work and scan age")

type UpdateJob struct {
	protocol.UpdateJob
	DeviceID     string                   `json:"device_id"`
	Actor        string                   `json:"actor"`
	CreatedAt    int64                    `json:"created_at"`
	ExpiresAt    int64                    `json:"deadline"`
	DispatchedAt *int64                   `json:"dispatched_at"`
	FinishedAt   *int64                   `json:"finished_at"`
	Status       string                   `json:"status"`
	Progress     *protocol.UpdateProgress `json:"progress"`
}

const updateColumns = "id,device_id,actor,created_at,expires_at,dispatched_at,finished_at,status,request_json,progress_json"

func scanUpdate(row interface{ Scan(...any) error }) (UpdateJob, error) {
	var q UpdateJob
	var id, request, progress string
	e := row.Scan(&id, &q.DeviceID, &q.Actor, &q.CreatedAt, &q.ExpiresAt, &q.DispatchedAt, &q.FinishedAt, &q.Status, &request, &progress)
	if e != nil {
		return q, e
	}
	if json.Unmarshal([]byte(request), &q.UpdateJob) != nil || q.ID != id || !windowsupdate.JobValid(q.UpdateJob) {
		return q, ErrUpdateJob
	}
	if progress != "" {
		q.Progress = new(protocol.UpdateProgress)
		if json.Unmarshal([]byte(progress), q.Progress) != nil || !windowsupdate.ProgressValid(*q.Progress, q.UpdateJob) {
			return q, ErrUpdateJob
		}
	}
	return q, nil
}
func expireUpdates(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, e := tx.QueryContext(ctx, `SELECT id,device_id,status FROM update_jobs WHERE status IN ('queued','dispatched') AND (expires_at<=? OR device_id IN (SELECT id FROM devices WHERE revoked_at IS NOT NULL))`, now.Unix())
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
		if _, e = tx.ExecContext(ctx, "UPDATE update_jobs SET status=?,finished_at=? WHERE id=?", status, now.Unix(), v.id); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, "server", "update_"+status, v.device+":"+v.id, status); e != nil {
			return e
		}
	}
	_, e = tx.ExecContext(ctx, "DELETE FROM update_jobs WHERE status NOT IN ('queued','dispatched') AND created_at<=?", now.Add(-7*24*time.Hour).Unix())
	return e
}
func updateEligible(ctx context.Context, tx *sql.Tx, id string, now time.Time, offline time.Duration) (protocol.UpdateSupport, error) {
	var raw string
	var s protocol.UpdateSupport
	e := tx.QueryRowContext(ctx, `SELECT f.snapshot_json FROM device_update_support f JOIN devices d ON d.id=f.device_id WHERE d.id=? AND d.revoked_at IS NULL AND d.last_contact_at>? AND d.last_contact_at<=? AND f.last_status='ok' AND f.capability_version=1 AND f.snapshot_at>? AND f.snapshot_at<=?`, id, now.Add(-offline).Unix(), now.Unix(), now.Add(-2*time.Minute).Unix(), now.Unix()).Scan(&raw)
	if e != nil || json.Unmarshal([]byte(raw), &s) != nil || !windowsupdate.SupportValid(s) || s.Broker != "available" {
		return s, ErrUpdateJob
	}
	return s, nil
}
func (s *Store) QueueUpdateJob(ctx context.Context, q UpdateJob, now time.Time, offline time.Duration) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = queueUpdateJobTx(ctx, tx, q, now, offline); e != nil {
		return e
	}
	return tx.Commit()
}
func queueUpdateJobTx(ctx context.Context, tx *sql.Tx, q UpdateJob, now time.Time, offline time.Duration) error {
	if !protocol.ValidID(q.DeviceID) || !windowsupdate.JobValid(q.UpdateJob) || q.Actor == "" || len(q.Actor) > 128 {
		return ErrUpdateJob
	}
	var e error
	if e = expireUpdates(ctx, tx, now); e != nil {
		return e
	}
	old, e := scanUpdate(tx.QueryRowContext(ctx, "SELECT "+updateColumns+" FROM update_jobs WHERE id=?", q.ID))
	if e == nil {
		x := q.UpdateJob
		x.ExpiresAt = old.UpdateJob.ExpiresAt
		a, _ := json.Marshal(x)
		b, _ := json.Marshal(old.UpdateJob)
		if old.DeviceID != q.DeviceID || old.Actor != q.Actor || string(a) != string(b) {
			return ErrUpdateJob
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	support, e := updateEligible(ctx, tx, q.DeviceID, now, offline)
	if e != nil {
		return e
	}
	if q.WindowStart != 0 && !support.Windowed {
		return ErrUpdateJob
	}
	if !windowsupdate.WindowAllows(q.UpdateJob, now) {
		return ErrUpdateJob
	}
	if (q.Action == "install" && !support.CanInstall) || (q.Action == "restart" && !support.CanRestart) {
		return ErrUpdateJob
	}
	if q.Action == "install" {
		scan, e := scanUpdate(tx.QueryRowContext(ctx, "SELECT "+updateColumns+" FROM update_jobs WHERE id=? AND device_id=?", q.ScanID, q.DeviceID))
		if e != nil || scan.Action != "scan" || scan.Status != "succeeded" || scan.Progress == nil || scan.CreatedAt <= now.Add(-2*time.Hour).Unix() || scan.CreatedAt > now.Unix() {
			return ErrUpdateJob
		}
		for _, v := range q.Updates {
			found := false
			for _, u := range scan.Progress.Catalog {
				if u.UpdateIdentity == v && u.Blocked == "" {
					found = true
				}
			}
			if !found {
				return ErrUpdateJob
			}
		}
	}
	// Preserve current scan references and still-valid submission intents while
	// pruning old terminal history to keep routine use below the hard global cap.
	if _, e = tx.ExecContext(ctx, `DELETE FROM update_jobs WHERE id IN (SELECT id FROM update_jobs WHERE status NOT IN ('queued','dispatched') AND created_at<? AND id<>? AND id NOT IN (SELECT scan FROM (SELECT CASE WHEN json_valid(request_json) THEN json_extract(request_json,'$.scan_id') END AS scan FROM update_jobs WHERE status IN ('queued','dispatched')) WHERE scan IS NOT NULL) ORDER BY created_at,id LIMIT (SELECT MAX(COUNT(*)-99,0) FROM update_jobs))`, now.Add(-2*time.Minute).Unix(), q.ScanID); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM update_jobs").Scan(&n); e != nil {
		return e
	}
	if n >= 100 {
		return ErrUpdateJob
	}
	q.UpdateJob.ExpiresAt = now.Add(time.Minute).Unix()
	if q.WindowEnd != 0 {
		q.UpdateJob.ExpiresAt = min(q.UpdateJob.ExpiresAt, q.WindowEnd)
	}
	raw, _ := json.Marshal(q.UpdateJob)
	if _, e = tx.ExecContext(ctx, `INSERT INTO update_jobs(id,device_id,actor,created_at,expires_at,status,request_json) VALUES(?,?,?,?,?,'queued',?)`, q.ID, q.DeviceID, q.Actor, now.Unix(), q.UpdateJob.ExpiresAt, string(raw)); e != nil {
		return ErrUpdateJob
	}
	if e = auditDevice(ctx, tx, now, q.Actor, "update_requested", q.DeviceID+":"+q.ID+":"+q.Action, "queued"); e != nil {
		return e
	}
	return nil
}
func (s *Store) DispatchUpdateJob(ctx context.Context, id, fp string, now time.Time) (protocol.UpdateDispatch, error) {
	var d protocol.UpdateDispatch
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return d, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return d, e
	}
	if e = expireUpdates(ctx, tx, now); e != nil {
		return d, e
	}
	q, e := scanUpdate(tx.QueryRowContext(ctx, "SELECT "+updateColumns+" FROM update_jobs WHERE device_id=? AND status='queued'", id))
	if errors.Is(e, sql.ErrNoRows) {
		return d, tx.Commit()
	}
	if e != nil {
		return d, e
	}
	// Scheduled jobs recheck the exact policy revision/window at dispatch.
	if e = patchDispatchTx(ctx, tx, q, now); e != nil {
		return d, e
	}
	// Recheck availability/permission at dispatch, as well as at queue time.
	support, e := updateEligible(ctx, tx, id, now, 2*time.Minute)
	if e != nil || (q.WindowStart != 0 && !support.Windowed) || !windowsupdate.WindowAllows(q.UpdateJob, now) || (q.Action == "install" && !support.CanInstall) || (q.Action == "restart" && !support.CanRestart) {
		return d, ErrUpdateJob
	}
	duration := 20 * time.Minute
	if q.Action == "install" {
		duration = 125 * time.Minute
	}
	if q.Action == "restart" {
		duration = 3 * time.Minute
	}
	q.UpdateJob.ExpiresAt = now.Add(time.Minute).Unix()
	if q.WindowEnd != 0 {
		q.UpdateJob.ExpiresAt = min(q.UpdateJob.ExpiresAt, q.WindowEnd)
	}
	raw, _ := json.Marshal(q.UpdateJob)
	if _, e = tx.ExecContext(ctx, "UPDATE update_jobs SET status='dispatched',dispatched_at=?,expires_at=?,request_json=? WHERE id=?", now.Unix(), now.Add(duration).Unix(), string(raw), q.ID); e != nil {
		return d, e
	}
	if e = auditDevice(ctx, tx, now, "device:"+id, "update_dispatched", id+":"+q.ID+":"+q.Action, "dispatched"); e != nil {
		return d, e
	}
	if e = tx.Commit(); e != nil {
		return d, e
	}
	d.Job = &q.UpdateJob
	return d, nil
}
func (s *Store) RecordUpdateProgress(ctx context.Context, id, fp string, p protocol.UpdateProgress, now time.Time) error {
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > windowsupdate.MaxBytes || !protocol.ValidID(p.ID) {
		return ErrUpdateJob
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return e
	}
	if e = expireUpdates(ctx, tx, now); e != nil {
		return e
	}
	q, e := scanUpdate(tx.QueryRowContext(ctx, "SELECT "+updateColumns+" FROM update_jobs WHERE id=? AND device_id=?", p.ID, id))
	if e != nil || !windowsupdate.ProgressValid(p, q.UpdateJob) {
		return ErrUpdateJob
	}
	if q.Progress != nil {
		old, _ := json.Marshal(q.Progress)
		if string(old) == string(raw) && (q.Status == "dispatched" || windowsupdate.Terminal(p)) {
			return tx.Commit()
		}
	}
	if q.Status != "dispatched" || (q.Progress != nil && p.Completed < q.Progress.Completed) {
		return ErrUpdateJob
	}
	if q.Progress != nil {
		for i, v := range q.Progress.Items {
			if i >= len(p.Items) || p.Items[i] != v {
				return ErrUpdateJob
			}
		}
	}
	status := "dispatched"
	var finished any
	if windowsupdate.Terminal(p) {
		status = "failed"
		if p.Outcome == "ok" || p.Outcome == "restart_scheduled" {
			status = "succeeded"
		}
		if p.Outcome == "unknown" {
			status = "unknown"
		}
		finished = now.Unix()
	}
	if _, e = tx.ExecContext(ctx, "UPDATE update_jobs SET status=?,finished_at=?,progress_json=? WHERE id=?", status, finished, string(raw), p.ID); e != nil {
		return e
	}
	if windowsupdate.Terminal(p) && p.RebootKnown && (p.RebootRequired || q.Action == "scan" && p.Outcome == "ok" && !p.Truncated) {
		if e = patchObserveScanTx(ctx, tx, id, p, now); e != nil {
			return e
		}
	}
	if q.Progress == nil || q.Progress.Phase != p.Phase || q.Progress.Completed != p.Completed || windowsupdate.Terminal(p) {
		if e = auditDevice(ctx, tx, now, "device:"+id, "update_progress", id+":"+p.ID, p.Phase+":"+p.Outcome); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) UpdateJobs(ctx context.Context, id string, now time.Time) ([]UpdateJob, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = expireUpdates(ctx, tx, now); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+updateColumns+" FROM update_jobs WHERE device_id=? ORDER BY created_at DESC,id DESC LIMIT 20", id)
	if e != nil {
		return nil, e
	}
	result := []UpdateJob{}
	for rows.Next() {
		q, e := scanUpdate(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		result = append(result, q)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	return result, tx.Commit()
}
func (s *Store) PruneUpdateJobs(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = expireUpdates(ctx, tx, now); e != nil {
		return e
	}
	return tx.Commit()
}
