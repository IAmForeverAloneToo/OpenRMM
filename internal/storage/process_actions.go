package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"

	"strconv"
	"time"
)

var ErrProcessAction = errors.New("process action unavailable; refresh the device and check its state, permissions, and pending actions")

type ProcessAction struct {
	protocol.ProcessAction
	DeviceID     string `json:"device_id"`
	Actor        string `json:"actor"`
	CreatedAt    int64  `json:"created_at"`
	DispatchedAt *int64 `json:"dispatched_at"`
	FinishedAt   *int64 `json:"finished_at"`
	Status       string `json:"status"`
	Outcome      string `json:"outcome"`
}

const processActionColumns = "id,pid,start,name,expires_at,device_id,actor,created_at,dispatched_at,finished_at,status,outcome"

func scanProcessAction(row interface{ Scan(...any) error }) (ProcessAction, error) {
	var a ProcessAction
	e := row.Scan(&a.ID, &a.PID, &a.Start, &a.Name, &a.ExpiresAt, &a.DeviceID, &a.Actor, &a.CreatedAt, &a.DispatchedAt, &a.FinishedAt, &a.Status, &a.Outcome)
	return a, e
}
func expireProcessActions(ctx context.Context, tx *sql.Tx, now time.Time) error {
	// Record every terminal transition in the same transaction, including revocation.
	rows, e := tx.QueryContext(ctx, `SELECT id,device_id,status FROM process_actions WHERE status IN ('queued','dispatched') AND (expires_at<=? OR device_id IN (SELECT id FROM devices WHERE revoked_at IS NOT NULL))`, now.Unix())
	if e != nil {
		return e
	}
	type item struct{ id, device, status string }
	var items []item
	for rows.Next() {
		var v item
		if e := rows.Scan(&v.id, &v.device, &v.status); e != nil {
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
		// A dispatched control may already be executing when revocation happens.
		if _, e = tx.ExecContext(ctx, "UPDATE process_actions SET status=?,finished_at=? WHERE id=?", status, now.Unix(), v.id); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, "server", "process_action_"+status, v.device+":"+v.id, status); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) QueueProcessAction(ctx context.Context, a ProcessAction, now time.Time, offlineAfter time.Duration) error {
	if !protocol.ValidID(a.ID) || !protocol.ValidID(a.DeviceID) || !processes.Manageable(a.PID, a.Name) || !processes.Start(a.Start) || len(a.Actor) == 0 || len(a.Actor) > 128 {
		return ErrProcessAction
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, a.Actor, a.DeviceID, "processes"); e != nil {
		return e
	}
	if e = expireProcessActions(ctx, tx, now); e != nil {
		return e
	}
	old, e := scanProcessAction(tx.QueryRowContext(ctx, "SELECT "+processActionColumns+" FROM process_actions WHERE id=?", a.ID))
	if e == nil {
		if old.DeviceID != a.DeviceID || old.PID != a.PID || old.Start != a.Start || old.Name != a.Name || old.Actor != a.Actor {
			return ErrProcessAction
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var data string
	var receipt int64
	e = tx.QueryRowContext(ctx, `SELECT f.snapshot_json,f.snapshot_at FROM device_processes f JOIN devices d ON d.id=f.device_id WHERE d.id=? AND d.revoked_at IS NULL AND d.last_contact_at>? AND d.last_contact_at<=? AND f.last_status='ok' AND f.capability_version=1 AND f.snapshot_at>? AND f.snapshot_at<=?`, a.DeviceID, now.Add(-offlineAfter).Unix(), now.Unix(), now.Add(-2*time.Minute).Unix(), now.Unix()).Scan(&data, &receipt)
	if e != nil {
		return ErrProcessAction
	}
	var v protocol.Processes
	if json.Unmarshal([]byte(data), &v) != nil || !processes.Valid(v) {
		return ErrProcessAction
	}
	allowed := false
	for _, item := range v.Items {
		if item.PID == a.PID && item.Start == a.Start && item.Name == a.Name {
			allowed = item.CanTerminate
		}
	}
	if !allowed {
		return ErrProcessAction
	}
	// Keep at most 1,000 records globally without pruning still-valid intent IDs.
	if _, e = tx.ExecContext(ctx, `DELETE FROM process_actions WHERE id IN (SELECT id FROM process_actions WHERE status NOT IN ('queued','dispatched') AND created_at<? ORDER BY created_at,id LIMIT (SELECT MAX(COUNT(*)-999,0) FROM process_actions))`, now.Add(-2*time.Minute).Unix()); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM process_actions").Scan(&count); e != nil {
		return e
	}
	if count >= 1000 {
		return ErrProcessAction
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO process_actions(id,device_id,pid,start,name,actor,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?,?,'queued')`, a.ID, a.DeviceID, a.PID, a.Start, a.Name, a.Actor, now.Unix(), now.Add(time.Minute).Unix()); e != nil {
		return ErrProcessAction
	}
	if e = auditDevice(ctx, tx, now, a.Actor, "process_action_requested", a.DeviceID+":"+a.ID+":"+strconv.FormatUint(uint64(a.PID), 10)+":"+a.Start, "queued"); e != nil {
		return e
	}

	return tx.Commit()
}
func (s *Store) DispatchProcessAction(ctx context.Context, id, fp string, now time.Time) (protocol.ProcessDispatch, error) {
	v := protocol.ProcessDispatch{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return v, e
	}
	if e = expireProcessActions(ctx, tx, now); e != nil {
		return v, e
	}
	a, e := scanProcessAction(tx.QueryRowContext(ctx, "SELECT "+processActionColumns+" FROM process_actions WHERE device_id=? AND status='queued'", id))
	if errors.Is(e, sql.ErrNoRows) {
		return v, tx.Commit()
	}
	if e != nil {
		return v, e
	}
	if e = authorizeActor(ctx, tx, a.Actor, id, "processes"); e != nil {
		if !errors.Is(e, ErrForbidden) {
			return v, e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE process_actions SET status='cancelled',finished_at=? WHERE id=?", now.Unix(), a.ID); e != nil {
			return v, e
		}
		if e = auditDevice(ctx, tx, now, "server", "technician_work_cancelled", id+":"+a.ID, "authorization_changed"); e != nil {
			return v, e
		}
		return v, tx.Commit()
	}
	// No lease/redelivery: commit before sending; an ambiguous response is never replayed.
	expiry := now.Add(90 * time.Second).Unix()
	if _, e = tx.ExecContext(ctx, "UPDATE process_actions SET status='dispatched',dispatched_at=?,expires_at=? WHERE id=?", now.Unix(), expiry, a.ID); e != nil {
		return v, e
	}
	if e = auditDevice(ctx, tx, now, "device:"+id, "process_action_dispatched", id+":"+a.ID, "dispatched"); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	a.ExpiresAt = expiry
	v.Action = &a.ProcessAction
	return v, nil
}
func (s *Store) CompleteProcessAction(ctx context.Context, id, fp string, r protocol.ProcessResult, now time.Time) error {
	if !processes.ResultValid(r) {
		return ErrProcessAction
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return e
	}
	if e = expireProcessActions(ctx, tx, now); e != nil {
		return e
	}
	a, e := scanProcessAction(tx.QueryRowContext(ctx, "SELECT "+processActionColumns+" FROM process_actions WHERE id=? AND device_id=?", r.ID, id))
	if e != nil {
		return ErrProcessAction
	}
	if a.Status != "dispatched" {
		if (a.Status == "succeeded" || a.Status == "failed") && a.Outcome == r.Outcome {
			return tx.Commit()
		}
		return ErrProcessAction
	}
	status := "failed"
	if r.Outcome == "succeeded" {

		status = "succeeded"
	}
	if _, e = tx.ExecContext(ctx, "UPDATE process_actions SET status=?,outcome=?,finished_at=? WHERE id=?", status, r.Outcome, now.Unix(), a.ID); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, "device:"+id, "process_action_completed", id+":"+a.ID, status+":"+r.Outcome); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ProcessActions(ctx context.Context, id string, now time.Time) ([]ProcessAction, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = expireProcessActions(ctx, tx, now); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+processActionColumns+" FROM process_actions WHERE device_id=? ORDER BY created_at DESC,id DESC LIMIT 20", id)
	if e != nil {
		return nil, e
	}
	items := []ProcessAction{}
	for rows.Next() {
		v, e := scanProcessAction(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	return items, tx.Commit()
}
