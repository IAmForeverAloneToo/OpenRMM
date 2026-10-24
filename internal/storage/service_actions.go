package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
	"strings"
	"time"
)

var ErrAction = errors.New("service action unavailable; refresh the device and check its state, permissions, and pending actions")

type ServiceAction struct {
	protocol.ServiceAction
	DeviceID     string `json:"device_id"`
	Actor        string `json:"actor"`
	CreatedAt    int64  `json:"created_at"`
	DispatchedAt *int64 `json:"dispatched_at"`
	FinishedAt   *int64 `json:"finished_at"`
	Status       string `json:"status"`
	Outcome      string `json:"outcome"`
	State        string `json:"state"`
}

const actionColumns = "id,service_name,action,expires_at,device_id,actor,created_at,dispatched_at,finished_at,status,outcome,observed_state"

func scanAction(row interface{ Scan(...any) error }) (ServiceAction, error) {
	var a ServiceAction
	e := row.Scan(&a.ID, &a.Service, &a.Action, &a.ExpiresAt, &a.DeviceID, &a.Actor, &a.CreatedAt, &a.DispatchedAt, &a.FinishedAt, &a.Status, &a.Outcome, &a.State)
	return a, e
}
func expireActions(ctx context.Context, tx *sql.Tx, now time.Time) error {
	// Record every terminal transition in the same transaction, including revocation.
	rows, e := tx.QueryContext(ctx, `SELECT id,device_id,status FROM service_actions WHERE status IN ('queued','dispatched') AND (expires_at<=? OR device_id IN (SELECT id FROM devices WHERE revoked_at IS NOT NULL))`, now.Unix())
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
		if _, e = tx.ExecContext(ctx, "UPDATE service_actions SET status=?,finished_at=? WHERE id=?", status, now.Unix(), v.id); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, "server", "service_action_"+status, v.device+":"+v.id, status); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) QueueServiceAction(ctx context.Context, a ServiceAction, now time.Time, offlineAfter time.Duration) error {
	if !protocol.ValidID(a.ID) || !protocol.ValidID(a.DeviceID) || !winservices.Manageable(a.Service) || !winservices.Action(a.Action) || !winservices.Text(a.Actor, 128) {
		return ErrAction
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = queueServiceAction(ctx, tx, a, now, offlineAfter); e != nil {
		return e
	}
	return tx.Commit()
}

// Shared by reviewed manual controls and the bounded health-response evaluator.
// The latter commits the intent, attempt and uncertainty guard atomically.
func queueServiceAction(ctx context.Context, tx *sql.Tx, a ServiceAction, now time.Time, offlineAfter time.Duration) error {
	var e error
	if e = authorizeActor(ctx, tx, a.Actor, a.DeviceID, "services"); e != nil {
		return e
	}
	if e = expireActions(ctx, tx, now); e != nil {
		return e
	}
	old, e := scanAction(tx.QueryRowContext(ctx, "SELECT "+actionColumns+" FROM service_actions WHERE id=?", a.ID))
	if e == nil {
		if old.DeviceID != a.DeviceID || old.Service != a.Service || old.Action != a.Action || old.Actor != a.Actor {
			return ErrAction
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var data string
	var receipt int64
	e = tx.QueryRowContext(ctx, `SELECT f.snapshot_json,f.snapshot_at FROM device_services f JOIN devices d ON d.id=f.device_id WHERE d.id=? AND d.revoked_at IS NULL AND d.last_contact_at>? AND d.last_contact_at<=? AND f.last_status='ok' AND f.capability_version=1 AND f.snapshot_at>? AND f.snapshot_at<=?`, a.DeviceID, now.Add(-offlineAfter).Unix(), now.Unix(), now.Add(-2*time.Minute).Unix(), now.Unix()).Scan(&data, &receipt)
	if e != nil {
		return ErrAction
	}
	var v protocol.Services
	if json.Unmarshal([]byte(data), &v) != nil || !winservices.Valid(v) {
		return ErrAction
	}
	allowed := false
	for _, item := range v.Items {
		if strings.EqualFold(item.Name, a.Service) {
			allowed = (a.Action == "start" && item.CanStart) || (a.Action == "stop" && item.CanStop) || (a.Action == "restart" && item.CanStart && item.CanStop)
		}
	}
	if !allowed {
		return ErrAction
	}
	// Keep at most 1,000 records globally without pruning still-valid intent IDs.
	if _, e = tx.ExecContext(ctx, `DELETE FROM service_actions WHERE id IN (SELECT id FROM service_actions WHERE status NOT IN ('queued','dispatched') AND created_at<? ORDER BY created_at,id LIMIT (SELECT MAX(COUNT(*)-999,0) FROM service_actions))`, now.Add(-2*time.Minute).Unix()); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM service_actions").Scan(&count); e != nil {
		return e
	}
	if count >= 1000 {
		return ErrAction
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO service_actions(id,device_id,service_name,action,actor,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?,'queued')`, a.ID, a.DeviceID, a.Service, a.Action, a.Actor, now.Unix(), now.Add(time.Minute).Unix()); e != nil {
		return ErrAction
	}
	if e = auditDevice(ctx, tx, now, a.Actor, "service_action_requested", a.DeviceID+":"+a.ID+":"+a.Service+":"+a.Action, "queued"); e != nil {
		return e
	}

	return nil
}
func authorizedActionDevice(ctx context.Context, tx *sql.Tx, id, fp string, now time.Time) error {
	var v string
	e := tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))`, id, fp, fp, now.Unix()).Scan(&v)
	if e != nil {
		return ErrAuthentication
	}
	return nil
}
func (s *Store) DispatchServiceAction(ctx context.Context, id, fp string, now time.Time) (protocol.ServiceDispatch, error) {
	v := protocol.ServiceDispatch{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return v, e
	}
	if e = expireActions(ctx, tx, now); e != nil {
		return v, e
	}
	a, e := scanAction(tx.QueryRowContext(ctx, "SELECT "+actionColumns+" FROM service_actions WHERE device_id=? AND status='queued'", id))
	if errors.Is(e, sql.ErrNoRows) {
		return v, tx.Commit()
	}
	if e != nil {
		return v, e
	}
	if e = authorizeActor(ctx, tx, a.Actor, id, "services"); e != nil {
		if !errors.Is(e, ErrForbidden) {
			return v, e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE service_actions SET status='cancelled',finished_at=? WHERE id=?", now.Unix(), a.ID); e != nil {
			return v, e
		}
		if e = auditDevice(ctx, tx, now, "server", "technician_work_cancelled", id+":"+a.ID, "authorization_changed"); e != nil {
			return v, e
		}
		return v, tx.Commit()
	}
	allowed, e := healthDispatchAllowed(ctx, tx, a, now)
	if e != nil {
		return v, e
	}
	if !allowed {
		if _, e = tx.ExecContext(ctx, "UPDATE service_actions SET status='cancelled',finished_at=? WHERE id=?", now.Unix(), a.ID); e != nil {
			return v, e
		}
		if e = auditDevice(ctx, tx, now, "server", "health_response_cancelled", id+":"+a.ID, "condition_or_configuration_changed"); e != nil {
			return v, e
		}
		return v, tx.Commit()
	}
	// No lease/redelivery: commit before sending; an ambiguous response is never replayed.
	expiry := now.Add(90 * time.Second).Unix()
	if _, e = tx.ExecContext(ctx, "UPDATE service_actions SET status='dispatched',dispatched_at=?,expires_at=? WHERE id=?", now.Unix(), expiry, a.ID); e != nil {
		return v, e
	}
	if e = auditDevice(ctx, tx, now, "device:"+id, "service_action_dispatched", id+":"+a.ID, "dispatched"); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	a.ExpiresAt = expiry
	v.Action = &a.ServiceAction
	return v, nil
}
func (s *Store) CompleteServiceAction(ctx context.Context, id, fp string, r protocol.ServiceResult, now time.Time) error {
	if !winservices.ResultValid(r) {
		return ErrAction
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return e
	}
	if e = expireActions(ctx, tx, now); e != nil {
		return e
	}
	a, e := scanAction(tx.QueryRowContext(ctx, "SELECT "+actionColumns+" FROM service_actions WHERE id=? AND device_id=?", r.ID, id))
	if e != nil {
		return ErrAction
	}
	if a.Status != "dispatched" {
		if (a.Status == "succeeded" || a.Status == "failed") && a.Outcome == r.Outcome && a.State == r.State {
			return tx.Commit()
		}
		return ErrAction
	}
	status := "failed"
	if r.Outcome == "succeeded" {
		target := "running"
		if a.Action == "stop" {
			target = "stopped"
		}
		if r.State != target {
			return ErrAction
		}
		status = "succeeded"
	}
	if _, e = tx.ExecContext(ctx, "UPDATE service_actions SET status=?,outcome=?,observed_state=?,finished_at=? WHERE id=?", status, r.Outcome, r.State, now.Unix(), a.ID); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, "device:"+id, "service_action_completed", id+":"+a.ID, status+":"+r.Outcome+":"+r.State); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ServiceActions(ctx context.Context, id string, now time.Time) ([]ServiceAction, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = expireActions(ctx, tx, now); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+actionColumns+" FROM service_actions WHERE device_id=? ORDER BY created_at DESC,id DESC LIMIT 20", id)
	if e != nil {
		return nil, e
	}
	items := []ServiceAction{}
	for rows.Next() {
		v, e := scanAction(rows)
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
