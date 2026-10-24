package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"time"
)

type ScriptRun struct {
	protocol.ScriptJob
	DeviceID        string                 `json:"device_id"`
	Actor           string                 `json:"actor"`
	CreatedAt       int64                  `json:"created_at"`
	DispatchedAt    *int64                 `json:"dispatched_at"`
	FinishedAt      *int64                 `json:"finished_at"`
	CancelRequested bool                   `json:"cancel_requested"`
	Status          string                 `json:"status"`
	Result          *protocol.ScriptResult `json:"result"`
}

const runColumns = "r.id,r.device_id,r.actor,r.created_at,r.expires_at,r.dispatched_at,r.finished_at,r.cancel_requested,r.status,r.arguments_json,r.result_json,v.id,v.script_id,v.version,v.sha256,v.definition_json"
const runJoin = " FROM script_runs r JOIN script_versions v ON v.id=r.version_id "

func scanRun(row interface{ Scan(...any) error }) (ScriptRun, error) {
	var r ScriptRun
	var args, result, definition string
	e := row.Scan(&r.ID, &r.DeviceID, &r.Actor, &r.CreatedAt, &r.ExpiresAt, &r.DispatchedAt, &r.FinishedAt, &r.CancelRequested, &r.Status, &args, &result, &r.Version.ID, &r.Version.ScriptID, &r.Version.Number, &r.Version.Hash, &definition)
	if e != nil {
		return r, e
	}
	if scripting.Decode([]byte(args), &r.Arguments) != nil || scripting.Decode([]byte(definition), &r.Version.Definition) != nil || !scripting.JobValid(r.ScriptJob) {
		return r, ErrScript
	}
	if result != "" {
		r.Result = new(protocol.ScriptResult)
		if scripting.Decode([]byte(result), r.Result) != nil || !scripting.ResultValid(*r.Result) || r.Result.ID != r.ID {
			return r, ErrScript
		}
	}
	return r, nil
}
func expireScriptRuns(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, e := tx.QueryContext(ctx, `SELECT id,device_id,status FROM script_runs WHERE status IN('queued','dispatched','running') AND(expires_at<=? OR device_id IN(SELECT id FROM devices WHERE revoked_at IS NOT NULL))`, now.Unix())
	if e != nil {
		return e
	}
	type item struct{ id, device, status string }
	items := []item{}
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
		status := "unknown"
		if v.status == "queued" {
			status = "expired"
		}
		raw, _ := json.Marshal(scripting.Failure(v.id, "unknown"))
		if _, e = tx.ExecContext(ctx, "UPDATE script_runs SET status=?,finished_at=?,result_json=? WHERE id=?", status, now.Unix(), string(raw), v.id); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, "server", "script_run_"+status, v.device+":"+v.id, status); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) QueueScriptRun(ctx context.Context, r ScriptRun, now time.Time, offline time.Duration) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = queueScriptRun(ctx, tx, r, now, offline); e != nil {
		return e
	}
	return tx.Commit()
}

// Shared by manual requests and the scheduler so consuming an occurrence and
// queuing its execution are one durable transaction.
func queueScriptRun(ctx context.Context, tx *sql.Tx, r ScriptRun, now time.Time, offline time.Duration) error {
	if !protocol.ValidID(r.ID) || !protocol.ValidID(r.DeviceID) || !protocol.ValidID(r.Version.ID) || r.Actor == "" || !scripting.Text(r.Actor, 128, false) {
		return ErrScript
	}
	var e error
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return e
	}
	old, e := scanRun(tx.QueryRowContext(ctx, "SELECT "+runColumns+runJoin+"WHERE r.id=?", r.ID))
	if e == nil {
		if old.DeviceID != r.DeviceID || old.Version.ID != r.Version.ID || old.Actor != r.Actor || scripting.ArgumentsHash(old.Arguments) != scripting.ArgumentsHash(r.Arguments) {
			return ErrScript
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	version, e := scanScriptVersion(tx.QueryRowContext(ctx, "SELECT "+scriptVersionColumns+" FROM script_versions WHERE id=?", r.Version.ID))
	if e != nil || !scripting.ArgumentsValid(version.Definition, r.Arguments) {
		return ErrScript
	}
	var support string
	e = tx.QueryRowContext(ctx, `SELECT f.support_json FROM device_script_support f JOIN devices d ON d.id=f.device_id WHERE d.id=? AND d.revoked_at IS NULL AND d.last_contact_at>? AND d.last_contact_at<=? AND f.capability_version=1 AND f.last_status='ok' AND f.reported_at>? AND f.reported_at<=?`, r.DeviceID, now.Add(-offline).Unix(), now.Unix(), now.Add(-2*time.Minute).Unix(), now.Unix()).Scan(&support)
	var cap protocol.ScriptSupport
	if e != nil || scripting.Decode([]byte(support), &cap) != nil || !scripting.SupportValid(cap) || !cap.Restricted || version.Definition.RunAs == "system" && cap.Administrator != "enabled" {
		return ErrScript
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM script_runs WHERE status NOT IN('queued','dispatched','running') AND created_at<? AND (created_at<? OR id IN(SELECT id FROM script_runs ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET 1999))`, now.Add(-2*time.Minute).Unix(), now.Add(-30*24*time.Hour).Unix()); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM script_runs").Scan(&count); e != nil {
		return e
	}
	if count >= 2000 {
		return ErrScript
	}
	var active int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM script_runs WHERE device_id=? AND status IN('queued','dispatched','running')", r.DeviceID).Scan(&active); e != nil {
		return e
	}
	if active != 0 {
		return ErrScript
	}
	args, _ := json.Marshal(r.Arguments)
	if _, e = tx.ExecContext(ctx, `INSERT INTO script_runs(id,device_id,version_id,arguments_json,actor,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?,'queued')`, r.ID, r.DeviceID, r.Version.ID, string(args), r.Actor, now.Unix(), now.Add(time.Minute).Unix()); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, r.Actor, "script_run_requested", r.DeviceID+":"+r.ID+":"+version.ID+":"+version.Hash+":"+version.Definition.RunAs, "queued"); e != nil {
		return e
	}
	return nil
}
func (s *Store) DispatchScriptRun(ctx context.Context, id, fp string, now time.Time) (protocol.ScriptDispatch, error) {
	v := protocol.ScriptDispatch{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return v, e
	}
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return v, e
	}
	r, e := scanRun(tx.QueryRowContext(ctx, "SELECT "+runColumns+runJoin+"WHERE r.device_id=? AND r.status='queued'", id))
	if errors.Is(e, sql.ErrNoRows) {
		return v, tx.Commit()
	}
	if e != nil {
		return v, e
	}
	// Commit consumed intent before delivery; no leases or automatic redelivery.
	if _, e = tx.ExecContext(ctx, "UPDATE script_runs SET status='dispatched',dispatched_at=?,expires_at=? WHERE id=?", now.Unix(), now.Add(time.Duration(r.Version.Definition.Timeout+30)*time.Second).Unix(), r.ID); e != nil {
		return v, e
	}
	if e = auditDevice(ctx, tx, now, "device:"+id, "script_run_dispatched", id+":"+r.ID, "dispatched"); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	r.ExpiresAt = now.Add(time.Minute).Unix()
	v.Job = &r.ScriptJob
	return v, nil
}
func (s *Store) UpdateScriptRun(ctx context.Context, id, fp string, result protocol.ScriptResult, now time.Time) (bool, error) {
	if !scripting.ResultValid(result) {
		return false, ErrScript
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return false, e
	}
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return false, e
	}
	r, e := scanRun(tx.QueryRowContext(ctx, "SELECT "+runColumns+runJoin+"WHERE r.id=? AND r.device_id=?", result.ID, id))
	if e != nil {
		return false, ErrScript
	}
	raw, _ := json.Marshal(result)
	if r.Status != "dispatched" && r.Status != "running" {
		if r.Result != nil {
			before, _ := json.Marshal(r.Result)
			if string(before) == string(raw) {
				return r.CancelRequested, tx.Commit()
			}
		}
		return false, ErrScript
	}
	status := "failed"
	switch result.Outcome {
	case "running":
		status = "running"
	case "succeeded", "cancelled", "unknown":
		status = result.Outcome
	}
	var finished any
	if status != "running" {
		finished = now.Unix()
	}
	if _, e = tx.ExecContext(ctx, "UPDATE script_runs SET status=?,result_json=?,finished_at=? WHERE id=?", status, string(raw), finished, r.ID); e != nil {
		return false, e
	}
	if r.Status != status || status != "running" {
		if e = auditDevice(ctx, tx, now, "device:"+id, "script_run_"+status, id+":"+r.ID, status+":"+result.Outcome); e != nil {
			return false, e
		}
	}
	return r.CancelRequested, tx.Commit()
}
func (s *Store) CancelScriptRun(ctx context.Context, id, run, actor string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return e
	}
	var status string
	var cancel bool
	e = tx.QueryRowContext(ctx, "SELECT status,cancel_requested FROM script_runs WHERE id=? AND device_id=?", run, id).Scan(&status, &cancel)
	if e != nil {
		return ErrScript
	}
	if cancel {
		return tx.Commit()
	}
	if status != "queued" && status != "dispatched" && status != "running" {
		return ErrScript
	}
	if status == "queued" {
		raw, _ := json.Marshal(scripting.Failure(run, "cancelled"))
		_, e = tx.ExecContext(ctx, "UPDATE script_runs SET status='cancelled',cancel_requested=1,finished_at=?,result_json=? WHERE id=?", now.Unix(), string(raw), run)
	} else {
		_, e = tx.ExecContext(ctx, "UPDATE script_runs SET cancel_requested=1 WHERE id=?", run)
	}
	if e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "script_run_cancel_requested", id+":"+run, "requested"); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ScriptRun(ctx context.Context, id, run string, now time.Time) (ScriptRun, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ScriptRun{}, e
	}
	defer tx.Rollback()
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return ScriptRun{}, e
	}
	r, e := scanRun(tx.QueryRowContext(ctx, "SELECT "+runColumns+runJoin+"WHERE r.id=? AND r.device_id=? AND r.created_at>?", run, id, now.Add(-30*24*time.Hour).Unix()))
	if e != nil {
		return r, ErrScript
	}
	return r, tx.Commit()
}
func (s *Store) ScriptRuns(ctx context.Context, id string, now time.Time) ([]ScriptRun, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+runColumns+runJoin+"WHERE r.device_id=? AND r.created_at>? ORDER BY r.created_at DESC,r.id DESC LIMIT 20", id, now.Add(-30*24*time.Hour).Unix())
	if e != nil {
		return nil, e
	}
	items := []ScriptRun{}
	for rows.Next() {
		r, e := scanRun(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	return items, tx.Commit()
}

func (s *Store) PruneScriptRuns(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM script_runs WHERE status NOT IN('queued','dispatched','running') AND created_at<=?", now.Add(-30*24*time.Hour).Unix()); e != nil {
		return e
	}
	return tx.Commit()
}
