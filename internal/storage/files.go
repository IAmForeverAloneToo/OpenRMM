package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"time"
)

var ErrFile = errors.New("file operation unavailable; refresh permissions, folder policy and device state")

type FileSupport struct {
	Status     string               `json:"status"`
	ReportedAt int64                `json:"reported_at"`
	Support    protocol.FileSupport `json:"support"`
}
type FileJob struct {
	protocol.FileJob
	DeviceID     string               `json:"device_id"`
	Actor        string               `json:"actor"`
	Status       string               `json:"status"`
	CreatedAt    int64                `json:"created_at"`
	DispatchedAt *int64               `json:"dispatched_at"`
	FinishedAt   *int64               `json:"finished_at"`
	PayloadUntil int64                `json:"payload_until"`
	Result       *protocol.FileResult `json:"result,omitempty"`
}

func (s *Store) RecordFileSupport(ctx context.Context, id, fp string, r protocol.FeatureReport, now time.Time) error {
	r, e := filetransfer.Normalize(r)
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
	_, e = tx.ExecContext(ctx, `INSERT INTO device_file_support VALUES(?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,reported_at=excluded.reported_at,support_json=excluded.support_json WHERE excluded.reported_at>=device_file_support.reported_at`, id, 1, r.Status, now.Unix(), string(r.Data))
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) FileSupport(ctx context.Context, id string) (FileSupport, error) {
	v := FileSupport{Status: "not_reported", Support: protocol.FileSupport{Roots: []protocol.FileRoot{}}}
	var raw string
	e := s.db.QueryRowContext(ctx, "SELECT last_status,reported_at,support_json FROM device_file_support WHERE device_id=?", id).Scan(&v.Status, &v.ReportedAt, &raw)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	if e == nil && v.Status == "ok" && (filetransfer.Decode([]byte(raw), &v.Support) != nil || !filetransfer.SupportValid(v.Support)) {
		e = ErrFile
	}
	return v, e
}
func fileSweep(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, e := tx.QueryContext(ctx, `SELECT id,device_id,actor,status,expires_at FROM file_jobs WHERE status IN('staged','queued','dispatched')`)
	if e != nil {
		return e
	}
	type item struct {
		id, device, actor, status string
		expires                   int64
	}
	var items []item
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.id, &v.device, &v.actor, &v.status, &v.expires); e != nil {
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
		var revoked int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NOT NULL", v.device).Scan(&revoked); e != nil {
			return e
		}
		allowed := authorizeActor(ctx, tx, v.actor, v.device, "files")
		if allowed != nil && !errors.Is(allowed, ErrForbidden) {
			return allowed
		}
		if v.expires > now.Unix() && revoked == 0 && allowed == nil {
			continue
		}
		status := "expired"
		if v.status == "dispatched" {
			status = "unknown"
		}
		if _, e = tx.ExecContext(ctx, "UPDATE file_jobs SET status=?,finished_at=?,payload=X'',reserve_bytes=0 WHERE id=?", status, now.Unix(), v.id); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, "server", "file_"+status, v.device+":"+v.id, status); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE file_jobs SET payload=X'',reserve_bytes=0 WHERE payload_until<=? OR device_id IN(SELECT id FROM devices WHERE revoked_at IS NOT NULL)", now.Unix()); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `DELETE FROM file_jobs WHERE status NOT IN('staged','queued','dispatched') AND(created_at<? OR id IN(SELECT id FROM file_jobs ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET 199))`, now.Add(-24*time.Hour).Unix())
	return e
}
func (s *Store) SweepFiles(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = fileSweep(ctx, tx, now); e != nil {
		return e
	}
	return tx.Commit()
}
func filePermission(ctx context.Context, tx *sql.Tx, device, root, op string, now time.Time, offline time.Duration) error {
	var raw string
	e := tx.QueryRowContext(ctx, `SELECT f.support_json FROM device_file_support f JOIN devices d ON d.id=f.device_id WHERE d.id=? AND d.revoked_at IS NULL AND d.last_contact_at>? AND d.last_contact_at<=? AND f.last_status='ok' AND f.capability_version=1 AND f.reported_at>? AND f.reported_at<=?`, device, now.Add(-offline).Unix(), now.Unix(), now.Add(-2*time.Minute).Unix(), now.Unix()).Scan(&raw)
	var s protocol.FileSupport
	if e != nil || filetransfer.Decode([]byte(raw), &s) != nil || !filetransfer.SupportValid(s) {
		return ErrFile
	}
	for _, r := range s.Roots {
		if r.ID == root && (op == "upload" && r.Write || op != "upload" && r.Read) {
			return nil
		}
	}
	return ErrFile
}
func (s *Store) QueueFile(ctx context.Context, q protocol.FileJob, device, actor string, now time.Time, offline time.Duration) error {
	if !protocol.ValidID(device) || !filetransfer.JobValid(q) || actor == "" {
		return ErrFile
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, actor, device, "files"); e != nil {
		return e
	}
	if e = fileSweep(ctx, tx, now); e != nil {
		return e
	}
	// Replay compares immutable metadata and payload digest before checking busy.
	data := q.Data
	q.Data = nil
	q.ExpiresAt = 0
	meta, _ := json.Marshal(q)
	var old, owner, target string
	e = tx.QueryRowContext(ctx, "SELECT job_json,actor,device_id FROM file_jobs WHERE id=?", q.ID).Scan(&old, &owner, &target)
	if e == nil {
		if old != string(meta) || owner != actor || target != device {
			return ErrFile
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e = filePermission(ctx, tx, device, q.Root, q.Operation, now, offline); e != nil {
		return e
	}
	reserve := q.Size
	if q.Operation == "download" {
		reserve = filetransfer.MaxFile
	}
	var jobs, active, busy int
	var used int64
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN status IN('staged','queued','dispatched') THEN 1 ELSE 0 END),0),COALESCE(SUM(reserve_bytes),0),COALESCE(SUM(CASE WHEN device_id=? AND status IN('staged','queued','dispatched') THEN 1 ELSE 0 END),0) FROM file_jobs", device).Scan(&jobs, &active, &used, &busy); e != nil {
		return e
	}
	if jobs >= 200 || active >= 8 || busy != 0 || used+reserve > 32*1024*1024 {
		return ErrFile
	}
	status := "queued"
	expires := now.Add(time.Minute).Unix()
	if q.Operation == "upload" {
		status = "staged"
		expires = now.Add(5 * time.Minute).Unix()
	}
	if data == nil {
		data = []byte{}
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO file_jobs(id,device_id,actor,job_json,payload,reserve_bytes,created_at,expires_at,payload_until,status)VALUES(?,?,?,?,?,?,?,?,?,?)", q.ID, device, actor, string(meta), data, reserve, now.Unix(), expires, now.Add(15*time.Minute).Unix(), status); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "file_requested", device+":"+q.ID, q.Operation+":"+q.Root+":"+q.Path+":"+q.Hash); e != nil {
		return e
	}
	return tx.Commit()
}
func scanFile(row interface{ Scan(...any) error }) (FileJob, error) {
	var v FileJob
	var raw, result string
	e := row.Scan(&raw, &v.DeviceID, &v.Actor, &v.Status, &v.CreatedAt, &v.ExpiresAt, &v.PayloadUntil, &v.DispatchedAt, &v.FinishedAt, &result)
	if e != nil {
		return v, e
	}
	expires := v.ExpiresAt
	if filetransfer.Decode([]byte(raw), &v.FileJob) != nil {
		return v, ErrFile
	}
	v.ExpiresAt = expires
	if result != "" {
		v.Result = new(protocol.FileResult)
		if filetransfer.Decode([]byte(result), v.Result) != nil {
			return v, ErrFile
		}
	}
	return v, nil
}

const fileColumns = "job_json,device_id,actor,status,created_at,expires_at,payload_until,dispatched_at,finished_at,result_json"

func (s *Store) FileJobs(ctx context.Context, v Session, device string, now time.Time) ([]FileJob, error) {
	if !v.Can("files") {
		return nil, ErrForbidden
	}
	if e := s.AuthorizeDevice(ctx, v, device, "files"); e != nil {
		return nil, e
	}
	if e := s.SweepFiles(ctx, now); e != nil {
		return nil, e
	}
	scope, args := technicianScope(v, "device_id")
	args = append([]any{device}, args...)
	rows, e := s.db.QueryContext(ctx, "SELECT "+fileColumns+" FROM file_jobs WHERE device_id=? AND "+scope+" ORDER BY created_at DESC,id DESC LIMIT 50", args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []FileJob{}
	for rows.Next() {
		a, e := scanFile(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, a)
	}
	return items, rows.Err()
}

// FileJob reads retained metadata only, never payload. The actor's current
// permissions and the exact device are checked even with a previously issued
// session projection. A job ID alone grants no access.
func (s *Store) FileJob(ctx context.Context, v Session, device, id string, now time.Time) (FileJob, error) {
	if !protocol.ValidID(device) || !protocol.ValidID(id) || !v.Can("files") {
		return FileJob{}, ErrFile
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return FileJob{}, e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, v.Actor(), device, "files"); e != nil {
		return FileJob{}, e
	}
	var active int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NULL", device).Scan(&active); e != nil || active != 1 {
		return FileJob{}, ErrFile
	}
	if e = fileSweep(ctx, tx, now); e != nil {
		return FileJob{}, e
	}
	a, e := scanFile(tx.QueryRowContext(ctx, "SELECT "+fileColumns+" FROM file_jobs WHERE id=? AND device_id=?", id, device))
	if errors.Is(e, sql.ErrNoRows) {
		return FileJob{}, ErrFile
	}
	if e != nil {
		return FileJob{}, e
	}
	return a, tx.Commit()
}
func (s *Store) DispatchFile(ctx context.Context, device, fp string, now time.Time) (protocol.FileDispatch, error) {
	out := protocol.FileDispatch{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, device, fp, now); e != nil {
		return out, e
	}
	if e = fileSweep(ctx, tx, now); e != nil {
		return out, e
	}
	v, e := scanFile(tx.QueryRowContext(ctx, "SELECT "+fileColumns+" FROM file_jobs WHERE device_id=? AND status='queued' ORDER BY created_at,id LIMIT 1", device))
	if errors.Is(e, sql.ErrNoRows) {
		return out, tx.Commit()
	}
	if e != nil {
		return out, e
	}
	if e = filePermission(ctx, tx, device, v.Root, v.Operation, now, 120*time.Second); e != nil {
		return out, e
	}
	if e = tx.QueryRowContext(ctx, "SELECT payload FROM file_jobs WHERE id=?", v.ID).Scan(&v.Data); e != nil {
		return out, e
	}
	if v.Operation != "upload" {
		v.Data = nil
	}
	v.ExpiresAt = now.Add(time.Minute).Unix()
	if !filetransfer.JobValid(v.FileJob) {
		return out, ErrFile
	}
	if _, e = tx.ExecContext(ctx, "UPDATE file_jobs SET status='dispatched',dispatched_at=?,expires_at=?,payload=X'' WHERE id=?", now.Unix(), now.Add(2*time.Minute).Unix(), v.ID); e != nil {
		return out, e
	}
	if e = auditDevice(ctx, tx, now, "device:"+device, "file_dispatched", device+":"+v.ID, v.Operation); e != nil {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	out.Job = &v.FileJob
	return out, nil
}
func (s *Store) CompleteFile(ctx context.Context, device, fp string, r protocol.FileResult, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, device, fp, now); e != nil {
		return e
	}
	if e = fileSweep(ctx, tx, now); e != nil {
		return e
	}
	v, e := scanFile(tx.QueryRowContext(ctx, "SELECT "+fileColumns+" FROM file_jobs WHERE id=? AND device_id=?", r.ID, device))
	if e != nil {
		return ErrFile
	}
	if e = authorizeActor(ctx, tx, v.Actor, device, "files"); e != nil {
		return e
	}
	if !filetransfer.ResultValid(v.FileJob, r) {
		return ErrFile
	}
	payload := r.Data
	r.Data = nil
	raw, _ := json.Marshal(r)
	if v.Status != "dispatched" {
		if v.Result != nil {
			old, _ := json.Marshal(v.Result)
			if string(old) == string(raw) {
				return tx.Commit()
			}
		}
		return ErrFile
	}
	reserve := int64(0)
	if v.Operation == "download" && r.Outcome == "succeeded" {
		reserve = int64(len(payload))
	}
	if payload == nil {
		payload = []byte{}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE file_jobs SET status=?,result_json=?,payload=?,reserve_bytes=?,finished_at=? WHERE id=?", r.Outcome, string(raw), payload, reserve, now.Unix(), v.ID); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, "device:"+device, "file_completed", device+":"+v.ID, r.Outcome+":"+r.Hash); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) FileDownload(ctx context.Context, v Session, device, id string, now time.Time) (FileJob, []byte, error) {
	var b []byte
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return FileJob{}, nil, e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, v.Actor(), device, "files"); e != nil {
		return FileJob{}, nil, e
	}
	var active int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NULL", device).Scan(&active); e != nil || active != 1 {
		return FileJob{}, nil, ErrFile
	}
	if e = fileSweep(ctx, tx, now); e != nil {
		return FileJob{}, nil, e
	}
	a, e := scanFile(tx.QueryRowContext(ctx, "SELECT "+fileColumns+" FROM file_jobs WHERE id=? AND device_id=?", id, device))
	if e != nil || a.Operation != "download" || a.Status != "succeeded" || a.PayloadUntil <= now.Unix() || a.Result == nil {
		return a, nil, ErrFile
	}
	if e = tx.QueryRowContext(ctx, "SELECT payload FROM file_jobs WHERE id=?", id).Scan(&b); e != nil {
		return a, nil, e
	}
	if int64(len(b)) != a.Result.Size || filetransfer.Digest(b) != a.Result.Hash {
		return a, nil, ErrFile
	}
	if e = auditDevice(ctx, tx, now, v.Actor(), "file_downloaded", device+":"+id, a.Result.Hash); e != nil {
		return a, nil, e
	}
	return a, b, tx.Commit()
}
func (s *Store) CancelFile(ctx context.Context, v Session, device, id string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, v.Actor(), device, "files"); e != nil {
		return e
	}
	if e = fileSweep(ctx, tx, now); e != nil {
		return e
	}
	var status string
	if e = tx.QueryRowContext(ctx, "SELECT status FROM file_jobs WHERE id=? AND device_id=?", id, device).Scan(&status); e != nil {
		return ErrFile
	}
	if status != "staged" && status != "queued" && status != "dispatched" {
		return tx.Commit()
	}
	next := "cancelled"
	if status == "dispatched" {
		next = "unknown"
	}
	if _, e = tx.ExecContext(ctx, "UPDATE file_jobs SET status=?,finished_at=?,payload=X'',reserve_bytes=0 WHERE id=?", next, now.Unix(), id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, v.Actor(), "file_cancelled", device+":"+id, next); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ConfirmFile(ctx context.Context, v Session, device, id string, now time.Time, offline time.Duration) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, v.Actor(), device, "files"); e != nil {
		return e
	}
	if e = fileSweep(ctx, tx, now); e != nil {
		return e
	}
	a, e := scanFile(tx.QueryRowContext(ctx, "SELECT "+fileColumns+" FROM file_jobs WHERE id=? AND device_id=?", id, device))
	if e != nil || a.Actor != v.Actor() || a.Operation != "upload" {
		return ErrFile
	}
	if a.Status != "staged" {
		if a.Status == "queued" || a.DispatchedAt != nil {
			return tx.Commit()
		}
		return ErrFile
	}
	if e = filePermission(ctx, tx, device, a.Root, a.Operation, now, offline); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE file_jobs SET status='queued',expires_at=? WHERE id=?", now.Add(time.Minute).Unix(), id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, v.Actor(), "file_upload_confirmed", device+":"+id, a.Hash); e != nil {
		return e
	}
	return tx.Commit()
}
