package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"time"
)

var ErrEventQuery = errors.New("event query unavailable; check device connectivity, log permissions, pending requests, and filters")

type EventQuery struct {
	protocol.EventQuery
	DeviceID     string                `json:"device_id"`
	Actor        string                `json:"actor"`
	CreatedAt    int64                 `json:"created_at"`
	ExpiresAt    int64                 `json:"expires_at"`
	DispatchedAt *int64                `json:"dispatched_at"`
	FinishedAt   *int64                `json:"finished_at"`
	Status       string                `json:"status"`
	Result       *protocol.EventResult `json:"result"`
}

const eventQueryColumns = "id,device_id,actor,created_at,expires_at,dispatched_at,finished_at,status,filter_json,result_json"

func scanEventQuery(row interface{ Scan(...any) error }) (EventQuery, error) {
	var q EventQuery
	var filter, result string
	e := row.Scan(&q.ID, &q.DeviceID, &q.Actor, &q.CreatedAt, &q.ExpiresAt, &q.DispatchedAt, &q.FinishedAt, &q.Status, &filter, &result)
	if e != nil {
		return q, e
	}
	if json.Unmarshal([]byte(filter), &q.Filter) != nil {
		return q, ErrEventQuery
	}
	if result != "" {
		q.Result = new(protocol.EventResult)
		if json.Unmarshal([]byte(result), q.Result) != nil {
			return q, ErrEventQuery
		}
	}
	return q, nil
}
func expireEventQueries(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, e := tx.QueryContext(ctx, `SELECT id,device_id,status FROM event_log_queries WHERE (status IN ('queued','dispatched') AND (expires_at<=? OR device_id IN (SELECT id FROM devices WHERE revoked_at IS NOT NULL))) OR created_at<=?`, now.Unix(), now.Add(-15*time.Minute).Unix())
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
		if v.status == "queued" || v.status == "dispatched" {
			status := "expired"
			if v.status == "dispatched" {
				status = "unknown"
			}
			if _, e = tx.ExecContext(ctx, "UPDATE event_log_queries SET status=?,finished_at=? WHERE id=?", status, now.Unix(), v.id); e != nil {
				return e
			}
			if e = auditDevice(ctx, tx, now, "server", "event_query_"+status, v.device+":"+v.id, status); e != nil {
				return e
			}
		}
	}
	_, e = tx.ExecContext(ctx, "DELETE FROM event_log_queries WHERE created_at<=?", now.Add(-15*time.Minute).Unix())
	return e
}
func (s *Store) QueueEventQuery(ctx context.Context, q EventQuery, now time.Time, offline time.Duration) error {
	if !protocol.ValidID(q.ID) || !protocol.ValidID(q.DeviceID) || !eventlogs.FilterValid(q.Filter) || q.Actor == "" || len(q.Actor) > 128 {
		return ErrEventQuery
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, q.Actor, q.DeviceID, "events"); e != nil {
		return e
	}
	// Raw XPath is for responders.
	if q.Filter.XPath != "" {
		if e = authorizeActor(ctx, tx, q.Actor, q.DeviceID, "response"); e != nil {
			return e
		}
	}
	if e = expireEventQueries(ctx, tx, now); e != nil {
		return e
	}
	old, e := scanEventQuery(tx.QueryRowContext(ctx, "SELECT "+eventQueryColumns+" FROM event_log_queries WHERE id=?", q.ID))
	if e == nil {
		if old.DeviceID != q.DeviceID || old.Actor != q.Actor || old.Filter != q.Filter {
			return ErrEventQuery
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var data string
	var version int
	e = tx.QueryRowContext(ctx, `SELECT f.snapshot_json,f.capability_version FROM device_event_logs f JOIN devices d ON d.id=f.device_id WHERE d.id=? AND d.revoked_at IS NULL AND d.last_contact_at>? AND d.last_contact_at<=? AND f.last_status='ok' AND f.capability_version BETWEEN 1 AND 3 AND f.snapshot_at>? AND f.snapshot_at<=?`, q.DeviceID, now.Add(-offline).Unix(), now.Unix(), now.Add(-2*time.Minute).Unix(), now.Unix()).Scan(&data, &version)
	if e != nil {
		return ErrEventQuery
	}
	var support protocol.EventLogSupport
	if json.Unmarshal([]byte(data), &support) != nil || !eventlogs.SupportValid(support) {
		return ErrEventQuery
	}
	// Version 1 agents read only System and Application, 25 events, no XPath.
	if version == 1 && !eventlogs.FilterValidV1(q.Filter) {
		return ErrEventQuery
	}
	// A probed channel must be readable; other channels are tried by name.
	state, probed := support.Channels[q.Filter.Channel]
	switch q.Filter.Channel {
	case "System":
		state, probed = support.System, true
	case "Application":
		state, probed = support.Application, true
	}
	if probed && state != "readable" {
		return ErrEventQuery
	}
	// At most 100 queries and 64 MiB of cached results (pages hold up
	// to 250 events and 4 MiB).
	var count, cached int64
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(length(result_json)),0) FROM event_log_queries").Scan(&count, &cached); e != nil {
		return e
	}
	if count >= 100 || cached >= 64<<20 {
		return ErrEventQuery
	}
	filter, _ := json.Marshal(q.Filter)
	if _, e = tx.ExecContext(ctx, `INSERT INTO event_log_queries(id,device_id,actor,created_at,expires_at,status,filter_json) VALUES(?,?,?,?,?,'queued',?)`, q.ID, q.DeviceID, q.Actor, now.Unix(), now.Add(time.Minute).Unix(), string(filter)); e != nil {
		return ErrEventQuery
	}
	if e = auditDevice(ctx, tx, now, q.Actor, "event_query_requested", q.DeviceID+":"+q.ID+":"+q.Filter.Channel, "queued"); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) DispatchEventQuery(ctx context.Context, id, fp string, now time.Time) (protocol.EventDispatch, error) {
	v := protocol.EventDispatch{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return v, e
	}
	if e = expireEventQueries(ctx, tx, now); e != nil {
		return v, e
	}
	q, e := scanEventQuery(tx.QueryRowContext(ctx, "SELECT "+eventQueryColumns+" FROM event_log_queries WHERE device_id=? AND status='queued'", id))
	if errors.Is(e, sql.ErrNoRows) {
		return v, tx.Commit()
	}
	if e != nil {
		return v, e
	}
	e = authorizeActor(ctx, tx, q.Actor, id, "events")
	if e == nil && q.Filter.XPath != "" {
		e = authorizeActor(ctx, tx, q.Actor, id, "response")
	}
	if e != nil {
		if !errors.Is(e, ErrForbidden) {
			return v, e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE event_log_queries SET status='cancelled',finished_at=? WHERE id=?", now.Unix(), q.ID); e != nil {
			return v, e
		}
		if e = auditDevice(ctx, tx, now, "server", "technician_work_cancelled", id+":"+q.ID, "authorization_changed"); e != nil {
			return v, e
		}
		return v, tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, "UPDATE event_log_queries SET status='dispatched',dispatched_at=?,expires_at=? WHERE id=?", now.Unix(), now.Add(time.Minute).Unix(), q.ID); e != nil {
		return v, e
	}
	if e = auditDevice(ctx, tx, now, "device:"+id, "event_query_dispatched", id+":"+q.ID, "dispatched"); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	v.Query = &q.EventQuery
	return v, nil
}
func (s *Store) CompleteEventQuery(ctx context.Context, id, fp string, r protocol.EventResult, now time.Time) error {
	data, e := json.Marshal(r)
	if e != nil || len(data) > eventlogs.MaxResultBytes || !protocol.ValidID(r.ID) {
		return ErrEventQuery
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, id, fp, now); e != nil {
		return e
	}
	if e = expireEventQueries(ctx, tx, now); e != nil {
		return e
	}
	q, e := scanEventQuery(tx.QueryRowContext(ctx, "SELECT "+eventQueryColumns+" FROM event_log_queries WHERE id=? AND device_id=?", r.ID, id))
	if e != nil || !eventlogs.ResultValid(r, q.Filter) {
		return ErrEventQuery
	}
	if q.Status != "dispatched" {
		if (q.Status == "succeeded" || q.Status == "failed") && q.Result != nil {
			old, _ := json.Marshal(q.Result)
			if string(old) == string(data) {
				return tx.Commit()
			}
		}
		return ErrEventQuery
	}
	status := "failed"
	if r.Outcome == "ok" {
		status = "succeeded"
	}
	if _, e = tx.ExecContext(ctx, "UPDATE event_log_queries SET status=?,result_json=?,finished_at=? WHERE id=?", status, string(data), now.Unix(), q.ID); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, "device:"+id, "event_query_completed", id+":"+q.ID, r.Outcome); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) EventQuery(ctx context.Context, device, id string, now time.Time) (EventQuery, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return EventQuery{}, e
	}
	defer tx.Rollback()
	if e = expireEventQueries(ctx, tx, now); e != nil {
		return EventQuery{}, e
	}
	q, e := scanEventQuery(tx.QueryRowContext(ctx, "SELECT "+eventQueryColumns+" FROM event_log_queries WHERE device_id=? AND id=?", device, id))
	if e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			if e = tx.Commit(); e != nil {
				return q, e
			}
			return q, ErrEventQuery
		}
		return q, e
	}
	return q, tx.Commit()
}
func (s *Store) PruneEventQueries(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = expireEventQueries(ctx, tx, now); e != nil {
		return e
	}
	return tx.Commit()
}
