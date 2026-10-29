package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"time"
)

var ErrSchedule = errors.New("schedule changed or unavailable; reload and review its settings")

// ScriptSchedule pins both version and arguments. Intervals are elapsed UTC
// seconds from StartAt, not calendar/cron expressions or local wall-clock time.
type ScriptSchedule struct {
	ID        string            `json:"id"`
	DeviceID  string            `json:"device_id"`
	VersionID string            `json:"version_id"`
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments"`
	StartAt   int64             `json:"start_at"`
	Interval  int64             `json:"interval_seconds"`
	NextAt    int64             `json:"next_at"`
	State     string            `json:"state"`
	Revision  int               `json:"revision"`
	Actor     string            `json:"actor"`
	UpdatedAt int64             `json:"updated_at"`
}
type ScriptOccurrence struct {
	DueAt      int64   `json:"due_at"`
	RecordedAt int64   `json:"recorded_at"`
	Revision   int     `json:"revision"`
	Count      int64   `json:"count"`
	Outcome    string  `json:"outcome"`
	RunID      *string `json:"run_id"`
	RunStatus  string  `json:"run_status"`
}

const scheduleColumns = "id,device_id,version_id,name,arguments_json,start_at,interval_seconds,next_at,state,revision,actor,updated_at"

func scanSchedule(row interface{ Scan(...any) error }) (ScriptSchedule, error) {
	var v ScriptSchedule
	var raw string
	e := row.Scan(&v.ID, &v.DeviceID, &v.VersionID, &v.Name, &raw, &v.StartAt, &v.Interval, &v.NextAt, &v.State, &v.Revision, &v.Actor, &v.UpdatedAt)
	if e == nil && scripting.Decode([]byte(raw), &v.Arguments) != nil {
		e = ErrSchedule
	}
	return v, e
}
func (s *Store) ScriptSchedule(ctx context.Context, device, id string) (ScriptSchedule, error) {
	return scanSchedule(s.db.QueryRowContext(ctx, "SELECT "+scheduleColumns+" FROM script_schedules WHERE id=? AND device_id=?", id, device))
}
func (s *Store) ScriptSchedules(ctx context.Context, device string) ([]ScriptSchedule, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT "+scheduleColumns+" FROM script_schedules WHERE device_id=? ORDER BY updated_at DESC,id LIMIT 500", device)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	vs := []ScriptSchedule{}
	for rows.Next() {
		v, e := scanSchedule(rows)
		if errors.Is(e, ErrSchedule) && v.ID != "" {
			// Damaged arguments: listed (paused by the evaluator) so it can be
			// cancelled; it cannot be resumed.
			v.Arguments, e = map[string]string{}, nil
		}
		if e != nil {
			return nil, e
		}
		vs = append(vs, v)
	}
	return vs, rows.Err()
}

// FleetSchedule is a schedule with display context for fleet-wide lists.
type FleetSchedule struct {
	ScriptSchedule
	Hostname      string `json:"hostname"`
	ScriptName    string `json:"script_name"`
	ScriptVersion int    `json:"script_version"`
	RunAs         string `json:"run_as"`
}

// FleetScriptSchedules lists schedules across devices, live ones first.
func (s *Store) FleetScriptSchedules(ctx context.Context) ([]FleetSchedule, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT id FROM script_schedules ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'paused' THEN 1 ELSE 2 END,next_at,id LIMIT 500")
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []FleetSchedule{}
	for _, id := range ids {
		v, e := scanSchedule(s.db.QueryRowContext(ctx, "SELECT "+scheduleColumns+" FROM script_schedules WHERE id=?", id))
		if errors.Is(e, ErrSchedule) && v.ID != "" {
			v.Arguments, e = map[string]string{}, nil // damaged: listed so it can be cancelled
		}
		if e != nil {
			return nil, e
		}
		f := FleetSchedule{ScriptSchedule: v}
		_ = s.db.QueryRowContext(ctx, "SELECT hostname FROM devices WHERE id=?", v.DeviceID).Scan(&f.Hostname)
		if version, e := s.ScriptVersion(ctx, v.VersionID); e == nil {
			f.ScriptName, f.ScriptVersion, f.RunAs = version.Definition.Name, version.Number, version.Definition.RunAs
		}
		out = append(out, f)
	}
	return out, nil
}

func (s *Store) ScriptOccurrences(ctx context.Context, device, id string, now time.Time) ([]ScriptOccurrence, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT o.due_at,o.recorded_at,o.revision,o.missed_count,o.outcome,o.run_id,COALESCE(r.status,'') FROM script_schedule_occurrences o JOIN script_schedules s ON s.id=o.schedule_id LEFT JOIN script_runs r ON r.id=o.run_id WHERE s.id=? AND s.device_id=? AND o.recorded_at>=? ORDER BY o.recorded_at DESC,o.id DESC LIMIT 50`, id, device, now.Add(-30*24*time.Hour).Unix())
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	vs := []ScriptOccurrence{}
	for rows.Next() {
		var v ScriptOccurrence
		if e = rows.Scan(&v.DueAt, &v.RecordedAt, &v.Revision, &v.Count, &v.Outcome, &v.RunID, &v.RunStatus); e != nil {
			return nil, e
		}
		vs = append(vs, v)
	}
	return vs, rows.Err()
}

// Save creates or revises a schedule only after a review bound to all fields.
// Existing schedule revisions provide optimistic concurrency for stale forms.
func (s *Store) SaveScriptSchedule(ctx context.Context, v ScriptSchedule, now time.Time) error {
	if !protocol.ValidID(v.ID) || !protocol.ValidID(v.DeviceID) || !protocol.ValidID(v.VersionID) || !scripting.Text(v.Name, 100, false) || v.Name == "" || !scripting.Text(v.Actor, 128, false) || v.Actor == "" || v.StartAt < now.Unix()+5 || v.StartAt > now.Add(366*24*time.Hour).Unix() || v.Interval != 0 && (v.Interval < 300 || v.Interval > 2592000) || v.Revision < 0 || v.Revision > 1000000 {
		return ErrSchedule
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	version, e := scanScriptVersion(tx.QueryRowContext(ctx, "SELECT "+scriptVersionColumns+" FROM script_versions WHERE id=?", v.VersionID))
	if e != nil || !scripting.ArgumentsValid(version.Definition, v.Arguments) {
		return ErrSchedule
	}
	var device string
	if e = tx.QueryRowContext(ctx, "SELECT id FROM devices WHERE id=? AND revoked_at IS NULL", v.DeviceID).Scan(&device); e != nil {
		return ErrSchedule
	}
	old, e := scanSchedule(tx.QueryRowContext(ctx, "SELECT "+scheduleColumns+" FROM script_schedules WHERE id=?", v.ID))
	raw, _ := json.Marshal(v.Arguments)
	if errors.Is(e, sql.ErrNoRows) {
		if v.Revision != 0 {
			return ErrSchedule
		}
		var total, live int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(state IN('active','paused')),0) FROM script_schedules").Scan(&total, &live); e != nil {
			return e
		}
		if total >= 500 || live >= 100 {
			return ErrSchedule
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO script_schedules("+scheduleColumns+") VALUES(?,?,?,?,?,?,?,?, 'active',1,?,?)", v.ID, v.DeviceID, v.VersionID, v.Name, string(raw), v.StartAt, v.Interval, v.StartAt, v.Actor, now.Unix())
	} else if e == nil {
		// An exact duplicate confirmed create/edit is harmless. State changes and
		// scheduler progress must not be undone by an old form retry.
		same := old.DeviceID == v.DeviceID && old.VersionID == v.VersionID && old.Name == v.Name && old.StartAt == v.StartAt && old.Interval == v.Interval && scripting.ArgumentsHash(old.Arguments) == scripting.ArgumentsHash(v.Arguments) && old.Actor == v.Actor
		if old.Revision == v.Revision+1 && same {
			return tx.Commit()
		}
		if old.DeviceID != v.DeviceID || old.Revision != v.Revision || old.State == "cancelled" || old.State == "completed" {
			return ErrSchedule
		}
		if e = cancelScheduledQueue(ctx, tx, v.ID, now, "schedule_edited"); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE script_schedules SET version_id=?,name=?,arguments_json=?,start_at=?,interval_seconds=?,next_at=?,revision=revision+1,actor=?,updated_at=? WHERE id=?`, v.VersionID, v.Name, string(raw), v.StartAt, v.Interval, v.StartAt, v.Actor, now.Unix(), v.ID)
	} else {
		return e
	}
	if e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, v.Actor, "script_schedule_saved", v.DeviceID+":"+v.ID+":"+v.VersionID, "reviewed"); e != nil {
		return e
	}
	return tx.Commit()
}

func cancelScheduledQueue(ctx context.Context, tx *sql.Tx, id string, now time.Time, reason string) error {
	// Already dispatched work remains visible and cancellable on its run page.
	rows, e := tx.QueryContext(ctx, `SELECT r.id,r.device_id FROM script_runs r JOIN script_schedule_occurrences o ON o.run_id=r.id WHERE o.schedule_id=? AND r.status='queued'`, id)
	if e != nil {
		return e
	}
	type item struct{ id, device string }
	items := []item{}
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.id, &v.device); e != nil {
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
		raw, _ := json.Marshal(scripting.Failure(v.id, "cancelled"))
		if _, e = tx.ExecContext(ctx, "UPDATE script_runs SET status='cancelled',finished_at=?,cancel_requested=1,result_json=? WHERE id=?", now.Unix(), string(raw), v.id); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, "server", "script_run_cancelled", v.device+":"+v.id, reason); e != nil {
			return e
		}
	}
	return nil
}

func (s *Store) ChangeScriptSchedule(ctx context.Context, device, id, actor, action string, revision int, now time.Time) error {
	if !scripting.Text(actor, 128, false) || actor == "" {
		return ErrSchedule
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	v, e := scanSchedule(tx.QueryRowContext(ctx, "SELECT "+scheduleColumns+" FROM script_schedules WHERE id=? AND device_id=?", id, device))
	if errors.Is(e, ErrSchedule) && v.ID != "" && action == "cancel" {
		e = nil // damaged arguments: it can only be cancelled
	}
	if e != nil || v.Revision != revision {
		return ErrSchedule
	}
	next := v.NextAt
	switch action {
	case "pause":
		if v.State != "active" {
			return ErrSchedule
		}
		v.State = "paused"
	case "resume":
		if v.State != "paused" {
			return ErrSchedule
		}
		var active int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NULL", device).Scan(&active); e != nil {
			return e
		}
		if active != 1 {
			return ErrSchedule
		}
		if next <= now.Unix() {
			if e = recordOccurrence(ctx, tx, v, now, "skipped_paused", nil); e != nil {
				return e
			}
			next, _ = advanceSchedule(v, now)
		}
		v.State = "active"
		if next == 0 {
			v.State = "completed"
		}
	case "cancel":
		if v.State != "active" && v.State != "paused" {
			return ErrSchedule
		}
		v.State = "cancelled"
	default:
		return ErrSchedule
	}
	if e = cancelScheduledQueue(ctx, tx, id, now, "schedule_"+action); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE script_schedules SET state=?,next_at=?,revision=revision+1,updated_at=? WHERE id=?", v.State, next, now.Unix(), id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "script_schedule_"+action, device+":"+id, v.State); e != nil {
		return e
	}
	return tx.Commit()
}

// Advance directly past now; outages produce one aggregate skipped record,
// never a loop of catch-up jobs. Bounds on the clock and interval prevent overflow.
func advanceSchedule(v ScriptSchedule, now time.Time) (next, count int64) {
	if v.Interval == 0 {
		return 0, 1
	}
	count = (now.Unix()-v.NextAt)/v.Interval + 1
	return v.NextAt + count*v.Interval, count
}
func recordOccurrence(ctx context.Context, tx *sql.Tx, v ScriptSchedule, now time.Time, outcome string, run *string) error {
	_, count := advanceSchedule(v, now)
	_, e := tx.ExecContext(ctx, "INSERT INTO script_schedule_occurrences(schedule_id,revision,due_at,recorded_at,missed_count,outcome,run_id) VALUES(?,?,?,?,?,?,?)", v.ID, v.Revision, v.NextAt, now.Unix(), count, outcome, run)
	if e != nil {
		return e
	}
	return auditDevice(ctx, tx, now, "scheduler", "script_schedule_occurrence", v.DeviceID+":"+v.ID, outcome)
}

// Initialize skips everything due at server startup and cancels undelivered
// scheduled jobs. It must finish before listeners and the evaluator start.
func (s *Store) InitializeScriptSchedules(ctx context.Context, now time.Time) error {
	return s.evaluateScriptSchedules(ctx, now, 120*time.Second, true)
}
func (s *Store) EvaluateScriptSchedules(ctx context.Context, now time.Time, offline time.Duration) error {
	return s.evaluateScriptSchedules(ctx, now, offline, false)
}
func (s *Store) evaluateScriptSchedules(ctx context.Context, now time.Time, offline time.Duration, startup bool) error {
	// A grossly invalid system clock must not manufacture future/past jobs.
	if now.Year() < 2020 || now.Year() > 2200 {
		return ErrSchedule
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+scheduleColumns+" FROM script_schedules WHERE state='active' OR ? ORDER BY next_at,id LIMIT 500", startup)
	if e != nil {
		return e
	}
	vs, damaged := []ScriptSchedule{}, []ScriptSchedule{}
	for rows.Next() {
		v, e := scanSchedule(rows)
		if errors.Is(e, ErrSchedule) && v.ID != "" {
			damaged = append(damaged, v)
			continue
		}
		if e != nil {
			rows.Close()
			return e
		}
		vs = append(vs, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	// A schedule whose stored arguments cannot be read is paused (once), so
	// it neither runs with wrong arguments nor stops the other schedules.
	for _, v := range damaged {
		if startup {
			if e = cancelScheduledQueue(ctx, tx, v.ID, now, "server_restart"); e != nil {
				return e
			}
		}
		if v.State != "active" {
			continue
		}
		if _, e = tx.ExecContext(ctx, "UPDATE script_schedules SET state='paused',revision=revision+1,updated_at=? WHERE id=?", now.Unix(), v.ID); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, "scheduler", "script_schedule_damaged", v.DeviceID+":"+v.ID, "paused"); e != nil {
			return e
		}
	}
	for _, v := range vs {
		if startup {
			if e = cancelScheduledQueue(ctx, tx, v.ID, now, "server_restart"); e != nil {
				return e
			}
		}
		if v.State != "active" || v.NextAt > now.Unix() {
			continue
		}
		outcome := "skipped_missed"
		var runID *string
		if startup {
			outcome = "skipped_restart"
		} else if now.Unix()-v.NextAt <= 20 {
			var b [16]byte
			if _, e = rand.Read(b[:]); e != nil {
				return e
			}
			id := hex.EncodeToString(b[:])
			r := ScriptRun{ScriptJob: protocol.ScriptJob{ID: id, Version: protocol.ScriptVersion{ID: v.VersionID}, Arguments: v.Arguments}, DeviceID: v.DeviceID, Actor: "schedule:" + v.ID}
			e = queueScriptRun(ctx, tx, r, now, offline)
			if errors.Is(e, ErrScript) {
				outcome = "skipped_unavailable"
			} else if e != nil {
				return e
			} else {
				outcome = "queued"
				runID = &id
				// A device must poll within this occurrence's short delivery window.
				if _, e = tx.ExecContext(ctx, "UPDATE script_runs SET expires_at=? WHERE id=?", v.NextAt+30, id); e != nil {
					return e
				}
			}
		}
		if e = recordOccurrence(ctx, tx, v, now, outcome, runID); e != nil {
			return e
		}
		next, _ := advanceSchedule(v, now)
		state := "active"
		if next == 0 {
			state = "completed"
		}
		if _, e = tx.ExecContext(ctx, "UPDATE script_schedules SET next_at=?,state=?,updated_at=? WHERE id=?", next, state, now.Unix(), v.ID); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM script_schedule_occurrences WHERE recorded_at<? OR id IN(SELECT id FROM script_schedule_occurrences ORDER BY id DESC LIMIT -1 OFFSET 2000)`, now.Add(-30*24*time.Hour).Unix()); e != nil {
		return e
	}
	// Finished schedules are kept 30 days, like their occurrences, so they
	// do not use up the schedule limit for good.
	if _, e = tx.ExecContext(ctx, `DELETE FROM script_schedules WHERE state IN('completed','cancelled') AND updated_at<? AND NOT EXISTS(SELECT 1 FROM script_schedule_occurrences o WHERE o.schedule_id=script_schedules.id)`, now.Add(-30*24*time.Hour).Unix()); e != nil {
		return e
	}
	return tx.Commit()
}
