package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
)

// serviceHealth is the first check adapter. Enumeration is queryable-only:
// absence does not prove failure, and transitions do not prove steady state.
func serviceHealth(c HealthCheck, report protocol.FeatureReport) (string, bool) {
	if c.Kind != "service_running" || report.Status != "ok" || report.Capability.Version != 1 {
		return "unknown", false
	}
	var data protocol.Services
	if json.Unmarshal(report.Data, &data) != nil || !winservices.Valid(data) {
		return "unknown", false
	}
	for _, v := range data.Items {
		if !strings.EqualFold(v.Name, c.Service) {
			continue
		}
		switch v.State {
		case "running":
			return "good", false
		case "stopped":
			return "bad", v.CanStart
		case "paused":
			return "bad", false
		}
	}
	return "unknown", false
}

func captureHealth(ctx context.Context, tx *sql.Tx, id string, report protocol.FeatureReport, now time.Time) error {
	rows, e := tx.QueryContext(ctx, "SELECT "+healthColumns+" FROM health_checks WHERE device_id=? AND enabled=1", id)
	if e != nil {
		return e
	}
	var checks []HealthCheck
	for rows.Next() {
		c, e := scanHealth(rows)
		if e != nil {
			rows.Close()
			return e
		}
		checks = append(checks, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	var online bool
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE(last_contact_at<=? AND last_contact_at>?-(SELECT offline_after FROM alert_runtime WHERE id=1),0) FROM devices WHERE id=?`, now.Unix(), now.Unix(), id).Scan(&online); e != nil {
		return e
	}
	for _, c := range checks {
		condition, _ := serviceHealth(c, report)
		if !online {
			condition = "unknown"
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO health_samples(check_id,revision,condition,received_at) VALUES(?,?,?,?)", c.ID, c.Revision, condition, now.Unix()); e != nil {
			return e
		}
		// Recheck at telemetry receipt as well as dispatch: an intervening good
		// or unknown report cancels queued work even before the next sweep.
		if condition != "bad" {
			if e = cancelHealthActions(ctx, tx, c.ID, now); e != nil {
				return e
			}
		}
	}
	r, e := tx.ExecContext(ctx, `DELETE FROM health_samples WHERE seq<=(SELECT COALESCE(MAX(seq),0)-10000 FROM health_samples)`)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n > 0 {
		_, e = tx.ExecContext(ctx, "UPDATE alert_runtime SET gap=1,last_gap=? WHERE id=1", now.Unix())
	}
	return e
}

func loadHealthState(ctx context.Context, tx *sql.Tx, id string) (alerting.State, string, error) {
	var state alerting.State
	var raw, attempt string
	e := tx.QueryRowContext(ctx, "SELECT state_json,attempt_id FROM health_states WHERE check_id=?", id).Scan(&raw, &attempt)
	if errors.Is(e, sql.ErrNoRows) {
		return state, "", nil
	}
	if e != nil {
		return state, "", e
	}
	if e = json.Unmarshal([]byte(raw), &state); e != nil {
		return state, "", e
	}
	return state, attempt, nil
}

func healthID() (string, error) {
	var v [16]byte
	_, e := rand.Read(v[:])
	return hex.EncodeToString(v[:]), e
}

func applyHealth(ctx context.Context, tx *sql.Tx, c HealthCheck, o alerting.Observation, now time.Time) error {
	s, attempt, e := loadHealthState(ctx, tx, c.ID)
	if e != nil {
		return e
	}
	next, event := alerting.ApplyHealth(c.Enabled, c.HoldSeconds, c.RecoverySeconds, s, o, now)
	if event == "open" {
		next.Incident, e = healthID()
		if e != nil {
			return e
		}
		attempt = ""
		if _, e = tx.ExecContext(ctx, `INSERT INTO alerts(id,device_id,hostname,kind,severity,threshold,hold_seconds,status,opened_at,last_seen,label) SELECT ?,id,hostname,?,?,0,?,'active',?,?,? FROM devices WHERE id=?`, next.Incident, "check:"+c.ID, c.Severity, c.HoldSeconds, now.Unix(), o.At, c.Name, c.DeviceID); e != nil {
			return e
		}
		if c.Email {
			if e = enqueueAlertMail(ctx, tx, next.Incident, "opened", now); e != nil {
				return e
			}
		}
	} else if event == "resolve" {
		if _, e = tx.ExecContext(ctx, `UPDATE alerts SET status='resolved',finished_at=?,close_reason='recovered' WHERE id=? AND status='active'`, now.Unix(), s.Incident); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE alert_deliveries SET status='cancelled',finished_at=?,reason='recovered_before_delivery' WHERE alert_id=? AND event='opened' AND status='queued'`, now.Unix(), s.Incident); e != nil {
			return e
		}
		var sent int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_deliveries WHERE alert_id=? AND event='opened' AND status='sent'", s.Incident).Scan(&sent); e != nil {
			return e
		}
		if c.Email && sent > 0 {
			if e = enqueueAlertMail(ctx, tx, s.Incident, "resolved", now); e != nil {
				return e
			}
		}
		next.Incident = ""
		attempt = ""
	}
	if next.Incident != "" && next.Condition == "bad" {
		if _, e = tx.ExecContext(ctx, "UPDATE alerts SET last_seen=MAX(last_seen,?) WHERE id=?", o.At, next.Incident); e != nil {
			return e
		}
	}
	if next.Condition != "bad" || next.Incident == "" {
		if e = cancelHealthActions(ctx, tx, c.ID, now); e != nil {
			return e
		}
	}
	if event != "" {
		id := next.Incident
		if id == "" {
			id = s.Incident
		}
		if e = auditDevice(ctx, tx, now, "server", "health_check_"+event, c.DeviceID+":"+c.ID+":"+id, c.Kind); e != nil {
			return e
		}
	}
	raw, _ := json.Marshal(next)
	_, e = tx.ExecContext(ctx, `INSERT INTO health_states(check_id,device_id,state_json,attempt_id) VALUES(?,?,?,?) ON CONFLICT(check_id) DO UPDATE SET state_json=excluded.state_json,attempt_id=excluded.attempt_id`, c.ID, c.DeviceID, string(raw), attempt)
	return e
}

func currentServiceHealth(ctx context.Context, tx *sql.Tx, c HealthCheck, now time.Time, offline int64) (string, bool, error) {
	var data, status string
	var version int
	var at, contact *int64
	e := tx.QueryRowContext(ctx, `SELECT f.snapshot_json,f.last_status,f.capability_version,f.snapshot_at,d.last_contact_at FROM device_services f JOIN devices d ON d.id=f.device_id WHERE d.id=? AND d.revoked_at IS NULL`, c.DeviceID).Scan(&data, &status, &version, &at, &contact)
	if errors.Is(e, sql.ErrNoRows) {
		return "unknown", false, nil
	}
	if e != nil {
		return "unknown", false, e
	}
	if at == nil || contact == nil || *at > now.Unix() || now.Unix()-*at >= 120 || *contact > now.Unix() || now.Unix()-*contact >= offline {
		return "unknown", false, nil
	}
	condition, start := serviceHealth(c, protocol.FeatureReport{Capability: protocol.Capability{Version: version}, Status: status, Data: json.RawMessage(data)})
	return condition, start, nil
}

func evaluateHealth(ctx context.Context, tx *sql.Tx, now time.Time, offline, last int64, gap bool) error {
	if gap || now.Unix() < last || now.Unix()-last > 45 {
		if _, e := tx.ExecContext(ctx, `UPDATE health_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.last_sample',0)`); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "DELETE FROM health_samples"); e != nil {
			return e
		}
	}
	if e := expireActions(ctx, tx, now); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+healthColumns+" FROM health_checks ORDER BY id LIMIT 100")
	if e != nil {
		return e
	}
	checks := map[string]HealthCheck{}
	for rows.Next() {
		c, e := scanHealth(rows)
		if e != nil {
			rows.Close()
			return e
		}
		checks[c.ID] = c
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for id, c := range checks {
		var active int
		if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY enrolled_at DESC,id LIMIT 1000) WHERE id=?`, c.DeviceID).Scan(&active); e != nil {
			return e
		}
		if !c.Enabled || active != 1 {
			if e = closeHealth(ctx, tx, id, "not_monitored", now); e != nil {
				return e
			}
			delete(checks, id)
		}
	}
	rows, e = tx.QueryContext(ctx, "SELECT seq,check_id,revision,condition,received_at FROM health_samples ORDER BY seq LIMIT 2000")
	if e != nil {
		return e
	}
	type sample struct {
		seq, revision, at int64
		id, condition     string
	}
	var samples []sample
	for rows.Next() {
		var v sample
		if e = rows.Scan(&v.seq, &v.id, &v.revision, &v.condition, &v.at); e != nil {
			rows.Close()
			return e
		}
		samples = append(samples, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range samples {
		if c, ok := checks[v.id]; ok && c.Revision == v.revision {
			if e = applyHealth(ctx, tx, c, alerting.Observation{Condition: v.condition, At: v.at}, now); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM health_samples WHERE seq=?", v.seq); e != nil {
			return e
		}
	}
	for _, c := range checks {
		state, _, e := loadHealthState(ctx, tx, c.ID)
		if e != nil {
			return e
		}
		condition, _, e := currentServiceHealth(ctx, tx, c, now, offline)
		if e != nil {
			return e
		}
		if condition == "unknown" || state.LastSample > now.Unix() || now.Unix()-state.LastSample >= 120 {
			if e = applyHealth(ctx, tx, c, alerting.Observation{Condition: "unknown", At: now.Unix()}, now); e != nil {
				return e
			}
		}
		if e = queueHealthResponse(ctx, tx, c, now, offline); e != nil {
			return e
		}
	}
	// Keep the latest guard's evidence, live incidents and pending actions even
	// when pruning completed history. Capacity exhaustion fails closed.
	_, e = tx.ExecContext(ctx, `DELETE FROM health_attempts WHERE status NOT IN ('queued','dispatched') AND action_id NOT IN (SELECT action_id FROM health_guards) AND incident_id NOT IN (SELECT id FROM alerts WHERE status='active') AND action_id IN (SELECT action_id FROM health_attempts ORDER BY created_at DESC,action_id LIMIT -1 OFFSET 2000)`)
	return e
}

func queueHealthResponse(ctx context.Context, tx *sql.Tx, c HealthCheck, now time.Time, offline int64) error {
	if !c.Enabled || !c.Response {
		return nil
	}
	state, attempt, e := loadHealthState(ctx, tx, c.ID)
	if e != nil {
		return e
	}
	if state.Incident == "" || attempt != "" || state.Condition != "bad" || state.Samples < 2 || state.LastSample-state.Since < c.HoldSeconds || state.LastSample > now.Unix() || now.Unix()-state.LastSample >= 120 {
		return nil
	}
	condition, start, e := currentServiceHealth(ctx, tx, c, now, offline)
	if e != nil {
		return e
	}
	if condition != "bad" || !start {
		return nil
	}
	var blocked bool
	var last int64
	e = tx.QueryRowContext(ctx, "SELECT blocked,last_attempt FROM health_guards WHERE device_id=? AND service_key=?", c.DeviceID, healthServiceKey(c.Service)).Scan(&blocked, &last)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if blocked || (last != 0 && (now.Unix() < last || now.Unix()-last < c.CooldownSeconds)) {
		return nil
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM health_attempts").Scan(&count); e != nil {
		return e
	}
	if count >= 10000 {
		return nil
	}
	id, e := healthID()
	if e != nil {
		return e
	}
	a := ServiceAction{ServiceAction: protocol.ServiceAction{ID: id, Service: c.Service, Action: "start"}, DeviceID: c.DeviceID, Actor: "health:" + c.ID}
	if e = queueServiceAction(ctx, tx, a, now, time.Duration(offline)*time.Second); errors.Is(e, ErrAction) {
		return nil
	} else if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO health_attempts(action_id,check_id,incident_id,revision,device_id,check_name,service_name,service_key,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, c.ID, state.Incident, c.Revision, c.DeviceID, c.Name, c.Service, healthServiceKey(c.Service), now.Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO health_guards(device_id,service_key,last_attempt,blocked,action_id) VALUES(?,?,?,1,?) ON CONFLICT(device_id,service_key) DO UPDATE SET last_attempt=excluded.last_attempt,blocked=1,action_id=excluded.action_id`, c.DeviceID, healthServiceKey(c.Service), now.Unix(), id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE health_states SET attempt_id=? WHERE check_id=?", id, c.ID); e != nil {
		return e
	}
	return auditDevice(ctx, tx, now, "server", "health_response_queued", c.DeviceID+":"+c.ID+":"+id, "start_once")
}

func healthDispatchAllowed(ctx context.Context, tx *sql.Tx, a ServiceAction, now time.Time) (bool, error) {
	var check, incident string
	var revision int64
	e := tx.QueryRowContext(ctx, "SELECT check_id,incident_id,revision FROM health_attempts WHERE action_id=?", a.ID).Scan(&check, &incident, &revision)
	if errors.Is(e, sql.ErrNoRows) {
		return !strings.HasPrefix(a.Actor, "health:"), nil
	}
	if e != nil {
		return false, e
	}
	c, e := scanHealth(tx.QueryRowContext(ctx, "SELECT "+healthColumns+" FROM health_checks WHERE id=?", check))
	if e != nil {
		return false, e
	}
	if !c.Enabled || !c.Response || c.Revision != revision || a.Actor != "health:"+check || a.DeviceID != c.DeviceID || a.Service != c.Service || a.Action != "start" {
		return false, nil
	}
	state, attempt, e := loadHealthState(ctx, tx, c.ID)
	if e != nil {
		return false, e
	}
	if state.Incident != incident || attempt != a.ID || state.Condition != "bad" || state.LastSample > now.Unix() || now.Unix()-state.LastSample >= 120 {
		return false, nil
	}
	var offline, sweep int64
	if e = tx.QueryRowContext(ctx, "SELECT offline_after,last_sweep FROM alert_runtime WHERE id=1").Scan(&offline, &sweep); e != nil {
		return false, e
	}
	if sweep > now.Unix() || now.Unix()-sweep >= 45 {
		return false, nil
	}
	var monitored int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY enrolled_at DESC,id LIMIT 1000) WHERE id=?`, c.DeviceID).Scan(&monitored); e != nil {
		return false, e
	}
	if monitored != 1 {
		return false, nil
	}
	condition, start, e := currentServiceHealth(ctx, tx, c, now, offline)
	return condition == "bad" && start, e
}
