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

func captureHealth(ctx context.Context, tx *sql.Tx, id string, report protocol.FeatureReport, snapshotAt *int64, now time.Time) error {
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
		condition, start := serviceHealth(c, report)
		if _, e = tx.ExecContext(ctx, `INSERT INTO health_current(check_id,revision,condition,can_start,snapshot_at) VALUES(?,?,?,?,?) ON CONFLICT(check_id) DO UPDATE SET revision=excluded.revision,condition=excluded.condition,can_start=excluded.can_start,snapshot_at=excluded.snapshot_at`, c.ID, c.Revision, condition, start, snapshotAt); e != nil {
			return e
		}
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

// sweepHealth holds, for one sweep, the health states and the latest
// service results of the checks: read in two queries rather than several
// per check, so the sweep's write transaction stays short.
type sweepHealth struct {
	states  map[string]healthState
	current map[string]serviceResult
	// queued lists the checks with a queued response action, the only ones
	// with an action to cancel.
	queued map[string]bool
	stmts  map[string]*sql.Stmt
}

// exec runs a statement of the sweep, prepared once per sweep.
func (h *sweepHealth) exec(ctx context.Context, tx *sql.Tx, q string, args ...any) error {
	stmt, ok := h.stmts[q]
	if !ok {
		var e error
		if stmt, e = tx.PrepareContext(ctx, q); e != nil {
			return e
		}
		h.stmts[q] = stmt
	}
	_, e := stmt.ExecContext(ctx, args...)
	return e
}

func (h *sweepHealth) close() {
	for _, stmt := range h.stmts {
		stmt.Close()
	}
}

type healthState struct {
	state   alerting.State
	attempt string
}

// serviceResult is a check's result from its device's latest services
// report, with that snapshot's time and the device's last contact.
type serviceResult struct {
	revision    int64
	condition   string
	start       bool
	at, contact *int64
}

func loadSweepHealth(ctx context.Context, tx *sql.Tx) (*sweepHealth, error) {
	h := &sweepHealth{states: map[string]healthState{}, current: map[string]serviceResult{}, queued: map[string]bool{}, stmts: map[string]*sql.Stmt{}}
	rows, e := tx.QueryContext(ctx, "SELECT check_id,state_json,attempt_id,device_id FROM health_states")
	if e != nil {
		return nil, e
	}
	damaged := map[string]string{}
	for rows.Next() {
		var id, raw, device string
		var v healthState
		if e = rows.Scan(&id, &raw, &v.attempt, &device); e != nil {
			rows.Close()
			return nil, e
		}
		if json.Unmarshal([]byte(raw), &v.state) != nil {
			damaged[id] = device
			continue
		}
		h.states[id] = v
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for id, device := range damaged {
		state, e := damagedState(ctx, tx, device, "check:"+id)
		if e != nil {
			return nil, e
		}
		h.states[id] = healthState{state: state}
	}
	rows, e = tx.QueryContext(ctx, `SELECT h.check_id,h.revision,h.condition,h.can_start,h.snapshot_at,d.last_contact_at FROM health_current h JOIN health_checks c ON c.id=h.check_id JOIN devices d ON d.id=c.device_id AND d.revoked_at IS NULL`)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var id string
		var r serviceResult
		if e = rows.Scan(&id, &r.revision, &r.condition, &r.start, &r.at, &r.contact); e != nil {
			rows.Close()
			return nil, e
		}
		h.current[id] = r
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	rows, e = tx.QueryContext(ctx, `SELECT DISTINCT h.check_id FROM health_attempts h JOIN service_actions a ON a.id=h.action_id WHERE a.status='queued'`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		h.queued[id] = true
	}
	return h, rows.Err()
}

// loadHealthState reads a check's state, from the sweep's states when h is
// set.
func loadHealthState(ctx context.Context, tx *sql.Tx, h *sweepHealth, id string) (alerting.State, string, error) {
	if h != nil {
		v := h.states[id]
		return v.state, v.attempt, nil
	}
	var state alerting.State
	var raw, attempt, device string
	e := tx.QueryRowContext(ctx, "SELECT state_json,attempt_id,device_id FROM health_states WHERE check_id=?", id).Scan(&raw, &attempt, &device)
	if errors.Is(e, sql.ErrNoRows) {
		return state, "", nil
	}
	if e != nil {
		return state, "", e
	}
	if json.Unmarshal([]byte(raw), &state) != nil {
		state, e = damagedState(ctx, tx, device, "check:"+id)
		return state, "", e
	}
	return state, attempt, nil
}

func healthID() (string, error) {
	var v [16]byte
	_, e := rand.Read(v[:])
	return hex.EncodeToString(v[:]), e
}

func applyHealth(ctx context.Context, tx *sql.Tx, h *sweepHealth, c HealthCheck, o alerting.Observation, now time.Time) error {
	s, attempt, e := loadHealthState(ctx, tx, h, c.ID)
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
	if (next.Condition != "bad" || next.Incident == "") && (h == nil || h.queued[c.ID]) {
		if e = cancelHealthActions(ctx, tx, c.ID, now); e != nil {
			return e
		}
		if h != nil {
			delete(h.queued, c.ID)
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
	const save = `INSERT INTO health_states(check_id,device_id,state_json,attempt_id) VALUES(?,?,?,?) ON CONFLICT(check_id) DO UPDATE SET state_json=excluded.state_json,attempt_id=excluded.attempt_id`
	if h == nil {
		_, e = tx.ExecContext(ctx, save, c.ID, c.DeviceID, string(raw), attempt)
		return e
	}
	if e = h.exec(ctx, tx, save, c.ID, c.DeviceID, string(raw), attempt); e != nil {
		return e
	}
	h.states[c.ID] = healthState{next, attempt}
	return nil
}

// serviceFresh reports whether a services snapshot is recent enough, from a
// device still in contact, to judge a check by.
func serviceFresh(at, contact *int64, now time.Time, offline int64) bool {
	return at != nil && contact != nil && *at <= now.Unix() && now.Unix()-*at < 120 && *contact <= now.Unix() && now.Unix()-*contact < offline
}

// currentServiceHealth judges a check by its device's latest services
// snapshot: in a sweep from the result stored with that report, otherwise
// (or for a check changed since) from the snapshot itself.
func currentServiceHealth(ctx context.Context, tx *sql.Tx, h *sweepHealth, c HealthCheck, now time.Time, offline int64) (string, bool, error) {
	if h != nil {
		if r, ok := h.current[c.ID]; ok && r.revision == c.Revision {
			if !serviceFresh(r.at, r.contact, now, offline) {
				return "unknown", false, nil
			}
			return r.condition, r.start, nil
		}
	}
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
	if !serviceFresh(at, contact, now, offline) {
		return "unknown", false, nil
	}
	condition, start := serviceHealth(c, protocol.FeatureReport{Capability: protocol.Capability{Version: version}, Status: status, Data: json.RawMessage(data)})
	return condition, start, nil
}

func evaluateHealth(ctx context.Context, tx *sql.Tx, now time.Time, offline, last int64, gap bool) error {
	if gap || now.Unix() < last || now.Unix()-last > 45 {
		if _, e := tx.ExecContext(ctx, `UPDATE health_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.last_sample',0) WHERE json_valid(state_json)`); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "DELETE FROM health_samples"); e != nil {
			return e
		}
	}
	if e := expireActions(ctx, tx, now); e != nil {
		return e
	}
	// Checks no longer monitored (disabled, or on a revoked or unlisted
	// device) lose their state and open alert once.
	rows, e := tx.QueryContext(ctx, `SELECT id FROM health_checks WHERE (enabled=0 OR device_id NOT IN (`+monitoredDevices+`)) AND (id IN (SELECT check_id FROM health_states) OR id IN (SELECT check_id FROM health_samples) OR id IN (SELECT h.check_id FROM health_attempts h JOIN service_actions a ON a.id=h.action_id WHERE a.status='queued') OR EXISTS(SELECT 1 FROM alerts WHERE kind='check:'||health_checks.id AND status='active'))`)
	if e != nil {
		return e
	}
	var unmonitored []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		unmonitored = append(unmonitored, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range unmonitored {
		if e = closeHealth(ctx, tx, id, "not_monitored", now); e != nil {
			return e
		}
	}
	// A revoked device never reports again: 30 days after the revocation its
	// checks go, with their response history (checked once an hour).
	revokedLong := now.Add(-30 * 24 * time.Hour).Unix()
	for _, q := range []string{
		"DELETE FROM health_attempts WHERE check_id IN (SELECT c.id FROM health_checks c JOIN devices d ON d.id=c.device_id WHERE d.revoked_at<?)",
		"DELETE FROM health_checks WHERE device_id IN (SELECT id FROM devices WHERE revoked_at<?) AND id NOT IN (SELECT check_id FROM health_states) AND id NOT IN (SELECT check_id FROM health_samples)",
	} {
		if now.Unix()/3600 == last/3600 {
			break
		}
		if _, e = tx.ExecContext(ctx, q, revokedLong); e != nil {
			return e
		}
	}
	rows, e = tx.QueryContext(ctx, "SELECT "+healthColumns+" FROM health_checks WHERE enabled=1 AND device_id IN ("+monitoredDevices+") ORDER BY id LIMIT ?", maxHealthChecks)
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
	h, e := loadSweepHealth(ctx, tx)
	if e != nil {
		return e
	}
	defer h.close()
	rows, e = tx.QueryContext(ctx, "SELECT seq,check_id,revision,condition,received_at FROM health_samples ORDER BY seq LIMIT 10000")
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
			if e = applyHealth(ctx, tx, h, c, alerting.Observation{Condition: v.condition, At: v.at}, now); e != nil {
				return e
			}
		}
	}
	// As with alert samples: read in order, removed only here.
	if len(samples) > 0 {
		if _, e = tx.ExecContext(ctx, "DELETE FROM health_samples WHERE seq<=?", samples[len(samples)-1].seq); e != nil {
			return e
		}
	}
	for _, c := range checks {
		state, _, e := loadHealthState(ctx, tx, h, c.ID)
		if e != nil {
			return e
		}
		condition, _, e := currentServiceHealth(ctx, tx, h, c, now, offline)
		if e != nil {
			return e
		}
		if condition == "unknown" || state.LastSample > now.Unix() || now.Unix()-state.LastSample >= 120 {
			if e = applyHealth(ctx, tx, h, c, alerting.Observation{Condition: "unknown", At: now.Unix()}, now); e != nil {
				return e
			}
		}
		if e = queueHealthResponse(ctx, tx, h, c, now, offline); e != nil {
			return e
		}
	}
	// Keep the latest guard's evidence, live incidents and pending actions even
	// when pruning completed history. Capacity exhaustion fails closed.
	_, e = tx.ExecContext(ctx, `DELETE FROM health_attempts WHERE status NOT IN ('queued','dispatched') AND action_id NOT IN (SELECT action_id FROM health_guards) AND incident_id NOT IN (SELECT id FROM alerts WHERE status='active') AND action_id IN (SELECT action_id FROM health_attempts ORDER BY created_at DESC,action_id LIMIT -1 OFFSET 2000)`)
	return e
}

func queueHealthResponse(ctx context.Context, tx *sql.Tx, h *sweepHealth, c HealthCheck, now time.Time, offline int64) error {
	if !c.Enabled || !c.Response {
		return nil
	}
	state, attempt, e := loadHealthState(ctx, tx, h, c.ID)
	if e != nil {
		return e
	}
	if state.Incident == "" || attempt != "" || state.Condition != "bad" || state.Samples < 2 || state.LastSample-state.Since < c.HoldSeconds || state.LastSample > now.Unix() || now.Unix()-state.LastSample >= 120 {
		return nil
	}
	condition, start, e := currentServiceHealth(ctx, tx, h, c, now, offline)
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
	if h != nil {
		if v, ok := h.states[c.ID]; ok {
			v.attempt = id
			h.states[c.ID] = v
		}
		h.queued[c.ID] = true
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
	state, attempt, e := loadHealthState(ctx, tx, nil, c.ID)
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
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY enrolled_at DESC,id`+fleetLimit+`) WHERE id=?`, c.DeviceID).Scan(&monitored); e != nil {
		return false, e
	}
	if monitored != 1 {
		return false, nil
	}
	condition, start, e := currentServiceHealth(ctx, tx, nil, c, now, offline)
	return condition == "bad" && start, e
}
