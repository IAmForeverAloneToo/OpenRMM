package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/diskspace"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/memory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"time"
)

var ErrAlert = errors.New("alert or settings unavailable; reload and try again")

// Capture is part of the authorized telemetry transaction. The short queue
// preserves intervening healthy readings even between evaluator sweeps.
func captureAlert(ctx context.Context, tx *sql.Tx, id, kind, status string, data []byte, now time.Time) error {
	if len(data) > 1024 {
		status = "failed"
		data = nil
	}
	if _, e := tx.ExecContext(ctx, `INSERT INTO alert_samples(device_id,kind,status,data,received_at,contact_at) SELECT id,?,?,?,?,last_contact_at FROM devices WHERE id=?`, kind, status, string(data), now.Unix(), id); e != nil {
		return e
	}
	r, e := tx.ExecContext(ctx, `DELETE FROM alert_samples WHERE seq<=(SELECT COALESCE(MAX(seq),0)-10000 FROM alert_samples)`)
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

type Alert struct {
	Label          string `json:"label"`
	ID             string `json:"id"`
	DeviceID       string `json:"device_id"`
	Hostname       string `json:"hostname"`
	Kind           string `json:"kind"`
	Severity       string `json:"severity"`
	Threshold      int    `json:"threshold"`
	HoldSeconds    int64  `json:"hold_seconds"`
	Status         string `json:"status"`
	OpenedAt       int64  `json:"opened_at"`
	LastSeen       int64  `json:"last_seen"`
	FinishedAt     *int64 `json:"finished_at"`
	AcknowledgedAt *int64 `json:"acknowledged_at"`
	AcknowledgedBy string `json:"acknowledged_by"`
	CloseReason    string `json:"close_reason"`
	Condition      string `json:"condition"`
}
type AlertDeviceState struct {
	Label    string `json:"label"`
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Kind     string `json:"kind"`
	alerting.State
}
type AlertRuntime struct {
	MailPaused       bool   `json:"mail_paused"`
	OfflineAfter     int64  `json:"offline_after_seconds"`
	LastSweep        int64  `json:"last_sweep"`
	LastGap          int64  `json:"last_gap"`
	MailConfig       string `json:"-"`
	MailConfigured   bool   `json:"mail_configured"`
	PendingSamples   int    `json:"pending_samples"`
	MonitoredDevices int    `json:"active_devices"`
	Limited          bool   `json:"capacity_limited"`
}

const ruleColumns = "kind,enabled,threshold,hold_seconds,recovery_seconds,severity,email,revision"

func scanRule(row interface{ Scan(...any) error }) (alerting.Rule, error) {
	var r alerting.Rule
	e := row.Scan(&r.Kind, &r.Enabled, &r.Threshold, &r.HoldSeconds, &r.RecoverySeconds, &r.Severity, &r.Email, &r.Revision)
	return r, e
}
func rulesTx(ctx context.Context, tx *sql.Tx) ([]alerting.Rule, error) {
	rows, e := tx.QueryContext(ctx, "SELECT "+ruleColumns+" FROM alert_rules ORDER BY kind")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var rs []alerting.Rule
	for rows.Next() {
		r, e := scanRule(rows)
		if e != nil || !alerting.RuleValid(r) {
			return nil, ErrAlert
		}
		rs = append(rs, r)
	}
	return rs, rows.Err()
}
func (s *Store) AlertRules(ctx context.Context) ([]alerting.Rule, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, e := rulesTx(ctx, tx)
	if e != nil {
		return nil, e
	}
	return r, tx.Commit()
}
func (s *Store) SaveAlertRule(ctx context.Context, r alerting.Rule, actor string, now time.Time) error {
	if !alerting.RuleValid(r) || actor == "" || len(actor) > 128 {
		return ErrAlert
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	old, e := scanRule(tx.QueryRowContext(ctx, "SELECT "+ruleColumns+" FROM alert_rules WHERE kind=?", r.Kind))
	if e != nil {
		return ErrAlert
	}
	compare := r
	compare.Revision = old.Revision
	if compare == old {
		return tx.Commit()
	}
	if old.Revision != r.Revision {
		return ErrAlert
	}
	before, e := organizationTx(ctx, tx, true)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alert_rules SET enabled=?,threshold=?,hold_seconds=?,recovery_seconds=?,severity=?,email=?,revision=revision+1 WHERE kind=?`, r.Enabled, r.Threshold, r.HoldSeconds, r.RecoverySeconds, r.Severity, r.Email, r.Kind); e != nil {
		return e
	}
	after, e := organizationTx(ctx, tx, true)
	if e != nil {
		return e
	}
	for _, impact := range policyImpacts(before, after) {
		for _, kind := range impact.Kinds {
			if e = resetDeviceRule(ctx, tx, impact.ID, kind, "settings_changed", now); e != nil {
				return e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE organization_state SET revision=revision+1 WHERE id=1"); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "alert_rule_changed", r.Kind, "saved"); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) InitializeAlerts(ctx context.Context, offline time.Duration, mailID string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "DELETE FROM alert_samples"); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM health_samples"); e != nil {
		return e
	}
	// Damaged states (not valid JSON) are left for the evaluator to replace;
	// they must not stop the server from starting.
	if _, e = tx.ExecContext(ctx, `UPDATE health_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.last_sample',0) WHERE json_valid(state_json)`); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE service_actions SET status='cancelled',finished_at=? WHERE status='queued' AND id IN (SELECT action_id FROM health_attempts)`, now.Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alert_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.value',NULL) WHERE json_valid(state_json)`); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alert_deliveries SET status=CASE WHEN status='sending' THEN 'unknown' ELSE 'cancelled' END,finished_at=?,reason=CASE WHEN status='sending' THEN 'interrupted' ELSE 'configuration_changed' END WHERE status='sending' OR (status='queued' AND config_id<>?)`, now.Unix(), mailID); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE alert_runtime SET offline_after=?,mail_config=?,last_sweep=?,gap=0 WHERE id=1", int64(offline/time.Second), mailID, now.Unix()); e != nil {
		return e
	}
	return tx.Commit()
}

type alertSample struct {
	seq                        int64
	device, kind, status, data string
	at                         int64
	contact                    *int64
}

func sampleObservation(v alertSample, r alerting.Rule, offline int64) alerting.Observation {
	o := alerting.Observation{Condition: "unknown", At: v.at}
	if v.kind == "offline" {
		if v.contact != nil && *v.contact == v.at {
			o.Condition = "good"
		}
		return o
	}
	if v.status != "ok" || v.contact == nil || *v.contact > v.at || v.at-*v.contact >= offline {
		return o
	}
	value := 0.0
	bad := false
	switch v.kind {
	case "cpu":
		var p protocol.CPU
		if json.Unmarshal([]byte(v.data), &p) != nil || !cpu.Valid(p) {
			return o
		}
		value = p.UsagePercent
		bad = value >= float64(r.Threshold)
	case "memory":
		var p protocol.Memory
		if json.Unmarshal([]byte(v.data), &p) != nil || !memory.Valid(p) {
			return o
		}
		value = 100 * (1 - float64(p.AvailableBytes)/float64(p.TotalBytes))
		bad = p.AvailableBytes*100 <= uint64(100-r.Threshold)*p.TotalBytes
	case "disk_space":
		var p protocol.DiskSpace
		if json.Unmarshal([]byte(v.data), &p) != nil || !diskspace.Valid(p) {
			return o
		}
		value = 100 * float64(p.AvailableBytes) / float64(p.TotalBytes)
		bad = p.AvailableBytes*100 < uint64(r.Threshold)*p.TotalBytes
	default:
		return o
	}
	o.Value = &value
	o.Condition = "good"
	if bad {
		o.Condition = "bad"
	}
	return o
}
func loadAlertState(ctx context.Context, tx *sql.Tx, id, kind string) (alerting.State, error) {
	if strings.HasPrefix(kind, "check:") {
		state, _, e := loadHealthState(ctx, tx, strings.TrimPrefix(kind, "check:"))
		return state, e
	}
	var raw string
	var s alerting.State
	e := tx.QueryRowContext(ctx, "SELECT state_json FROM alert_states WHERE device_id=? AND kind=?", id, kind).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if json.Unmarshal([]byte(raw), &s) != nil {
		return damagedState(ctx, tx, id, kind)
	}
	return s, nil
}

// damagedState replaces a state that cannot be read: qualification starts
// over (the next save writes a valid state), and an open alert stays linked
// so it can still resolve. One damaged row must not stop evaluation.
func damagedState(ctx context.Context, tx *sql.Tx, device, kind string) (alerting.State, error) {
	s := alerting.State{Condition: "unknown"}
	e := tx.QueryRowContext(ctx, "SELECT id FROM alerts WHERE device_id=? AND kind=? AND status='active' ORDER BY opened_at DESC LIMIT 1", device, kind).Scan(&s.Incident)
	if errors.Is(e, sql.ErrNoRows) {
		e = nil
	}
	return s, e
}
func enqueueAlertMail(ctx context.Context, tx *sql.Tx, id, event string, now time.Time) error {
	_, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO alert_deliveries(alert_id,event,config_id,status,created_at,next_attempt) SELECT ?,?,mail_config,'queued',?,? FROM alert_runtime WHERE id=1 AND mail_config<>'' AND mail_paused=0`, id, event, now.Unix(), now.Unix())
	return e
}
func applyAlert(ctx context.Context, tx *sql.Tx, d Device, r alerting.Rule, o alerting.Observation, now time.Time) error {
	s, e := loadAlertState(ctx, tx, d.ID, r.Kind)
	if e != nil {
		return e
	}
	next, event := alerting.Apply(r, s, o, now)
	if event == "open" {
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return e
		}
		next.Incident = hex.EncodeToString(nonce[:])
		if _, e = tx.ExecContext(ctx, `INSERT INTO alerts(id,device_id,hostname,kind,severity,threshold,hold_seconds,status,opened_at,last_seen) VALUES(?,?,?,?,?,?,?,'active',?,?)`, next.Incident, d.ID, d.Hostname, r.Kind, r.Severity, r.Threshold, r.HoldSeconds, now.Unix(), o.At); e != nil {
			return e
		}
		if r.Email {
			if e = enqueueAlertMail(ctx, tx, next.Incident, "opened", now); e != nil {
				return e
			}
		}
	} else if event == "resolve" {
		if _, e = tx.ExecContext(ctx, "UPDATE alerts SET status='resolved',finished_at=?,close_reason='recovered' WHERE id=? AND status='active'", now.Unix(), s.Incident); e != nil {
			return e
		}
		// Suppress unattempted opening mail after recovery. A recovery notice is
		// queued only after confirmed relay acceptance of the opening notice.
		if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET status='cancelled',finished_at=?,reason='recovered_before_delivery' WHERE alert_id=? AND event='opened' AND status='queued'", now.Unix(), s.Incident); e != nil {
			return e
		}
		var delivered int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_deliveries WHERE alert_id=? AND event='opened' AND status='sent'", s.Incident).Scan(&delivered); e != nil {
			return e
		}
		if r.Email && delivered > 0 {
			if e = enqueueAlertMail(ctx, tx, s.Incident, "resolved", now); e != nil {
				return e
			}
		}
		next.Incident = ""
	}
	if next.Incident != "" && o.Condition == "bad" {
		if _, e = tx.ExecContext(ctx, "UPDATE alerts SET last_seen=MAX(last_seen,?) WHERE id=?", o.At, next.Incident); e != nil {
			return e
		}
	}
	if event != "" {
		target := next.Incident
		if target == "" {
			target = s.Incident
		}
		if e = auditDevice(ctx, tx, now, "server", "alert_"+event, d.ID+":"+target, r.Kind); e != nil {
			return e
		}
	}
	raw, _ := json.Marshal(next)
	_, e = tx.ExecContext(ctx, "INSERT INTO alert_states VALUES(?,?,?) ON CONFLICT(device_id,kind) DO UPDATE SET state_json=excluded.state_json", d.ID, r.Kind, string(raw))
	return e
}

// EvaluateAlerts consumes ordered receipt observations atomically, then checks
// offline/stale conditions. It uses a bounded fleet matching the device list.
func (s *Store) EvaluateAlerts(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var offline, last int64
	var gap bool
	if e = tx.QueryRowContext(ctx, "SELECT offline_after,last_sweep,gap FROM alert_runtime WHERE id=1").Scan(&offline, &last, &gap); e != nil {
		return e
	}
	if gap || now.Unix() < last || now.Unix()-last > 45 {
		if _, e = tx.ExecContext(ctx, `UPDATE alert_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.value',NULL) WHERE json_valid(state_json)`); e != nil {
			return e
		}
	}
	organization, e := organizationTx(ctx, tx, true)
	if e != nil {
		return e
	}
	rules := map[string]map[string]alerting.Rule{}
	for _, d := range organization.Devices {
		rs, _ := organization.Effective(d)
		rules[d.ID] = map[string]alerting.Rule{}
		for _, r := range rs {
			rules[d.ID][r.Kind] = r
		}
	}
	rows, e := tx.QueryContext(ctx, "SELECT id,hostname,last_contact_at FROM devices WHERE revoked_at IS NULL ORDER BY enrolled_at DESC,id LIMIT 1000")
	if e != nil {
		return e
	}
	fleet := map[string]Device{}
	for rows.Next() {
		var d Device
		if e = rows.Scan(&d.ID, &d.Hostname, &d.LastContactAt); e != nil {
			rows.Close()
			return e
		}
		fleet[d.ID] = d
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alerts SET status='closed',finished_at=?,close_reason='not_monitored' WHERE status='active' AND device_id NOT IN (SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY enrolled_at DESC,id LIMIT 1000)`, now.Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM alert_states WHERE device_id NOT IN (SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY enrolled_at DESC,id LIMIT 1000)`); e != nil {
		return e
	}
	rows, e = tx.QueryContext(ctx, "SELECT seq,device_id,kind,status,data,received_at,contact_at FROM alert_samples ORDER BY seq LIMIT 2000")
	if e != nil {
		return e
	}
	var samples []alertSample
	for rows.Next() {
		var v alertSample
		if e = rows.Scan(&v.seq, &v.device, &v.kind, &v.status, &v.data, &v.at, &v.contact); e != nil {
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
		d, ok := fleet[v.device]
		if ok {
			r, ok := rules[d.ID][v.kind]
			if ok {
				if e = applyAlert(ctx, tx, d, r, sampleObservation(v, r, offline), now); e != nil {
					return e
				}
			}
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM alert_samples WHERE seq=?", v.seq); e != nil {
			return e
		}
	}
	for _, d := range fleet {
		for _, r := range rules[d.ID] {
			state, e := loadAlertState(ctx, tx, d.ID, r.Kind)
			if e != nil {
				return e
			}
			o := alerting.Observation{Condition: "unknown", At: now.Unix()}
			online := d.LastContactAt != nil && *d.LastContactAt <= now.Unix() && now.Unix()-*d.LastContactAt < offline
			if r.Kind == "offline" {
				if d.LastContactAt != nil && *d.LastContactAt <= now.Unix() && !online {
					o.Condition = "bad"
				} else if online {
					continue
				}
			} else if online && state.LastSample <= now.Unix() && now.Unix()-state.LastSample < alerting.Freshness(r.Kind) {
				continue
			}
			if e = applyAlert(ctx, tx, d, r, o, now); e != nil {
				return e
			}
		}
	}
	if e = evaluateHealth(ctx, tx, now, offline, last, gap); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alert_deliveries SET status='cancelled',finished_at=?,reason='no_longer_relevant' WHERE status='queued' AND ((event='opened' AND alert_id IN (SELECT id FROM alerts WHERE status<>'active' OR acknowledged_at IS NOT NULL)) OR alert_id IN (SELECT id FROM alerts WHERE status='closed') OR created_at<=?)`, now.Unix(), now.Add(-time.Hour).Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET status='unknown',finished_at=?,reason='interrupted' WHERE status='sending' AND next_attempt<=?", now.Unix(), now.Unix()); e != nil {
		return e
	}
	// History is bounded separately from active incidents (at most 4/fleet device).
	if _, e = tx.ExecContext(ctx, `DELETE FROM alerts WHERE status<>'active' AND (finished_at<? OR id IN (SELECT id FROM alerts WHERE status<>'active' ORDER BY finished_at DESC,id LIMIT -1 OFFSET 2000))`, now.Add(-30*24*time.Hour).Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE alert_runtime SET last_sweep=?,gap=0 WHERE id=1", now.Unix()); e != nil {
		return e
	}
	return tx.Commit()
}

const alertColumns = "a.id,a.device_id,a.hostname,a.kind,a.severity,a.threshold,a.hold_seconds,a.status,a.opened_at,a.last_seen,a.finished_at,a.acknowledged_at,a.acknowledged_by,a.close_reason,a.label"

func scanAlert(row interface{ Scan(...any) error }) (Alert, error) {
	var a Alert
	e := row.Scan(&a.ID, &a.DeviceID, &a.Hostname, &a.Kind, &a.Severity, &a.Threshold, &a.HoldSeconds, &a.Status, &a.OpenedAt, &a.LastSeen, &a.FinishedAt, &a.AcknowledgedAt, &a.AcknowledgedBy, &a.CloseReason, &a.Label)
	return a, e
}
func (s *Store) Alerts(ctx context.Context, device string) ([]Alert, error) {
	return s.AlertsForSession(ctx, Session{}, device)
}
func (s *Store) AlertsForSession(ctx context.Context, v Session, device string) ([]Alert, error) {
	scope, args := technicianScope(v, "a.device_id")
	args = append([]any{device, device}, args...)
	rows, e := s.db.QueryContext(ctx, "SELECT "+alertColumns+" FROM alerts a WHERE (?='' OR a.device_id=?) AND "+scope+" ORDER BY CASE a.status WHEN 'active' THEN 0 ELSE 1 END,CASE a.severity WHEN 'critical' THEN 0 ELSE 1 END,a.opened_at DESC,a.id LIMIT 200", args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []Alert{}
	for rows.Next() {
		a, e := scanAlert(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, a)
	}
	return result, rows.Err()
}
func (s *Store) AlertStates(ctx context.Context, device string) ([]AlertDeviceState, error) {
	return s.AlertStatesForSession(ctx, Session{}, device)
}
func (s *Store) AlertStatesForSession(ctx context.Context, v Session, device string) ([]AlertDeviceState, error) {
	scope, args := technicianScope(v, "s.device_id")
	args = append([]any{device, device}, args...)
	rows, e := s.db.QueryContext(ctx, "SELECT s.device_id,d.hostname,s.kind,s.state_json,s.label FROM (SELECT device_id,kind,state_json,'' AS label FROM alert_states UNION ALL SELECT h.device_id,'check:'||h.check_id,h.state_json,c.name FROM health_states h JOIN health_checks c ON c.id=h.check_id) s JOIN devices d ON d.id=s.device_id WHERE (?='' OR s.device_id=?) AND "+scope+" ORDER BY s.device_id,s.kind LIMIT 4100", args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []AlertDeviceState{}
	for rows.Next() {
		var a AlertDeviceState
		var raw string
		if e = rows.Scan(&a.DeviceID, &a.Hostname, &a.Kind, &raw, &a.Label); e != nil || json.Unmarshal([]byte(raw), &a.State) != nil {
			return nil, ErrAlert
		}
		result = append(result, a)
	}
	return result, rows.Err()
}
func (s *Store) AlertRuntime(ctx context.Context) (AlertRuntime, error) {
	var r AlertRuntime
	e := s.db.QueryRowContext(ctx, `SELECT offline_after,last_sweep,last_gap,mail_config,mail_paused,(SELECT COUNT(*) FROM alert_samples),(SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL) FROM alert_runtime WHERE id=1`).Scan(&r.OfflineAfter, &r.LastSweep, &r.LastGap, &r.MailConfig, &r.MailPaused, &r.PendingSamples, &r.MonitoredDevices)
	r.Limited = r.MonitoredDevices > 1000
	r.MailConfigured = r.MailConfig != ""
	return r, e
}
func (s *Store) AcknowledgeAlert(ctx context.Context, id, actor string, now time.Time) error {
	if !protocol.ValidID(id) || actor == "" || len(actor) > 128 {
		return ErrAlert
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := scanAlert(tx.QueryRowContext(ctx, "SELECT "+alertColumns+" FROM alerts a WHERE a.id=?", id))
	if e != nil || a.Status != "active" {
		return ErrAlert
	}
	if a.AcknowledgedAt != nil {
		return tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, "UPDATE alerts SET acknowledged_at=?,acknowledged_by=? WHERE id=?", now.Unix(), actor, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET status='cancelled',finished_at=?,reason='acknowledged' WHERE alert_id=? AND event='opened' AND status='queued'", now.Unix(), id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "alert_acknowledged", a.DeviceID+":"+id, "acknowledged"); e != nil {
		return e
	}
	return tx.Commit()
}
