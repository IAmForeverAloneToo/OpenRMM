package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
)

var ErrHealthCheck = errors.New("health check changed or unavailable; reload and review again")

// Canonicalize the complete Unicode simple-fold cycle, matching EqualFold.
// SQLite lower() only folds ASCII and cannot be used for Windows service keys.
func healthServiceKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		key := r
		for n := unicode.SimpleFold(r); n != r; n = unicode.SimpleFold(n) {
			if n < key {
				key = n
			}
		}
		b.WriteRune(key)
	}
	return b.String()
}

type HealthCheck struct {
	ID              string `json:"id"`
	DeviceID        string `json:"device_id"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Service         string `json:"service"`
	Enabled         bool   `json:"enabled"`
	HoldSeconds     int64  `json:"hold_seconds"`
	RecoverySeconds int64  `json:"recovery_seconds"`
	Severity        string `json:"severity"`
	Email           bool   `json:"email"`
	Response        bool   `json:"response"`
	CooldownSeconds int64  `json:"cooldown_seconds"`
	Revision        int64  `json:"revision"`
}

type HealthChange struct {
	Check HealthCheck `json:"check"`
	Rearm bool        `json:"rearm"`
}

type HealthStatus struct {
	HealthCheck
	Hostname    string         `json:"hostname"`
	State       alerting.State `json:"state"`
	AttemptID   string         `json:"attempt_id"`
	Blocked     bool           `json:"response_blocked"`
	LastAttempt int64          `json:"last_attempt"`
}

type HealthAttempt struct {
	ActionID   string `json:"action_id"`
	CheckID    string `json:"check_id"`
	IncidentID string `json:"incident_id"`
	DeviceID   string `json:"device_id"`
	CheckName  string `json:"check_name"`
	Service    string `json:"service"`
	CreatedAt  int64  `json:"created_at"`
	Status     string `json:"status"`
	Outcome    string `json:"outcome"`
	State      string `json:"state"`
	FinishedAt *int64 `json:"finished_at"`
}

const healthColumns = "id,device_id,name,kind,service_name,enabled,hold_seconds,recovery_seconds,severity,email,response,cooldown_seconds,revision"

// maxHealthChecks bounds the live (enabled, monitored) checks fleet-wide and
// maxStoredHealthChecks all stored ones; checks of revoked devices are
// removed. monitoredDevices are the devices alerting evaluates.
const (
	maxHealthChecks       = 2000
	maxStoredHealthChecks = 5000
	monitoredDevices      = "SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY enrolled_at DESC,id LIMIT 1000"
)

func scanHealth(row interface{ Scan(...any) error }) (HealthCheck, error) {
	var c HealthCheck
	e := row.Scan(&c.ID, &c.DeviceID, &c.Name, &c.Kind, &c.Service, &c.Enabled, &c.HoldSeconds, &c.RecoverySeconds, &c.Severity, &c.Email, &c.Response, &c.CooldownSeconds, &c.Revision)
	return c, e
}

// healthValid allows monitoring any service, including OpenRMM's own, but an
// automatic start (Response) only for services the agent may control.
func healthValid(c HealthCheck) bool {
	return protocol.ValidID(c.ID) && protocol.ValidID(c.DeviceID) && validOrganizationName(c.Name) && len(c.Name) <= 128 && c.Kind == "service_running" && winservices.Name(c.Service) && (!c.Response || winservices.Manageable(c.Service)) && c.HoldSeconds >= 60 && c.HoldSeconds <= 86400 && c.RecoverySeconds >= 60 && c.RecoverySeconds <= 3600 && (c.Severity == "warning" || c.Severity == "critical") && c.CooldownSeconds >= 3600 && c.CooldownSeconds <= 604800 && c.Revision >= 0
}

// Configuration is administrator-only, revision checked, and bound to a review
// of the exact proposed response. Edits never erase the device/service guard.
func (s *Store) ChangeHealthCheck(ctx context.Context, c HealthChange, actor, digest string, now time.Time) (string, error) {
	v := c.Check
	if !healthValid(v) {
		return "", ErrHealthCheck
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if e = ownerTx(ctx, tx, actor); e != nil {
		return "", e
	}
	var hostname string
	if e = tx.QueryRowContext(ctx, "SELECT hostname FROM devices WHERE id=? AND revoked_at IS NULL AND os='windows'", v.DeviceID).Scan(&hostname); e != nil {
		return "", ErrHealthCheck
	}
	old, e := scanHealth(tx.QueryRowContext(ctx, "SELECT "+healthColumns+" FROM health_checks WHERE id=?", v.ID))
	if errors.Is(e, sql.ErrNoRows) {
		if v.Revision != 0 || c.Rearm {
			return "", ErrHealthCheck
		}
		// Live checks (enabled, on a monitored device) count toward the
		// limits; stored ones, disabled included, have a wider bound.
		var stored, total, perDevice int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(enabled=1 AND device_id IN ("+monitoredDevices+")),0),COALESCE(SUM(enabled=1 AND device_id=?),0) FROM health_checks", v.DeviceID).Scan(&stored, &total, &perDevice); e != nil {
			return "", e
		}
		if stored >= maxStoredHealthChecks || total >= maxHealthChecks || perDevice >= 10 {
			return "", ErrHealthCheck
		}
	} else if e != nil || old.Revision != v.Revision || old.DeviceID != v.DeviceID {
		return "", ErrHealthCheck
	}
	var guardAction string
	var guardTime int64
	var guardBlocked bool
	if c.Rearm {
		var pending int
		if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM health_attempts WHERE device_id=? AND service_key=? AND status IN ('queued','dispatched')`, v.DeviceID, healthServiceKey(v.Service)).Scan(&pending); e != nil {
			return "", e
		}
		if pending > 0 {
			return "", ErrHealthCheck
		}
		e = tx.QueryRowContext(ctx, "SELECT action_id,last_attempt,blocked FROM health_guards WHERE device_id=? AND service_key=?", v.DeviceID, healthServiceKey(v.Service)).Scan(&guardAction, &guardTime, &guardBlocked)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return "", e
		}
	}
	raw, _ := json.Marshal(struct {
		Before       HealthCheck
		Change       HealthChange
		Hostname     string
		GuardAction  string
		GuardTime    int64
		GuardBlocked bool
	}{old, c, hostname, guardAction, guardTime, guardBlocked})
	sum := sha256.Sum256(raw)
	expected := hex.EncodeToString(sum[:])
	if digest == "" {
		return expected, nil
	}
	if digest != expected {
		return "", ErrHealthCheck
	}
	if e = closeHealth(ctx, tx, v.ID, "settings_changed", now); e != nil {
		return "", e
	}
	if v.Revision == 0 {
		_, e = tx.ExecContext(ctx, `INSERT INTO health_checks(id,device_id,name,kind,service_name,service_key,enabled,hold_seconds,recovery_seconds,severity,email,response,cooldown_seconds,revision,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)`, v.ID, v.DeviceID, v.Name, v.Kind, v.Service, healthServiceKey(v.Service), v.Enabled, v.HoldSeconds, v.RecoverySeconds, v.Severity, v.Email, v.Response, v.CooldownSeconds, now.Unix())
	} else {
		_, e = tx.ExecContext(ctx, `UPDATE health_checks SET name=?,kind=?,service_name=?,service_key=?,enabled=?,hold_seconds=?,recovery_seconds=?,severity=?,email=?,response=?,cooldown_seconds=?,revision=revision+1 WHERE id=?`, v.Name, v.Kind, v.Service, healthServiceKey(v.Service), v.Enabled, v.HoldSeconds, v.RecoverySeconds, v.Severity, v.Email, v.Response, v.CooldownSeconds, v.ID)
	}
	if e != nil {
		return "", e
	}
	if c.Rearm {
		if _, e = tx.ExecContext(ctx, "UPDATE health_guards SET blocked=0 WHERE device_id=? AND service_key=?", v.DeviceID, healthServiceKey(v.Service)); e != nil {
			return "", e
		}
	}
	if e = auditDevice(ctx, tx, now, actor, "health_check_changed", v.DeviceID+":"+v.ID, "reviewed"); e != nil {
		return "", e
	}
	if c.Rearm {
		if e = auditDevice(ctx, tx, now, actor, "health_response_rearmed", v.DeviceID+":"+v.ID, "cooldown_retained"); e != nil {
			return "", e
		}
	}
	return expected, tx.Commit()
}

func closeHealth(ctx context.Context, tx *sql.Tx, id, reason string, now time.Time) error {
	if _, e := tx.ExecContext(ctx, `UPDATE alerts SET status='closed',finished_at=?,close_reason=? WHERE kind=? AND status='active'`, now.Unix(), reason, "check:"+id); e != nil {
		return e
	}
	if e := cancelHealthActions(ctx, tx, id, now); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, "DELETE FROM health_samples WHERE check_id=?", id); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, "DELETE FROM health_states WHERE check_id=?", id)
	return e
}

func cancelHealthActions(ctx context.Context, tx *sql.Tx, id string, now time.Time) error {
	r, e := tx.ExecContext(ctx, `UPDATE service_actions SET status='cancelled',finished_at=? WHERE status='queued' AND id IN (SELECT action_id FROM health_attempts WHERE check_id=?)`, now.Unix(), id)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n > 0 {
		return auditDevice(ctx, tx, now, "server", "health_response_cancelled", id, "not_dispatched")
	}
	return nil
}

func (s *Store) HealthChecksForSession(ctx context.Context, v Session, device string, now time.Time) ([]HealthStatus, error) {
	scope, args := technicianScope(v, "c.device_id")
	args = append([]any{device, device}, args...)
	columns := "c." + strings.ReplaceAll(healthColumns, ",", ",c.")
	rows, e := s.db.QueryContext(ctx, `SELECT `+columns+`,d.hostname,COALESCE(h.state_json,'{}'),COALESCE(h.attempt_id,''),COALESCE(g.blocked,0),COALESCE(g.last_attempt,0),(SELECT last_sweep FROM alert_runtime WHERE id=1),d.revoked_at FROM health_checks c JOIN devices d ON d.id=c.device_id LEFT JOIN health_states h ON h.check_id=c.id LEFT JOIN health_guards g ON g.device_id=c.device_id AND g.service_key=c.service_key WHERE (?='' OR c.device_id=?) AND `+scope+` ORDER BY c.created_at,c.id LIMIT 5000`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []HealthStatus{}
	for rows.Next() {
		var r HealthStatus
		var raw string
		var sweep int64
		var revoked *int64
		c := &r.HealthCheck
		if e = rows.Scan(&c.ID, &c.DeviceID, &c.Name, &c.Kind, &c.Service, &c.Enabled, &c.HoldSeconds, &c.RecoverySeconds, &c.Severity, &c.Email, &c.Response, &c.CooldownSeconds, &c.Revision, &r.Hostname, &raw, &r.AttemptID, &r.Blocked, &r.LastAttempt, &sweep, &revoked); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(raw), &r.State); e != nil {
			return nil, e
		}
		if revoked != nil || !c.Enabled || r.State.Condition == "" || r.State.LastSample > now.Unix() || now.Unix()-r.State.LastSample >= 120 || sweep > now.Unix() || now.Unix()-sweep >= 45 {
			r.State.Condition = "unknown"
			r.State.Value = nil
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) HealthAttemptsForSession(ctx context.Context, v Session, device string) ([]HealthAttempt, error) {
	scope, args := technicianScope(v, "h.device_id")
	args = append([]any{device, device}, args...)
	rows, e := s.db.QueryContext(ctx, `SELECT action_id,check_id,incident_id,device_id,check_name,service_name,created_at,status,outcome,observed_state,finished_at FROM health_attempts h WHERE (?='' OR h.device_id=?) AND `+scope+` ORDER BY created_at DESC,action_id DESC LIMIT 100`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []HealthAttempt{}
	for rows.Next() {
		var a HealthAttempt
		if e = rows.Scan(&a.ActionID, &a.CheckID, &a.IncidentID, &a.DeviceID, &a.CheckName, &a.Service, &a.CreatedAt, &a.Status, &a.Outcome, &a.State, &a.FinishedAt); e != nil {
			return nil, e
		}
		result = append(result, a)
	}
	return result, rows.Err()
}
