package storage

import (
	"context"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"time"
)

type AlertDelivery struct {
	ID          int64  `json:"id"`
	AlertID     string `json:"alert_id"`
	Event       string `json:"event"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	NextAttempt int64  `json:"next_attempt"`
	Attempts    int    `json:"attempts"`
	FinishedAt  *int64 `json:"finished_at"`
	Reason      string `json:"reason"`
}

func (s *Store) PauseAlertMail(ctx context.Context, paused bool, actor string, now time.Time) error {
	if actor == "" || len(actor) > 128 {
		return ErrAlert
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE alert_runtime SET mail_paused=? WHERE id=1", paused); e != nil {
		return e
	}
	if paused {
		if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET status='cancelled',finished_at=?,reason='paused' WHERE status='queued'", now.Unix()); e != nil {
			return e
		}
	}
	if e = auditDevice(ctx, tx, now, actor, "alert_email_pause", "", fmt.Sprint(paused)); e != nil {
		return e
	}
	return tx.Commit()
}

// Claim commits Sending before network I/O. A crashed send becomes Unknown at
// next startup, never an automatic replay of potentially accepted mail.
func (s *Store) ClaimAlertMail(ctx context.Context, configID string, now time.Time) (int64, alerting.Notice, error) {
	var n alerting.Notice
	if configID == "" {
		return 0, n, nil
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return 0, n, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT id,alert_id,event FROM alert_deliveries WHERE status='queued' AND config_id=? AND config_id=(SELECT mail_config FROM alert_runtime WHERE id=1 AND mail_paused=0) AND next_attempt<=? AND created_at>? AND attempts<5 ORDER BY id LIMIT 100`, configID, now.Unix(), now.Add(-time.Hour).Unix())
	if e != nil {
		return 0, n, e
	}
	type candidate struct {
		id           int64
		alert, event string
	}
	var cs []candidate
	for rows.Next() {
		var c candidate
		if e = rows.Scan(&c.id, &c.alert, &c.event); e != nil {
			rows.Close()
			return 0, n, e
		}
		cs = append(cs, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, n, e
	}
	organization, e := organizationTx(ctx, tx, true)
	if e != nil {
		return 0, n, e
	}
	effective := map[string][]alerting.Rule{}
	for _, d := range organization.Devices {
		effective[d.ID], _ = organization.Effective(d)
	}
	for _, c := range cs {
		a, e := scanAlert(tx.QueryRowContext(ctx, "SELECT "+alertColumns+" FROM alerts a WHERE a.id=?", c.alert))
		if e != nil {
			return 0, n, e
		}
		valid := true
		rule := ruleByKind(effective[a.DeviceID], a.Kind)
		valid = rule.Enabled && rule.Email
		if strings.HasPrefix(a.Kind, "check:") {
			c, err := scanHealth(tx.QueryRowContext(ctx, "SELECT "+healthColumns+" FROM health_checks WHERE id=?", strings.TrimPrefix(a.Kind, "check:")))
			if err != nil {
				return 0, n, err
			}
			_, monitored := effective[a.DeviceID]
			valid = c.Enabled && c.Email && monitored
		}
		var active int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NULL", a.DeviceID).Scan(&active); e != nil {
			return 0, n, e
		}
		valid = valid && active == 1
		if c.event == "opened" {
			valid = valid && a.Status == "active" && a.AcknowledgedAt == nil
		} else {
			valid = valid && a.Status == "resolved" && a.CloseReason == "recovered"
			var newer int
			if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE device_id=? AND kind=? AND status='active'", a.DeviceID, a.Kind).Scan(&newer); e != nil {
				return 0, n, e
			}
			valid = valid && newer == 0
		}
		if !valid {
			if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET status='cancelled',finished_at=?,reason='no_longer_relevant' WHERE id=?", now.Unix(), c.id); e != nil {
				return 0, n, e
			}
			continue
		}
		if c.event == "opened" {
			state, e := loadAlertState(ctx, tx, a.DeviceID, a.Kind)
			if e != nil {
				return 0, n, e
			}
			if state.Condition != "bad" || state.LastSample > now.Unix() || now.Unix()-state.LastSample >= alerting.Freshness(a.Kind) {
				if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET next_attempt=? WHERE id=?", now.Add(30*time.Second).Unix(), c.id); e != nil {
					return 0, n, e
				}
				continue
			}
		}
		var sweep int64
		if e = tx.QueryRowContext(ctx, "SELECT last_sweep FROM alert_runtime WHERE id=1").Scan(&sweep); e != nil {
			return 0, n, e
		}
		if sweep > now.Unix() || now.Unix()-sweep >= 45 {
			continue
		}
		if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET status='sending',attempts=attempts+1,next_attempt=? WHERE id=?", now.Add(30*time.Second).Unix(), c.id); e != nil {
			return 0, n, e
		}
		n = alerting.Notice{AlertID: a.ID, Event: c.event, DeviceID: a.DeviceID, Hostname: a.Hostname, Title: alerting.Title(a.Kind), Severity: a.Severity, OpenedAt: a.OpenedAt}
		if strings.HasPrefix(a.Kind, "check:") {
			n.Title = a.Label
			n.Condition = fmt.Sprintf("Required-service check qualified for %d seconds of observed samples. Review the device health check for service and response details.", a.HoldSeconds)
		} else if a.Kind == "offline" {
			n.Condition = fmt.Sprintf("Offline alert qualified for %d seconds beyond the connection timeout.", a.HoldSeconds)
		} else {
			comparison := "at least"
			unit := "usage"
			if a.Kind == "disk_space" {
				comparison = "below"
				unit = "available"
			}
			n.Condition = fmt.Sprintf("%s %d%% %s for at least %d seconds of observed samples.", comparison, a.Threshold, unit, a.HoldSeconds)
		}
		if e = tx.Commit(); e != nil {
			return 0, n, e
		}
		return c.id, n, nil
	}
	return 0, n, tx.Commit()
}
func (s *Store) FinishAlertMail(ctx context.Context, id int64, r alerting.MailResult, now time.Time) error {
	validReason := map[string]bool{"accepted": true, "connection": true, "tls": true, "tls_required": true, "rejected": true, "temporary": true, "acceptance_unknown": true, "invalid_notice": true, "too_large": true, "encoding": true, "disabled": true}
	if !validReason[r.Reason] || (r.Status != "sent" && r.Status != "retry" && r.Status != "failed" && r.Status != "unknown") {
		return ErrAlert
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var attempts int
	var created int64
	var status, aid string
	if e = tx.QueryRowContext(ctx, "SELECT status,attempts,created_at,alert_id FROM alert_deliveries WHERE id=?", id).Scan(&status, &attempts, &created, &aid); e != nil {
		return e
	}
	if status != "sending" {
		return ErrAlert
	}
	status = r.Status
	var finished any = now.Unix()
	next := now.Unix()
	if status == "retry" {
		status = "failed"
		if attempts < 5 && now.Unix()-created < 3600 {
			status = "queued"
			finished = nil
			next = now.Add(time.Duration(1<<uint(attempts-1)) * time.Minute).Unix()
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET status=?,finished_at=?,next_attempt=?,reason=? WHERE id=?", status, finished, next, r.Reason, id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, "server", "alert_email", aid, status); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) AlertDeliveries(ctx context.Context, device string) ([]AlertDelivery, error) {
	return s.AlertDeliveriesForSession(ctx, Session{}, device)
}
func (s *Store) AlertDeliveriesForSession(ctx context.Context, v Session, device string) ([]AlertDelivery, error) {
	return s.alertDeliveriesFor(ctx, v, device, "")
}
func (s *Store) IncidentDeliveriesForSession(ctx context.Context, v Session, incident string) ([]AlertDelivery, error) {
	if !protocol.ValidID(incident) {
		return nil, ErrAlertNotFound
	}
	return s.alertDeliveriesFor(ctx, v, "", incident)
}
func (s *Store) alertDeliveriesFor(ctx context.Context, v Session, device, incident string) ([]AlertDelivery, error) {
	scope, args := technicianScope(v, "a.device_id")
	args = append([]any{device, device, incident, incident}, args...)
	rows, e := s.db.QueryContext(ctx, `SELECT m.id,m.alert_id,m.event,m.status,m.created_at,m.next_attempt,m.attempts,m.finished_at,m.reason FROM alert_deliveries m JOIN alerts a ON a.id=m.alert_id WHERE (?='' OR a.device_id=?) AND (?='' OR a.id=?) AND `+scope+` ORDER BY m.id DESC LIMIT 100`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []AlertDelivery{}
	for rows.Next() {
		var v AlertDelivery
		if e = rows.Scan(&v.ID, &v.AlertID, &v.Event, &v.Status, &v.CreatedAt, &v.NextAttempt, &v.Attempts, &v.FinishedAt, &v.Reason); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
