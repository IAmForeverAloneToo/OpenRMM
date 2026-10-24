package storage

import (
	"context"
	"database/sql"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"unicode"
	"unicode/utf8"
)

const AlertPageSize = 50

var ErrAlertNotFound = errors.New("incident unavailable")

type AlertFilter struct {
	Device, Group, Tag, Status, Acknowledgment, Severity, Kind, Query string
	Page                                                              int
}

func (f AlertFilter) Valid() bool {
	if f.Page < 1 || f.Page > 1000 || (f.Device != "" && !protocol.ValidID(f.Device)) || (f.Group != "" && f.Group != "ungrouped" && !ValidOrganizationID(f.Group)) {
		return false
	}
	if f.Tag != "" {
		tags, e := ParseDeviceTags(f.Tag)
		if e != nil || len(tags) != 1 || tags[0] != f.Tag {
			return false
		}
	}
	allowed := func(value string, choices ...string) bool {
		for _, choice := range choices {
			if value == choice {
				return true
			}
		}
		return false
	}
	if !allowed(f.Status, "", "active", "resolved", "closed") || !allowed(f.Acknowledgment, "", "unacknowledged", "acknowledged") || !allowed(f.Severity, "", "critical", "warning") || !allowed(f.Kind, "", "offline", "cpu", "memory", "disk_space", "health") {
		return false
	}
	if len(f.Query) > 128 || !utf8.ValidString(f.Query) {
		return false
	}
	for _, c := range f.Query {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return false
		}
	}
	return true
}

type AlertCounts struct {
	Matching       int `json:"matching"`
	Active         int `json:"active"`
	Unacknowledged int `json:"unacknowledged_active"`
	Critical       int `json:"critical_active"`
	Resolved       int `json:"resolved"`
	Closed         int `json:"closed"`
}
type AlertTriage struct {
	Counts   AlertCounts `json:"counts"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Alerts   []Alert     `json:"alerts"`
}

// Scope and filters apply before counts and pagination. Both SELECTs share a
// read transaction; this projection never evaluates or changes an incident.
func (s *Store) AlertTriage(ctx context.Context, v Session, f AlertFilter) (AlertTriage, error) {
	out := AlertTriage{Page: f.Page, PageSize: AlertPageSize, Alerts: []Alert{}}
	if !f.Valid() {
		return out, ErrAlert
	}
	scope, args := technicianScope(v, "a.device_id")
	where := ` FROM alerts a LEFT JOIN device_organization o ON o.device_id=a.device_id WHERE (` + scope + `)`
	add := func(clause string, values ...any) { where += " AND " + clause; args = append(args, values...) }
	if f.Device != "" {
		add("a.device_id=?", f.Device)
	}
	if f.Group == "ungrouped" {
		add("COALESCE(o.group_id,'')=''")
	} else if f.Group != "" {
		add("o.group_id=?", f.Group)
	}
	if f.Tag != "" {
		add("EXISTS(SELECT 1 FROM json_each(o.tags_json) WHERE value=?)", f.Tag)
	}
	if f.Status != "" {
		add("a.status=?", f.Status)
	}
	if f.Severity != "" {
		add("a.severity=?", f.Severity)
	}
	if f.Kind == "health" {
		add("a.kind LIKE 'check:%'")
	} else if f.Kind != "" {
		add("a.kind=?", f.Kind)
	}
	if f.Acknowledgment == "acknowledged" {
		add("a.acknowledged_at IS NOT NULL")
	} else if f.Acknowledgment == "unacknowledged" {
		add("a.acknowledged_at IS NULL")
	}
	if f.Query != "" {
		add("(instr(lower(a.hostname),lower(?))>0 OR instr(a.device_id,?)>0)", f.Query, f.Query)
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	c := &out.Counts
	e = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(a.status='active'),0),COALESCE(SUM(a.status='active' AND a.acknowledged_at IS NULL),0),COALESCE(SUM(a.status='active' AND a.severity='critical'),0),COALESCE(SUM(a.status='resolved'),0),COALESCE(SUM(a.status='closed'),0)`+where, args...).Scan(&c.Matching, &c.Active, &c.Unacknowledged, &c.Critical, &c.Resolved, &c.Closed)
	if e != nil {
		return out, e
	}
	args = append(args, AlertPageSize, (f.Page-1)*AlertPageSize)
	rows, e := tx.QueryContext(ctx, "SELECT "+alertColumns+where+" ORDER BY CASE a.status WHEN 'active' THEN 0 ELSE 1 END,CASE a.severity WHEN 'critical' THEN 0 ELSE 1 END,a.opened_at DESC,a.id LIMIT ? OFFSET ?", args...)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			rows.Close()
			return out, err
		}
		out.Alerts = append(out.Alerts, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}

func (s *Store) AlertIncidentForSession(ctx context.Context, v Session, id string) (Alert, error) {
	if !protocol.ValidID(id) {
		return Alert{}, ErrAlertNotFound
	}
	scope, args := technicianScope(v, "a.device_id")
	args = append([]any{id}, args...)
	a, e := scanAlert(s.db.QueryRowContext(ctx, "SELECT "+alertColumns+" FROM alerts a WHERE a.id=? AND ("+scope+")", args...))
	if errors.Is(e, sql.ErrNoRows) {
		return Alert{}, ErrAlertNotFound
	}
	return a, e
}

func AlertRuleFamily(kind string) string {
	if strings.HasPrefix(kind, "check:") {
		return "health"
	}
	return kind
}
