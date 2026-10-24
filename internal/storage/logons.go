package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/logons"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Logon history bounds (365 days, like the session history).
const (
	LogonHistoryDays        = 365
	LogonHistoryLimit       = 20000 // per device, separately for network logons
	logonGlobalHistoryLimit = 1000000
	LogonHistoryPage        = 500
)

type LogonStatus struct {
	Capability  protocol.Capability `json:"capability"`
	Status      string              `json:"status"`
	ReportedAt  int64               `json:"reported_at"`
	CollectedAt *int64              `json:"collected_at"`
	More        bool                `json:"more"`
}

func logonsError() error { return errors.New("cannot persist logon history") }

// RecordLogons stores a batch of logons after repeating device authorization.
// Logons outside retention are dropped; a repeated logon is ignored.
func (s *Store) RecordLogons(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	report, e := logons.Normalize(report)
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return logonsError()
	}
	defer tx.Rollback()
	var allowed int
	if e = tx.QueryRowContext(ctx, `SELECT 1 FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))`, id, fingerprint, fingerprint, now.Unix()).Scan(&allowed); errors.Is(e, sql.ErrNoRows) {
		return ErrAuthentication
	} else if e != nil {
		return logonsError()
	}
	var collected any
	more := false
	if report.Status == "ok" {
		collected = now.Unix()
		var v protocol.Logons
		if json.Unmarshal(report.Data, &v) != nil {
			return logonsError()
		}
		more = v.More
		oldest, newest := now.Add(-LogonHistoryDays*24*time.Hour).Unix(), now.Add(24*time.Hour).Unix()
		for _, l := range v.Logons {
			if l.Time <= oldest || l.Time > newest {
				continue
			}
			if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO logon_history(device_id,logon_at,record_id,user_name,domain,sid,logon_type,source_ip,source_port,workstation,auth_package,logon_process,logon_id,elevated)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, l.Time, int64(l.RecordID), l.User, l.Domain, l.SID, l.Type, l.SourceIP, l.SourcePort, l.Workstation, l.AuthPackage, l.LogonProcess, l.LogonID, l.Elevated); e != nil {
				return logonsError()
			}
		}
		// Network logons have their own cap, so on a busy server they never
		// push out the interactive and Remote Desktop history.
		if len(v.Logons) > 0 {
			for _, network := range []bool{false, true} {
				if _, e = tx.ExecContext(ctx, `DELETE FROM logon_history WHERE device_id=? AND (logon_type IN ('network','network_cleartext'))=? AND logon_at<(SELECT logon_at FROM logon_history WHERE device_id=? AND (logon_type IN ('network','network_cleartext'))=? ORDER BY logon_at DESC LIMIT 1 OFFSET ?)`, id, network, id, network, LogonHistoryLimit-1); e != nil {
					return logonsError()
				}
			}
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO device_logons(device_id,capability_version,last_status,reported_at,collected_at,more) VALUES(?,?,?,?,?,?)
 ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,reported_at=excluded.reported_at,
 collected_at=coalesce(excluded.collected_at,device_logons.collected_at),more=CASE WHEN excluded.last_status='ok' THEN excluded.more ELSE device_logons.more END
 WHERE excluded.reported_at>=device_logons.reported_at`, id, report.Capability.Version, report.Status, now.Unix(), collected, more); e != nil {
		return logonsError()
	}
	if tx.Commit() != nil {
		return logonsError()
	}
	return nil
}

func (s *Store) LogonStatus(ctx context.Context, id string) (LogonStatus, error) {
	v := LogonStatus{Capability: logons.Capability, Status: "not_reported"}
	e := s.db.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,collected_at,more FROM device_logons WHERE device_id=?`, id).Scan(&v.Capability.Version, &v.Status, &v.ReportedAt, &v.CollectedAt, &v.More)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	if e != nil {
		return v, errors.New("cannot read logon history")
	}
	return v, nil
}

// LogonFilter narrows the history: a text in user, domain, source address or
// workstation; a kind (interactive includes cached logons, network includes
// cleartext network logons); and a page cursor (older than Before/Record).
type LogonFilter struct {
	Query  string
	Kind   string
	Before int64
	Record uint64
}

var logonKinds = map[string][]string{"interactive": {"interactive", "cached"}, "remote": {"remote"}, "network": {"network", "network_cleartext"}}

func ValidLogonFilter(f LogonFilter) bool {
	if _, ok := logonKinds[f.Kind]; f.Kind != "" && !ok {
		return false
	}
	return len(f.Query) <= 100 && !strings.ContainsAny(f.Query, "\x00\r\n") && f.Before >= 0 && (f.Before > 0 || f.Record == 0)
}

// Logons returns the newest page of logons within retention, newest first,
// and whether older ones match.
func (s *Store) Logons(ctx context.Context, id string, f LogonFilter, now time.Time) ([]protocol.Logon, bool, error) {
	if !ValidLogonFilter(f) {
		return nil, false, errors.New("invalid logon filter")
	}
	q := `SELECT logon_at,record_id,user_name,domain,sid,logon_type,source_ip,source_port,workstation,auth_package,logon_process,logon_id,elevated FROM logon_history WHERE device_id=? AND logon_at>?`
	args := []any{id, now.Add(-LogonHistoryDays * 24 * time.Hour).Unix()}
	if kinds := logonKinds[f.Kind]; len(kinds) > 0 {
		q += ` AND logon_type IN (?` + strings.Repeat(",?", len(kinds)-1) + `)`
		for _, k := range kinds {
			args = append(args, k)
		}
	}
	if t := strings.TrimSpace(f.Query); t != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(t)) + "%"
		q += ` AND (lower(user_name) LIKE ? ESCAPE '\' OR lower(domain) LIKE ? ESCAPE '\' OR lower(source_ip) LIKE ? ESCAPE '\' OR lower(workstation) LIKE ? ESCAPE '\' OR lower(domain||'\'||user_name) LIKE ? ESCAPE '\')`
		args = append(args, like, like, like, like, like)
	}
	if f.Before > 0 {
		q += ` AND (logon_at<? OR (logon_at=? AND record_id<?))`
		args = append(args, f.Before, f.Before, int64(f.Record))
	}
	q += ` ORDER BY logon_at DESC,record_id DESC LIMIT ?`
	args = append(args, LogonHistoryPage+1)
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, false, errors.New("cannot read logon history")
	}
	defer rows.Close()
	out := []protocol.Logon{}
	for rows.Next() {
		var l protocol.Logon
		var record int64
		if rows.Scan(&l.Time, &record, &l.User, &l.Domain, &l.SID, &l.Type, &l.SourceIP, &l.SourcePort, &l.Workstation, &l.AuthPackage, &l.LogonProcess, &l.LogonID, &l.Elevated) != nil || record <= 0 {
			return nil, false, errors.New("cannot read logon history")
		}
		l.RecordID = uint64(record)
		out = append(out, l)
	}
	if e = rows.Err(); e != nil {
		return nil, false, errors.New("cannot read logon history")
	}
	if len(out) > LogonHistoryPage {
		return out[:LogonHistoryPage], true, nil
	}
	return out, false, nil
}

// PruneLogonHistory removes logons past retention and keeps the overall table
// within its cap.
func (s *Store) PruneLogonHistory(ctx context.Context, now time.Time) error {
	if _, e := s.db.ExecContext(ctx, `DELETE FROM logon_history WHERE logon_at<=?`, now.Add(-LogonHistoryDays*24*time.Hour).Unix()); e != nil {
		return errors.New("cannot prune logon history")
	}
	if _, e := s.db.ExecContext(ctx, `DELETE FROM logon_history WHERE rowid IN (SELECT rowid FROM logon_history ORDER BY logon_at ASC LIMIT max(0,(SELECT COUNT(*) FROM logon_history)-?))`, logonGlobalHistoryLimit); e != nil {
		return errors.New("cannot prune logon history")
	}
	return nil
}
