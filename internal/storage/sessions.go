package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sessions"
)

// Observed session history bounds (365 days).
const (
	SessionHistoryDays        = 365
	SessionHistoryLimit       = 2000
	sessionGlobalHistoryLimit = 500000
	SessionHistoryPage        = 500
	signedInFreshness         = 5 * time.Minute
)

type Sessions struct {
	Capability protocol.Capability `json:"capability"`
	Status     string              `json:"status"`
	ReportedAt int64               `json:"reported_at"`
	SnapshotAt *int64              `json:"snapshot_at"`
	Data       *protocol.Sessions  `json:"data"`
}

// SessionRecord is one observed session: first and last seen by the agent and
// when it was gone (nil while it is still reported).
type SessionRecord struct {
	ID          int64            `json:"id"`
	Session     protocol.Session `json:"session"`
	FirstSeenAt int64            `json:"first_seen_at"`
	LastSeenAt  int64            `json:"last_seen_at"`
	EndedAt     *int64           `json:"ended_at"`
}

func sessionKey(v protocol.Session) string {
	return fmt.Sprintf("%d|%s|%s|%d", v.ID, v.Domain, v.User, v.LogonAt)
}
func sessionsError() error { return errors.New("cannot persist signed-in sessions") }

// RecordSessions stores the newest report and, for an "ok" report, updates the
// observed history in the same transaction after repeating device
// authorization. Out-of-order and failed reports leave the history unchanged.
func (s *Store) RecordSessions(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	report, e := sessions.Normalize(report)
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return errors.New("cannot begin sessions report")
	}
	defer tx.Rollback()
	var allowed int
	if e = tx.QueryRowContext(ctx, `SELECT 1 FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))`, id, fingerprint, fingerprint, now.Unix()).Scan(&allowed); errors.Is(e, sql.ErrNoRows) {
		return ErrAuthentication
	} else if e != nil {
		return errors.New("cannot authenticate sessions report")
	}
	var last int64
	if e = tx.QueryRowContext(ctx, `SELECT reported_at FROM device_sessions WHERE device_id=?`, id).Scan(&last); e != nil && !errors.Is(e, sql.ErrNoRows) {
		return sessionsError()
	}
	if now.Unix() < last {
		return nil
	}
	var snapshotAt any
	if report.Status == "ok" {
		snapshotAt = now.Unix()
		var v protocol.Sessions
		if json.Unmarshal(report.Data, &v) != nil {
			return sessionsError()
		}
		for _, x := range v.Sessions {
			b, _ := json.Marshal(x)
			if _, e = tx.ExecContext(ctx, `INSERT INTO session_history(device_id,session_key,user_name,domain,session_json,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?)
 ON CONFLICT(device_id,session_key) DO UPDATE SET session_json=excluded.session_json,last_seen_at=excluded.last_seen_at,ended_at=NULL`, id, sessionKey(x), x.User, x.Domain, string(b), now.Unix(), now.Unix()); e != nil {
				return sessionsError()
			}
		}
		// Sessions no longer reported were gone by now.
		if _, e = tx.ExecContext(ctx, `UPDATE session_history SET ended_at=? WHERE device_id=? AND ended_at IS NULL AND last_seen_at<?`, now.Unix(), id, now.Unix()); e != nil {
			return sessionsError()
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM session_history WHERE device_id=? AND id NOT IN (SELECT id FROM session_history WHERE device_id=? ORDER BY last_seen_at DESC,id DESC LIMIT ?)`, id, id, SessionHistoryLimit); e != nil {
			return sessionsError()
		}
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO device_sessions(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at) VALUES(?,?,?,?,?,?)
 ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,reported_at=excluded.reported_at,
 snapshot_json=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_json ELSE device_sessions.snapshot_json END,
 snapshot_at=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_at ELSE device_sessions.snapshot_at END`, id, report.Capability.Version, report.Status, now.Unix(), string(report.Data), snapshotAt)
	if e != nil {
		return sessionsError()
	}
	if tx.Commit() != nil {
		return sessionsError()
	}
	return nil
}

func (s *Store) Sessions(ctx context.Context, id string) (Sessions, error) {
	v := Sessions{Capability: sessions.Capability, Status: "not_reported"}
	var data string
	e := s.db.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,snapshot_json,snapshot_at FROM device_sessions WHERE device_id=?`, id).Scan(&v.Capability.Version, &v.Status, &v.ReportedAt, &data, &v.SnapshotAt)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	if e != nil {
		return v, errors.New("cannot read signed-in sessions")
	}
	if data != "" {
		v.Data = new(protocol.Sessions)
		if json.Unmarshal([]byte(data), v.Data) != nil || !sessions.Valid(*v.Data) {
			return v, errors.New("cannot decode signed-in sessions")
		}
	}
	return v, nil
}

// SessionHistory returns the newest observed sessions within retention.
func (s *Store) SessionHistory(ctx context.Context, id string, now time.Time) ([]SessionRecord, error) {
	out := []SessionRecord{}
	rows, e := s.db.QueryContext(ctx, `SELECT id,session_json,first_seen_at,last_seen_at,ended_at FROM session_history WHERE device_id=? AND last_seen_at>? ORDER BY last_seen_at DESC,id DESC LIMIT ?`, id, now.Add(-SessionHistoryDays*24*time.Hour).Unix(), SessionHistoryPage)
	if e != nil {
		return nil, errors.New("cannot read session history")
	}
	defer rows.Close()
	for rows.Next() {
		var r SessionRecord
		var raw string
		if rows.Scan(&r.ID, &raw, &r.FirstSeenAt, &r.LastSeenAt, &r.EndedAt) != nil || json.Unmarshal([]byte(raw), &r.Session) != nil || !sessions.SessionValid(r.Session) {
			return nil, errors.New("cannot decode session history")
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SignedInUsers maps devices to the users of their active sessions, from
// reports no older than five minutes ("DOMAIN\user", or "user").
func (s *Store) SignedInUsers(ctx context.Context, now time.Time) (map[string][]string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT device_id,snapshot_json FROM device_sessions WHERE last_status='ok' AND snapshot_at>?`, now.Add(-signedInFreshness).Unix())
	if e != nil {
		return nil, errors.New("cannot read signed-in users")
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, raw string
		var v protocol.Sessions
		if rows.Scan(&id, &raw) != nil || json.Unmarshal([]byte(raw), &v) != nil || !sessions.Valid(v) {
			return nil, errors.New("cannot decode signed-in users")
		}
		for _, x := range v.Sessions {
			if x.State != "active" {
				continue
			}
			name := x.User
			if x.Domain != "" {
				name = x.Domain + `\` + x.User
			}
			out[id] = append(out[id], name)
		}
	}
	return out, rows.Err()
}

// PruneSessionHistory removes observed sessions past retention and keeps the
// overall table within its cap.
func (s *Store) PruneSessionHistory(ctx context.Context, now time.Time) error {
	if _, e := s.db.ExecContext(ctx, `DELETE FROM session_history WHERE last_seen_at<=?`, now.Add(-SessionHistoryDays*24*time.Hour).Unix()); e != nil {
		return errors.New("cannot prune session history")
	}
	if _, e := s.db.ExecContext(ctx, `DELETE FROM session_history WHERE id IN (SELECT id FROM session_history ORDER BY last_seen_at ASC,id ASC LIMIT max(0,(SELECT COUNT(*) FROM session_history)-?))`, sessionGlobalHistoryLimit); e != nil {
		return errors.New("cannot prune session history")
	}
	return nil
}
