package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ServerUpdateSettings is the daily check's state.
type ServerUpdateSettings struct {
	CheckEnabled bool   `json:"check_enabled"`
	CheckedAt    *int64 `json:"checked_at"`
	CheckError   string `json:"check_error"`
	// Available is the newest signed release found (JSON), or empty.
	Available string `json:"-"`
}

// ServerUpdate is one update request and its outcome.
type ServerUpdate struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Sequence    int64  `json:"sequence"`
	FromVersion string `json:"from_version"`
	RequestedBy string `json:"requested_by"`
	RequestedAt int64  `json:"requested_at"`
	Phase       string `json:"phase"`
	Detail      string `json:"detail"`
	Backup      string `json:"backup"`
	FinishedAt  *int64 `json:"finished_at"`
}

// ErrServerUpdate is an update request that conflicts with another.
var ErrServerUpdate = errors.New("a server update is already in progress")

func (s *Store) ServerUpdateSettings(ctx context.Context) (ServerUpdateSettings, error) {
	var v ServerUpdateSettings
	var checked sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT check_enabled,checked_at,check_error,available_json FROM server_update_settings WHERE id=1").Scan(&v.CheckEnabled, &checked, &v.CheckError, &v.Available); err != nil {
		return ServerUpdateSettings{}, errors.New("cannot read server update settings")
	}
	if checked.Valid {
		v.CheckedAt = &checked.Int64
	}
	return v, nil
}

// SetServerUpdateCheck turns the daily check on or off.
func (s *Store) SetServerUpdateCheck(ctx context.Context, enabled bool, actor string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin server update settings change")
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE server_update_settings SET check_enabled=? WHERE id=1 AND check_enabled<>?", enabled, enabled)
	if err != nil {
		return errors.New("cannot store server update settings")
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return nil
	}
	action := "server_update_check_disabled"
	if enabled {
		action = "server_update_check_enabled"
	}
	if err := audit(ctx, tx, now, actor, action, "success"); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordServerUpdateCheck stores a check's result: the release found (JSON,
// already verified by the caller) or an empty string, and a short error.
func (s *Store) RecordServerUpdateCheck(ctx context.Context, available, checkError string, now time.Time) error {
	if len(checkError) > 300 {
		checkError = checkError[:300]
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE server_update_settings SET checked_at=?,check_error=?,available_json=? WHERE id=1", now.Unix(), checkError, available); err != nil {
		return errors.New("cannot store the update check")
	}
	return nil
}

// StartServerUpdate records a request handed to the updater. Only one may be
// unfinished at a time; requests the updater never answered for an hour do
// not block a new one.
func (s *Store) StartServerUpdate(ctx context.Context, u ServerUpdate, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin server update")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE server_updates SET phase='failed',detail='The updater did not answer.',finished_at=? WHERE finished_at IS NULL AND requested_at<?", now.Unix(), now.Add(-time.Hour).Unix()); err != nil {
		return errors.New("cannot close stale server updates")
	}
	var open int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM server_updates WHERE finished_at IS NULL").Scan(&open); err != nil {
		return errors.New("cannot read server updates")
	}
	if open > 0 {
		return ErrServerUpdate
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO server_updates(id,version,sequence,from_version,requested_by,requested_at,phase) VALUES (?,?,?,?,?,?,'requested')", u.ID, u.Version, u.Sequence, u.FromVersion, u.RequestedBy, now.Unix()); err != nil {
		return errors.New("cannot store the server update")
	}
	if err := audit(ctx, tx, now, u.RequestedBy, "server_update_requested", "success"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM server_updates WHERE id NOT IN (SELECT id FROM server_updates ORDER BY requested_at DESC LIMIT 100)"); err != nil {
		return errors.New("cannot bound server update history")
	}
	return tx.Commit()
}

// CancelServerUpdate closes a request the updater could not be given.
func (s *Store) CancelServerUpdate(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE server_updates SET phase='failed',detail='The request could not be handed to the updater.',finished_at=? WHERE id=? AND finished_at IS NULL", now.Unix(), id)
	return err
}

// ApplyServerUpdateStatus copies the updater's progress into the history
// and audits the outcome once.
func (s *Store) ApplyServerUpdateStatus(ctx context.Context, id, phase, detail, backup string, done bool, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin server update status")
	}
	defer tx.Rollback()
	var finished sql.NullInt64
	var current, actor string
	if err := tx.QueryRowContext(ctx, "SELECT phase,finished_at,requested_by FROM server_updates WHERE id=?", id).Scan(&current, &finished, &actor); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return errors.New("cannot read server update")
	}
	if finished.Valid || current == phase {
		return nil
	}
	var end any
	if done {
		end = now.Unix()
	}
	if _, err := tx.ExecContext(ctx, "UPDATE server_updates SET phase=?,detail=?,backup=?,finished_at=? WHERE id=?", phase, detail, backup, end, id); err != nil {
		return errors.New("cannot store server update status")
	}
	if done {
		outcome := "success"
		if phase != "succeeded" {
			outcome = phase
		}
		if err := audit(ctx, tx, now, actor, "server_update_finished", outcome); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ServerUpdates lists recent update requests, newest first.
func (s *Store) ServerUpdates(ctx context.Context) ([]ServerUpdate, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,version,sequence,from_version,requested_by,requested_at,phase,detail,backup,finished_at FROM server_updates ORDER BY requested_at DESC,id LIMIT 20")
	if err != nil {
		return nil, errors.New("cannot list server updates")
	}
	defer rows.Close()
	out := []ServerUpdate{}
	for rows.Next() {
		var u ServerUpdate
		var finished sql.NullInt64
		if err := rows.Scan(&u.ID, &u.Version, &u.Sequence, &u.FromVersion, &u.RequestedBy, &u.RequestedAt, &u.Phase, &u.Detail, &u.Backup, &finished); err != nil {
			return nil, errors.New("cannot decode server update")
		}
		if finished.Valid {
			u.FinishedAt = &finished.Int64
		}
		out = append(out, u)
	}
	if rows.Err() != nil {
		return nil, errors.New("cannot read server updates")
	}
	return out, nil
}
