package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// BackupSettings schedules the nightly backup taken by the updater sidecar.
type BackupSettings struct {
	Enabled   bool   `json:"enabled"`
	Hour      int    `json:"hour"` // UTC
	UpdatedAt *int64 `json:"updated_at"`
	Revision  int64  `json:"revision"`
}

// ErrBackupSettingsChanged means the settings changed since they were read.
var ErrBackupSettingsChanged = errors.New("the backup settings changed since they were loaded")

func (s *Store) BackupSettings(ctx context.Context) (BackupSettings, error) {
	var b BackupSettings
	var updated sql.NullInt64
	if e := s.db.QueryRowContext(ctx, "SELECT enabled,hour,updated_at,revision FROM backup_settings WHERE id=1").Scan(&b.Enabled, &b.Hour, &updated, &b.Revision); e != nil {
		return BackupSettings{}, errors.New("cannot read the backup settings")
	}
	if updated.Valid {
		b.UpdatedAt = &updated.Int64
	}
	return b, nil
}

// SetBackupSettings stores the schedule when the revision still matches.
func (s *Store) SetBackupSettings(ctx context.Context, b BackupSettings, actor string, now time.Time) error {
	if b.Hour < 0 || b.Hour > 23 {
		return errors.New("invalid backup hour")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return errors.New("cannot begin the backup settings change")
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(ctx, "UPDATE backup_settings SET enabled=?,hour=?,updated_at=?,revision=revision+1 WHERE id=1 AND revision=?", b.Enabled, b.Hour, now.Unix(), b.Revision)
	if e != nil {
		return errors.New("cannot store the backup settings")
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrBackupSettingsChanged
	}
	if e = audit(ctx, tx, now, actor, "backup_settings_changed", "success"); e != nil {
		return e
	}
	return tx.Commit()
}

// AuditBackupRequest records a backup requested from the dashboard.
func (s *Store) AuditBackupRequest(ctx context.Context, actor, outcome string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = audit(ctx, tx, now, actor, "backup_requested", outcome); e != nil {
		return e
	}
	return tx.Commit()
}
