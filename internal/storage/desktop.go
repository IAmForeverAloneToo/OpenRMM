package storage

import (
	"context"
	"database/sql"
	"time"
)

// CheckDesktopAuthorization does not refresh browser inactivity on agent polls.
func (s *Store) CheckDesktopAuthorization(ctx context.Context, device, owner string, now time.Time) error {
	var n int
	e := s.db.QueryRowContext(ctx, `SELECT 1 FROM devices d, sessions s JOIN administrators a ON a.id=s.administrator_id
	 WHERE d.id=? AND d.revoked_at IS NULL AND s.token_hash=? AND s.credential_version=a.credential_version
	 AND s.technician_id IS NULL AND a.mfa_confirmed=1 AND s.expires_at>? AND s.last_seen_at>?`, device, owner, now.Unix(), now.Add(-30*time.Minute).Unix()).Scan(&n)
	if e == sql.ErrNoRows {
		v, err := technicianSession(ctx, s.db, owner, now)
		if err != nil {
			return err
		}
		return s.AuthorizeDevice(ctx, v, device, "desktop")
	}
	return e
}
func (s *Store) AuditDesktop(ctx context.Context, actor, action, target, outcome string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = auditDevice(ctx, tx, now, actor, action, target, outcome); e != nil {
		return e
	}
	return tx.Commit()
}
