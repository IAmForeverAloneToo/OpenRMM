package storage

import (
	"context"
	"database/sql"
	"time"
)

// The terminal (the live response console) runs as SYSTEM. The
// owner may use it, and technicians with the response permission and access
// to the device.
func (s *Store) CheckTerminalAuthorization(ctx context.Context, device, owner string, now time.Time) error {
	var n int
	e := s.db.QueryRowContext(ctx, `SELECT 1 FROM devices d, sessions s JOIN administrators a ON a.id=s.administrator_id
 WHERE d.id=? AND d.revoked_at IS NULL AND s.token_hash=? AND s.credential_version=a.credential_version
 AND s.technician_id IS NULL AND a.mfa_confirmed=1 AND s.expires_at>? AND s.last_seen_at>?`, device, owner, now.Unix(), now.Add(-30*time.Minute).Unix()).Scan(&n)
	// The terminal is the live response console: technicians
	// with the response permission and access to the device may use it.
	if e == sql.ErrNoRows {
		v, err := technicianSession(ctx, s.db, owner, now)
		if err != nil {
			return err
		}
		return s.AuthorizeDevice(ctx, v, device, "response")
	}
	return e
}
