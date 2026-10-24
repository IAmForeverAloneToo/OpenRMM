package storage

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

// First-administrator setup link. The install command creates
// it on the server; the browser uses it to create the administrator.

// ErrSetupLink: the link is unknown, expired, used, or an administrator
// already exists.
var ErrSetupLink = errors.New("the setup link is not valid; create a new one with the install command")

// administratorConfirmed reports whether a working administrator exists.
func administratorConfirmed(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (bool, error) {
	var confirmed bool
	e := q.QueryRowContext(ctx, "SELECT mfa_confirmed FROM administrators WHERE id=1").Scan(&confirmed)
	if errors.Is(e, sql.ErrNoRows) {
		return false, nil
	}
	return confirmed, e
}

// AdministratorConfirmed reports whether the first administrator exists.
func (s *Store) AdministratorConfirmed(ctx context.Context) (bool, error) {
	return administratorConfirmed(ctx, s.db)
}

// NewSetupLink stores a new link's hash, replacing an earlier one; refused
// once an administrator exists.
func (s *Store) NewSetupLink(ctx context.Context, hash string, expires, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if done, e := administratorConfirmed(ctx, tx); e != nil {
		return e
	} else if done {
		return ErrAlreadyConfigured
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO setup_links(id,token_hash,expires_at,used_at) VALUES(1,?,?,NULL) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at,used_at=NULL`, hash, expires.Unix()); e != nil {
		return e
	}
	if e = audit(ctx, tx, now, "local-operator", "setup_link_created", "success"); e != nil {
		return e
	}
	return tx.Commit()
}

// CheckSetupLink accepts the link with this hash while it is unexpired and
// unused and no administrator exists.
func (s *Store) CheckSetupLink(ctx context.Context, hash string, now time.Time) error {
	var stored string
	var expires int64
	var used sql.NullInt64
	e := s.db.QueryRowContext(ctx, `SELECT token_hash,expires_at,used_at FROM setup_links WHERE id=1`).Scan(&stored, &expires, &used)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrSetupLink
	}
	if e != nil {
		return e
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 || now.Unix() >= expires || used.Valid {
		return ErrSetupLink
	}
	if done, e := administratorConfirmed(ctx, s.db); e != nil {
		return e
	} else if done {
		return ErrSetupLink
	}
	return nil
}

// UseSetupLink marks the link used once the administrator is confirmed.
func (s *Store) UseSetupLink(ctx context.Context, hash string, now time.Time) error {
	_, e := s.db.ExecContext(ctx, `UPDATE setup_links SET used_at=? WHERE id=1 AND token_hash=? AND used_at IS NULL`, now.Unix(), hash)
	return e
}
