package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNoAdministrator   = errors.New("administrator is not configured")
	ErrAlreadyConfigured = errors.New("administrator is already configured; use local reset for recovery")
	ErrAuthentication    = errors.New("authentication failed")
	// ErrDeviceRevoked is an authentication failure for a device identity that an
	// administrator revoked; it matches ErrAuthentication too.
	ErrDeviceRevoked = fmt.Errorf("%w: device revoked", ErrAuthentication)
)

type Administrator struct {
	Username     string
	PasswordHash string
	TOTPCipher   []byte
	Confirmed    bool
	LastStep     int64
	Version      int64
}

type Session struct {
	Technician *Technician
	TokenHash  string
	Username   string
	CSRF       string
	Version    int64
	CreatedAt  int64
	ExpiresAt  int64
	LastSeenAt int64
}

func (s *Store) Administrator(ctx context.Context) (Administrator, error) {
	var admin Administrator
	err := s.db.QueryRowContext(ctx, "SELECT username, password_hash, totp_cipher, mfa_confirmed, last_totp_step, credential_version FROM administrators WHERE id=1").Scan(&admin.Username, &admin.PasswordHash, &admin.TOTPCipher, &admin.Confirmed, &admin.LastStep, &admin.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return Administrator{}, ErrNoAdministrator
	}
	if err != nil {
		return Administrator{}, errors.New("cannot read administrator configuration")
	}
	return admin, nil
}

func audit(ctx context.Context, tx *sql.Tx, now time.Time, actor, action, outcome string) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events (occurred_at, actor, action, outcome) VALUES (?, ?, ?, ?)", now.UTC().Format(time.RFC3339Nano), actor, action, outcome); err != nil {
		return errors.New("cannot record audit event")
	}
	// Live response steps without a case (live_*) are their only record and
	// are kept for a year instead (see SweepEvidence).
	_, err := tx.ExecContext(ctx, "DELETE FROM audit_events WHERE id <= (SELECT COALESCE(MAX(id), 0) - 1000 FROM audit_events) AND action NOT LIKE 'live\\_%' ESCAPE '\\'")
	if err != nil {
		return errors.New("cannot bound audit history")
	}
	return nil
}

func (s *Store) SetAdministrator(ctx context.Context, admin Administrator, codes []string, reset bool, now time.Time) error {
	return s.setAdministrator(ctx, admin, codes, reset, false, now)
}

// ReplaceUnconfirmedAdministrator redoes a first-administrator setup that was
// started from the setup link but never confirmed. It refuses,
// inside the same transaction, once the administrator is confirmed.
func (s *Store) ReplaceUnconfirmedAdministrator(ctx context.Context, admin Administrator, codes []string, now time.Time) error {
	return s.setAdministrator(ctx, admin, codes, true, true, now)
}

func (s *Store) setAdministrator(ctx context.Context, admin Administrator, codes []string, reset, unconfirmedOnly bool, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin administrator setup")
	}
	defer tx.Rollback()
	var technicianNames int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM technicians WHERE username=?", admin.Username).Scan(&technicianNames); err != nil || technicianNames != 0 {
		return ErrAlreadyConfigured
	}
	var version int64
	var confirmed bool
	err = tx.QueryRowContext(ctx, "SELECT credential_version,mfa_confirmed FROM administrators WHERE id=1").Scan(&version, &confirmed)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return errors.New("cannot read administrator setup state")
	}
	exists := err == nil
	if exists && !reset {
		return ErrAlreadyConfigured
	}
	if !exists && reset {
		return ErrNoAdministrator
	}
	if unconfirmedOnly && confirmed {
		return ErrAlreadyConfigured
	}
	if exists {
		if _, err := tx.ExecContext(ctx, "UPDATE technicians SET enabled=0,revision=revision+1,invitation_hash=NULL,invitation_until=NULL"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
			return errors.New("cannot invalidate administrator sessions")
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM recovery_codes"); err != nil {
			return errors.New("cannot replace recovery codes")
		}
		_, err = tx.ExecContext(ctx, "UPDATE administrators SET username=?, password_hash=?, totp_cipher=?, mfa_confirmed=0, last_totp_step=-1, credential_version=? WHERE id=1", admin.Username, admin.PasswordHash, admin.TOTPCipher, version+1)
	} else {
		_, err = tx.ExecContext(ctx, "INSERT INTO administrators (id, username, password_hash, totp_cipher, mfa_confirmed, last_totp_step, credential_version) VALUES (1, ?, ?, ?, 0, -1, 1)", admin.Username, admin.PasswordHash, admin.TOTPCipher)
	}
	if err != nil {
		return errors.New("cannot write administrator configuration")
	}
	for _, code := range codes {
		if _, err := tx.ExecContext(ctx, "INSERT INTO recovery_codes (code_hash, administrator_id) VALUES (?, 1)", code); err != nil {
			return errors.New("cannot store recovery code hashes")
		}
	}
	action := "administrator_setup"
	if reset {
		action = "administrator_reset"
	}
	if err := audit(ctx, tx, now, "local-operator", action, "success"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit administrator setup")
	}
	return nil
}

func (s *Store) ConfirmAdministrator(ctx context.Context, version, step int64, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin MFA confirmation")
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE administrators SET mfa_confirmed=1, last_totp_step=? WHERE id=1 AND credential_version=? AND mfa_confirmed=0 AND last_totp_step<?", step, version, step)
	if err != nil {
		return errors.New("cannot confirm MFA")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrAuthentication
	}
	if err := audit(ctx, tx, now, "local-operator", "administrator_mfa_confirmation", "success"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit MFA confirmation")
	}
	return nil
}

// CompleteLogin consumes a factor and creates the session in one transaction.
// The version check prevents a concurrent local reset from accepting old factors.
func (s *Store) CompleteLogin(ctx context.Context, version, step int64, recoveryHash string, session Session, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin authenticated session")
	}
	defer tx.Rollback()
	var currentVersion int64
	var confirmed bool
	if err := tx.QueryRowContext(ctx, "SELECT credential_version, mfa_confirmed FROM administrators WHERE id=1").Scan(&currentVersion, &confirmed); err != nil {
		return ErrAuthentication
	}
	if currentVersion != version || !confirmed {
		return ErrAuthentication
	}
	var result sql.Result
	if recoveryHash != "" {
		result, err = tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE administrator_id=1 AND code_hash=?", recoveryHash)
	} else {
		result, err = tx.ExecContext(ctx, "UPDATE administrators SET last_totp_step=? WHERE id=1 AND last_totp_step<?", step, step)
	}
	if err != nil {
		return errors.New("cannot consume authentication factor")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrAuthentication
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=? OR last_seen_at<=?", now.Unix(), now.Add(-30*time.Minute).Unix()); err != nil {
		return errors.New("cannot expire old sessions")
	}
	// Bound concurrent sessions as well as expired state for this single account.
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE technician_id IS NULL ORDER BY created_at DESC, token_hash LIMIT -1 OFFSET 15)"); err != nil {
		return errors.New("cannot bound active sessions")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO sessions (token_hash, administrator_id, csrf_token, credential_version, created_at, expires_at, last_seen_at) VALUES (?, 1, ?, ?, ?, ?, ?)", session.TokenHash, session.CSRF, version, session.CreatedAt, session.ExpiresAt, session.LastSeenAt); err != nil {
		return errors.New("cannot create authenticated session")
	}
	if err := audit(ctx, tx, now, "administrator", "login", "success"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit authenticated session")
	}
	return nil
}

func (s *Store) Session(ctx context.Context, tokenHash string, now time.Time) (Session, error) {
	var session Session
	err := s.db.QueryRowContext(ctx, `SELECT s.token_hash, a.username, s.csrf_token, s.credential_version, s.created_at, s.expires_at, s.last_seen_at
        FROM sessions s JOIN administrators a ON a.id=s.administrator_id
        WHERE s.token_hash=? AND s.technician_id IS NULL AND s.credential_version=a.credential_version AND a.mfa_confirmed=1
        AND s.expires_at>? AND s.last_seen_at>?`, tokenHash, now.Unix(), now.Add(-30*time.Minute).Unix()).Scan(&session.TokenHash, &session.Username, &session.CSRF, &session.Version, &session.CreatedAt, &session.ExpiresAt, &session.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		session, err = technicianSession(ctx, s.db, tokenHash, now)
	}
	if errors.Is(err, ErrAuthentication) {
		return Session{}, ErrAuthentication
	}
	if err != nil {
		return Session{}, errors.New("cannot verify session")
	}
	// Do not resurrect a row deleted by logout or reset between SELECT and UPDATE.
	result, err := s.db.ExecContext(ctx, "UPDATE sessions SET last_seen_at=? WHERE token_hash=? AND credential_version=?", now.Unix(), tokenHash, session.Version)
	if err != nil {
		return Session{}, errors.New("cannot refresh session activity")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return Session{}, ErrAuthentication
	}
	return session, nil
}

func (s *Store) Logout(ctx context.Context, tokenHash string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin logout")
	}
	defer tx.Rollback()
	actor := "administrator"
	var technician *string
	if err := tx.QueryRowContext(ctx, "SELECT technician_id FROM sessions WHERE token_hash=?", tokenHash).Scan(&technician); err == nil && technician != nil {
		actor = "technician:" + *technician
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", tokenHash); err != nil {
		return errors.New("cannot revoke session")
	}
	if err := audit(ctx, tx, now, actor, "logout", "success"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit logout")
	}
	return nil
}

func (s *Store) AuditLoginFailure(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin audit event")
	}
	defer tx.Rollback()
	if err := audit(ctx, tx, now, "anonymous", "login", "failure"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit audit event")
	}
	return nil
}
