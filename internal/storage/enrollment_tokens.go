package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// ErrEnrollmentToken covers token limits, unknown tokens and invalid settings.
var ErrEnrollmentToken = errors.New("enrollment token or installer settings unavailable; reload and try again")

// EnrollmentToken describes a stored token. Only the token's hash
// is kept; the token itself is shown or downloaded once. A single-device token
// is deleted when used; a reusable deployment token counts its devices.
type EnrollmentToken struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Reusable   bool   `json:"reusable"`
	MaxDevices int    `json:"max_devices"`
	Used       int    `json:"used"`
	Actor      string `json:"actor"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
	RevokedAt  *int64 `json:"revoked_at,omitempty"`
}

// InstallerSettings are the public addresses written into downloaded
// installers: the HTTPS origin agents enroll with and the device origin.
type InstallerSettings struct {
	ServerURL string `json:"server_url"`
	DeviceURL string `json:"device_url"`
}

const (
	maxPendingSingleTokens = 100
	maxActiveDeployTokens  = 50
	deployTokenRetention   = 30 * 24 * time.Hour
)

// NewEnrollmentToken stores a single-device token created by the administrator.
func (s *Store) NewEnrollmentToken(ctx context.Context, hash string, now, expires time.Time) error {
	id := sha256.Sum256([]byte(hash))
	return s.AddEnrollmentToken(ctx, hash, EnrollmentToken{ID: hex.EncodeToString(id[:16]), MaxDevices: 1, Actor: "administrator", ExpiresAt: expires.Unix()}, now)
}

func (s *Store) AddEnrollmentToken(ctx context.Context, hash string, t EnrollmentToken, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin enrollment token creation")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM enrollment_tokens WHERE (reusable=0 AND expires_at<=?) OR (reusable=1 AND COALESCE(revoked_at,expires_at)<=?)", now.Unix(), now.Add(-deployTokenRetention).Unix()); err != nil {
		return errors.New("cannot expire enrollment tokens")
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM enrollment_tokens WHERE reusable=? AND expires_at>? AND revoked_at IS NULL", t.Reusable, now.Unix()).Scan(&count); err != nil {
		return errors.New("cannot inspect enrollment tokens")
	}
	if !t.Reusable && count >= maxPendingSingleTokens || t.Reusable && count >= maxActiveDeployTokens {
		return ErrEnrollmentToken
	}
	if t.MaxDevices < 1 || t.MaxDevices > 10000 || !t.Reusable && t.MaxDevices != 1 || len(t.Label) > 80 || t.ID == "" {
		return ErrEnrollmentToken
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO enrollment_tokens(token_hash,created_at,expires_at,id,label,reusable,max_devices,actor) VALUES (?,?,?,?,?,?,?,?)", hash, now.Unix(), t.ExpiresAt, t.ID, t.Label, t.Reusable, t.MaxDevices, t.Actor); err != nil {
		return errors.New("cannot store enrollment token hash")
	}
	action := "enrollment_token_created"
	if t.Reusable {
		action = "deployment_token_created"
	}
	if err := auditDevice(ctx, tx, now, t.Actor, action, t.ID, "success"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit enrollment token")
	}
	return nil
}

// DeploymentTokens lists reusable tokens, newest first, including expired and
// revoked ones within their retention.
func (s *Store) DeploymentTokens(ctx context.Context, now time.Time) ([]EnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,label,reusable,max_devices,used,actor,created_at,expires_at,revoked_at FROM enrollment_tokens WHERE reusable=1 AND COALESCE(revoked_at,expires_at)>? ORDER BY created_at DESC,id LIMIT 200", now.Add(-deployTokenRetention).Unix())
	if err != nil {
		return nil, errors.New("cannot list deployment tokens")
	}
	defer rows.Close()
	items := []EnrollmentToken{}
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.Label, &t.Reusable, &t.MaxDevices, &t.Used, &t.Actor, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt); err != nil {
			return nil, errors.New("cannot decode deployment token")
		}
		items = append(items, t)
	}
	if rows.Err() != nil {
		return nil, errors.New("cannot read deployment tokens")
	}
	return items, nil
}

// RevokeDeploymentToken stops a reusable token; devices it enrolled stay.
func (s *Store) RevokeDeploymentToken(ctx context.Context, id, actor string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin token revocation")
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE enrollment_tokens SET revoked_at=? WHERE id=? AND id<>'' AND reusable=1 AND revoked_at IS NULL", now.Unix(), id)
	if err != nil {
		return errors.New("cannot revoke deployment token")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrEnrollmentToken
	}
	if err := auditDevice(ctx, tx, now, actor, "deployment_token_revoked", id, "success"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) InstallerSettings(ctx context.Context) (InstallerSettings, error) {
	var v InstallerSettings
	if err := s.db.QueryRowContext(ctx, "SELECT server_url,device_url FROM installer_settings WHERE id=1").Scan(&v.ServerURL, &v.DeviceURL); err != nil {
		return InstallerSettings{}, errors.New("cannot read installer settings")
	}
	return v, nil
}

// SetInstallerSettings stores already validated origins.
func (s *Store) SetInstallerSettings(ctx context.Context, v InstallerSettings, actor string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin installer settings change")
	}
	defer tx.Rollback()
	var current InstallerSettings
	if err := tx.QueryRowContext(ctx, "SELECT server_url,device_url FROM installer_settings WHERE id=1").Scan(&current.ServerURL, &current.DeviceURL); err != nil {
		return errors.New("cannot read installer settings")
	}
	if current == v {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "UPDATE installer_settings SET server_url=?,device_url=? WHERE id=1", v.ServerURL, v.DeviceURL); err != nil {
		return errors.New("cannot store installer settings")
	}
	if err := audit(ctx, tx, now, actor, "installer_settings_changed", "success"); err != nil {
		return err
	}
	return tx.Commit()
}

// InitializeInstallerSettings stores the install command's addresses only
// while no addresses are set, so dashboard changes are kept.
func (s *Store) InitializeInstallerSettings(ctx context.Context, v InstallerSettings, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin installer settings change")
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE installer_settings SET server_url=?,device_url=? WHERE id=1 AND server_url='' AND device_url=''", v.ServerURL, v.DeviceURL)
	if err != nil {
		return errors.New("cannot store installer settings")
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return nil
	}
	if err := audit(ctx, tx, now, "install", "installer_settings_changed", "success"); err != nil {
		return err
	}
	return tx.Commit()
}

// consumeEnrollmentToken uses one device of a valid token and returns its ID.
func consumeEnrollmentToken(ctx context.Context, tx *sql.Tx, hash string, now time.Time) (string, error) {
	var id string
	var reusable bool
	err := tx.QueryRowContext(ctx, "SELECT id,reusable FROM enrollment_tokens WHERE token_hash=? AND expires_at>? AND revoked_at IS NULL AND used<max_devices", hash, now.Unix()).Scan(&id, &reusable)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAuthentication
	}
	if err != nil {
		return "", errors.New("cannot read enrollment token")
	}
	query := "DELETE FROM enrollment_tokens WHERE token_hash=? AND reusable=0"
	if reusable {
		query = "UPDATE enrollment_tokens SET used=used+1 WHERE token_hash=? AND reusable=1 AND used<max_devices"
	}
	result, err := tx.ExecContext(ctx, query, hash)
	if err != nil {
		return "", errors.New("cannot consume enrollment token")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return "", ErrAuthentication
	}
	return id, nil
}
