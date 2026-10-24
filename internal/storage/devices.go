package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type Device struct {
	ID                  string `json:"id"`
	Hostname            string `json:"hostname"`
	OS                  string `json:"os"`
	Architecture        string `json:"architecture"`
	EnrolledAt          int64  `json:"enrolled_at"`
	RevokedAt           *int64 `json:"revoked_at,omitempty"`
	LastContactAt       *int64 `json:"last_contact_at"`
	AgentVersion        string `json:"agent_version"`
	Certificate         string `json:"-"`
	Fingerprint         string `json:"-"`
	PreviousFingerprint string `json:"-"`
	PreviousUntil       int64  `json:"-"`
}

func auditDevice(ctx context.Context, tx *sql.Tx, now time.Time, actor, action, target, outcome string) error {
	if err := audit(ctx, tx, now, actor, action, outcome); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE audit_events SET target=? WHERE id=last_insert_rowid()", target); err != nil {
		return errors.New("cannot record device audit target")
	}
	return nil
}
func (s *Store) DeviceAuthority(ctx context.Context) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT fingerprint FROM device_authority WHERE id=1").Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", errors.New("cannot read device authority binding")
	}
	return value, nil
}
func (s *Store) BindDeviceAuthority(ctx context.Context, fingerprint string) error {
	if _, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO device_authority VALUES (1, ?)", fingerprint); err != nil {
		return errors.New("cannot bind device authority")
	}
	bound, err := s.DeviceAuthority(ctx)
	if err != nil || bound != fingerprint {
		return errors.New("device authority does not match database; restore the matching CA backup")
	}
	return nil
}
func (s *Store) EnrollDevice(ctx context.Context, hash string, device Device, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin device enrollment")
	}
	defer tx.Rollback()
	token, err := consumeEnrollmentToken(ctx, tx, hash, now)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO devices (id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint,enrollment_token_id) VALUES (?,?,?,?,?,?,?,?)", device.ID, device.Hostname, device.OS, device.Architecture, now.Unix(), device.Certificate, device.Fingerprint, token); err != nil {
		return errors.New("cannot store enrolled device")
	}
	if err := auditDevice(ctx, tx, now, "device:"+device.ID, "device_enrolled", device.ID, "success"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit device enrollment")
	}
	return nil
}
func (s *Store) Devices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,hostname,os,architecture,enrolled_at,revoked_at,last_contact_at,agent_version FROM devices ORDER BY enrolled_at DESC,id LIMIT 1000")
	if err != nil {
		return nil, errors.New("cannot list devices")
	}
	defer rows.Close()
	devices := make([]Device, 0)
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.OS, &d.Architecture, &d.EnrolledAt, &d.RevokedAt, &d.LastContactAt, &d.AgentVersion); err != nil {
			return nil, errors.New("cannot decode device record")
		}
		devices = append(devices, d)
	}
	if rows.Err() != nil {
		return nil, errors.New("cannot read complete device list")
	}
	return devices, nil
}
func (s *Store) ActiveDevice(ctx context.Context, id, fingerprint string, now time.Time) (Device, error) {
	var d Device
	err := s.db.QueryRowContext(ctx, `SELECT id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint,previous_fingerprint,previous_until FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))`, id, fingerprint, fingerprint, now.Unix()).Scan(&d.ID, &d.Hostname, &d.OS, &d.Architecture, &d.EnrolledAt, &d.Certificate, &d.Fingerprint, &d.PreviousFingerprint, &d.PreviousUntil)
	if errors.Is(err, sql.ErrNoRows) {
		var revoked int
		if s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NOT NULL", id).Scan(&revoked) == nil && revoked > 0 {
			return Device{}, ErrDeviceRevoked
		}
		return Device{}, ErrAuthentication
	}
	if err != nil {
		return Device{}, errors.New("cannot authenticate device")
	}
	return d, nil
}
func (s *Store) RenewDevice(ctx context.Context, id, oldFingerprint, newFingerprint, cert string, now time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", errors.New("cannot begin device renewal")
	}
	defer tx.Rollback()
	var current, previous, persisted string
	var until int64
	err = tx.QueryRowContext(ctx, "SELECT fingerprint,previous_fingerprint,previous_until,certificate_pem FROM devices WHERE id=? AND revoked_at IS NULL", id).Scan(&current, &previous, &until, &persisted)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAuthentication
	}
	if err != nil {
		return "", errors.New("cannot inspect renewal state")
	}
	if oldFingerprint == previous && until > now.Unix() {
		return persisted, nil
	} // Lost-response retry within bounded overlap.
	if current != oldFingerprint {
		return "", ErrAuthentication
	}
	if _, err := tx.ExecContext(ctx, "UPDATE devices SET previous_fingerprint=fingerprint,previous_until=?,fingerprint=?,certificate_pem=? WHERE id=?", now.Add(5*time.Minute).Unix(), newFingerprint, cert, id); err != nil {
		return "", errors.New("cannot store renewed certificate")
	}
	if err := auditDevice(ctx, tx, now, "device:"+id, "device_certificate_renewed", id, "success"); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", errors.New("cannot commit device renewal")
	}
	return cert, nil
}
func (s *Store) RevokeDevice(ctx context.Context, id string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin device revocation")
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL", now.Unix(), id)
	if err != nil {
		return errors.New("cannot revoke device")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrAuthentication
	}
	if err := auditDevice(ctx, tx, now, "administrator", "device_revoked", id, "success"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit revocation")
	}
	return nil
}
func (s *Store) AuditEnrollmentFailure(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin enrollment audit")
	}
	defer tx.Rollback()
	if err := auditDevice(ctx, tx, now, "anonymous", "device_enrollment", "", "failure"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit enrollment audit")
	}
	return nil
}
