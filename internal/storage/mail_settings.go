package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// MailSettings is the alert e-mail configuration set in the dashboard. The
// password is kept only as ciphertext; callers decrypt it with the server's
// encryption key.
type MailSettings struct {
	Enabled        bool     `json:"enabled"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	TLS            string   `json:"tls"`
	Username       string   `json:"username"`
	PasswordCipher []byte   `json:"-"`
	From           string   `json:"from"`
	To             []string `json:"to"`
	ServerURL      string   `json:"server_url"`
	UpdatedAt      *int64   `json:"updated_at"`
	Revision       int64    `json:"revision"`
}

// ErrMailSettingsChanged means the settings changed since they were read.
var ErrMailSettingsChanged = errors.New("the e-mail settings changed since they were loaded")

func (s *Store) MailSettings(ctx context.Context) (MailSettings, error) {
	var m MailSettings
	var to string
	var updated sql.NullInt64
	e := s.db.QueryRowContext(ctx, "SELECT enabled,host,port,tls,username,password_cipher,from_address,recipients_json,server_url,updated_at,revision FROM mail_settings WHERE id=1").
		Scan(&m.Enabled, &m.Host, &m.Port, &m.TLS, &m.Username, &m.PasswordCipher, &m.From, &to, &m.ServerURL, &updated, &m.Revision)
	if e != nil || json.Unmarshal([]byte(to), &m.To) != nil {
		return MailSettings{}, errors.New("cannot read the e-mail settings")
	}
	if updated.Valid {
		m.UpdatedAt = &updated.Int64
	}
	if m.To == nil {
		m.To = []string{}
	}
	return m, nil
}

// SetMailSettings stores already validated settings when the revision still
// matches. The ciphertext replaces the stored password as given (nil clears
// it).
func (s *Store) SetMailSettings(ctx context.Context, m MailSettings, actor string, now time.Time) error {
	to, _ := json.Marshal(m.To)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return errors.New("cannot begin the e-mail settings change")
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(ctx, "UPDATE mail_settings SET enabled=?,host=?,port=?,tls=?,username=?,password_cipher=?,from_address=?,recipients_json=?,server_url=?,updated_at=?,revision=revision+1 WHERE id=1 AND revision=?",
		m.Enabled, m.Host, m.Port, m.TLS, m.Username, m.PasswordCipher, m.From, string(to), m.ServerURL, now.Unix(), m.Revision)
	if e != nil {
		return errors.New("cannot store the e-mail settings")
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrMailSettingsChanged
	}
	if e = audit(ctx, tx, now, actor, "email_settings_changed", "success"); e != nil {
		return e
	}
	return tx.Commit()
}

// AuditMailTest records a test message sent from the e-mail settings.
func (s *Store) AuditMailTest(ctx context.Context, actor, outcome string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = audit(ctx, tx, now, actor, "email_test_sent", outcome); e != nil {
		return e
	}
	return tx.Commit()
}

// UseMailConfig switches alert e-mail to another configuration (an empty ID
// turns it off). Notices queued for a different configuration are cancelled
// rather than sent with settings they were not queued for.
func (s *Store) UseMailConfig(ctx context.Context, id string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return errors.New("cannot begin the e-mail configuration change")
	}
	defer tx.Rollback()
	var current string
	if e = tx.QueryRowContext(ctx, "SELECT mail_config FROM alert_runtime WHERE id=1").Scan(&current); e != nil {
		return errors.New("cannot read the e-mail configuration")
	}
	if current == id {
		return nil
	}
	if _, e = tx.ExecContext(ctx, "UPDATE alert_deliveries SET status='cancelled',finished_at=?,reason='configuration_changed' WHERE status='queued' AND config_id<>?", now.Unix(), id); e != nil {
		return errors.New("cannot cancel queued e-mail")
	}
	if _, e = tx.ExecContext(ctx, "UPDATE alert_runtime SET mail_config=? WHERE id=1", id); e != nil {
		return errors.New("cannot store the e-mail configuration")
	}
	return tx.Commit()
}
