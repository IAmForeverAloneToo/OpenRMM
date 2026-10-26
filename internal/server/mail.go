package server

import (
	"context"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/auth"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

const smtpPasswordPurpose = "smtp-password"

// mailSource is the alert e-mail configuration in use: the protected SMTP
// file when the server was started with one, otherwise the dashboard's
// e-mail settings.
type mailSource struct {
	store *storage.Store
	auth  *auth.Service
	file  *alerting.Mailer

	mu       sync.Mutex
	mailer   *alerting.Mailer // dashboard settings; nil when off or unusable
	lastTest time.Time
}

// mailConfig is the configuration stored settings describe, without the
// password.
func mailConfig(m storage.MailSettings) alerting.MailConfig {
	return alerting.MailConfig{Host: m.Host, Port: m.Port, TLS: m.TLS, Username: m.Username, From: m.From, To: m.To, ServerURL: m.ServerURL}
}

// storedMailID is the configuration ID of enabled dashboard settings,
// computed without decrypting the password, so queued notices survive a
// restart.
func storedMailID(ctx context.Context, s *storage.Store) (string, error) {
	m, e := s.MailSettings(ctx)
	if e != nil || !m.Enabled {
		return "", e
	}
	return alerting.ConfigID(mailConfig(m)), nil
}

// Current returns the mailer for queued notices, or nil when e-mail is off.
func (m *mailSource) Current() *alerting.Mailer {
	if m.file != nil {
		return m.file
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mailer
}

// Reload rebuilds the mailer from the dashboard settings and switches the
// queue to it. Settings that cannot be used turn e-mail off.
func (m *mailSource) Reload(ctx context.Context, now time.Time) error {
	if m.file != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	settings, e := m.store.MailSettings(ctx)
	if e != nil {
		return e
	}
	var mailer *alerting.Mailer
	var problem error
	if settings.Enabled {
		mailer, problem = m.build(settings)
	}
	id := ""
	if mailer != nil {
		id = mailer.ID
	}
	if e = m.store.UseMailConfig(ctx, id, now); e != nil {
		return e
	}
	m.mailer = mailer
	return problem
}

func (m *mailSource) build(settings storage.MailSettings) (*alerting.Mailer, error) {
	c := mailConfig(settings)
	if settings.PasswordCipher != nil {
		password, e := m.auth.OpenSetting(smtpPasswordPurpose, settings.PasswordCipher)
		if e != nil {
			return nil, e
		}
		c.Password = string(password)
	}
	return alerting.NewMailer(c)
}

// allowTest limits test messages to one every 30 seconds.
func (m *mailSource) allowTest(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.Sub(m.lastTest) < 30*time.Second && !now.Before(m.lastTest) {
		return false
	}
	m.lastTest = now
	return true
}
