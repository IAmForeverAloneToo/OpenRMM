package storage

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestMailSettings(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	m, e := s.MailSettings(ctx)
	if e != nil || m.Enabled || m.Port != 587 || m.TLS != "starttls" || m.PasswordCipher != nil || m.To == nil || m.Revision != 1 {
		t.Fatal("unexpected default e-mail settings", m, e)
	}
	m.Enabled, m.Host, m.Username, m.PasswordCipher, m.From, m.To, m.ServerURL = true, "smtp.example.invalid", "rmm", []byte("sealed"), "rmm@example.invalid", []string{"a@example.invalid", "b@example.invalid"}, "https://rmm.example.invalid"
	if e = s.SetMailSettings(ctx, m, "admin", now); e != nil {
		t.Fatal(e)
	}
	if e = s.SetMailSettings(ctx, m, "admin", now); !errors.Is(e, ErrMailSettingsChanged) {
		t.Fatal("stale revision accepted", e)
	}
	got, e := s.MailSettings(ctx)
	if e != nil || !got.Enabled || got.Host != m.Host || string(got.PasswordCipher) != "sealed" || !slices.Equal(got.To, m.To) || got.Revision != 2 || got.UpdatedAt == nil || *got.UpdatedAt != now.Unix() {
		t.Fatal("e-mail settings not stored", got, e)
	}
	// Clearing the password stores no ciphertext.
	got.PasswordCipher = nil
	if e = s.SetMailSettings(ctx, got, "admin", now); e != nil {
		t.Fatal(e)
	}
	if got, e = s.MailSettings(ctx); e != nil || got.PasswordCipher != nil {
		t.Fatal("password not cleared", e)
	}
	var audits int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='email_settings_changed' AND actor='admin'").Scan(&audits); e != nil || audits != 2 {
		t.Fatal("settings changes not audited", audits, e)
	}
	if e = s.AuditMailTest(ctx, "admin", "sent", now); e != nil {
		t.Fatal(e)
	}
	// Switching configuration updates the runtime; the same ID is a no-op.
	for _, id := range []string{"first", "first", ""} {
		if e = s.UseMailConfig(ctx, id, now); e != nil {
			t.Fatal(e)
		}
		if r, e := s.AlertRuntime(ctx); e != nil || r.MailConfig != id {
			t.Fatal("mail configuration not switched", r.MailConfig, e)
		}
	}
}
