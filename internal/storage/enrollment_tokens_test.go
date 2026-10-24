package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// Reusable deployment tokens enroll up to their device limit until
// they expire or are revoked; single-device tokens are consumed; devices
// record the token they used.
func TestDeploymentTokensLimitRevokeAndRecordDevices(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	n := 0
	enroll := func(hash string, at time.Time) error {
		n++
		d := Device{ID: fmt.Sprintf("%032x", n), Hostname: "pc", OS: "windows", Architecture: "amd64", Certificate: "cert", Fingerprint: fmt.Sprint("fp", n)}
		return s.EnrollDevice(ctx, hash, d, at)
	}
	deploy := EnrollmentToken{ID: "11111111111111111111111111111111", Label: "Office", Reusable: true, MaxDevices: 2, Actor: "owner", ExpiresAt: now.Add(48 * time.Hour).Unix()}
	if e = s.AddEnrollmentToken(ctx, "deploy-hash", deploy, now); e != nil {
		t.Fatal(e)
	}
	if e = s.AddEnrollmentToken(ctx, "bad", EnrollmentToken{ID: "x", MaxDevices: 5, ExpiresAt: now.Add(time.Hour).Unix()}, now); !errors.Is(e, ErrEnrollmentToken) {
		t.Fatal("single-device token with a device limit accepted", e)
	}
	for i := 0; i < 2; i++ {
		if e = enroll("deploy-hash", now.Add(time.Minute)); e != nil {
			t.Fatal("deployment enrollment", i, e)
		}
	}
	if e = enroll("deploy-hash", now.Add(time.Minute)); !errors.Is(e, ErrAuthentication) {
		t.Fatal("device limit exceeded", e)
	}
	var recorded int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM devices WHERE enrollment_token_id=?", deploy.ID).Scan(&recorded); e != nil || recorded != 2 {
		t.Fatal("devices not recorded against the token", recorded, e)
	}
	tokens, e := s.DeploymentTokens(ctx, now)
	if e != nil || len(tokens) != 1 || tokens[0].Used != 2 || tokens[0].Label != "Office" || tokens[0].Actor != "owner" {
		t.Fatal("deployment list", tokens, e)
	}

	second := EnrollmentToken{ID: "22222222222222222222222222222222", Label: "Lab", Reusable: true, MaxDevices: 10, Actor: "owner", ExpiresAt: now.Add(time.Hour).Unix()}
	if e = s.AddEnrollmentToken(ctx, "second-hash", second, now); e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeDeploymentToken(ctx, second.ID, "owner", now); e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeDeploymentToken(ctx, second.ID, "owner", now); !errors.Is(e, ErrEnrollmentToken) {
		t.Fatal("revoked twice", e)
	}
	if e = enroll("second-hash", now.Add(time.Minute)); !errors.Is(e, ErrAuthentication) {
		t.Fatal("revoked token enrolled", e)
	}
	if e = s.NewEnrollmentToken(ctx, "single", now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = enroll("single", now.Add(2*time.Hour)); !errors.Is(e, ErrAuthentication) {
		t.Fatal("expired single token enrolled", e)
	}

	// Revoked and expired deployments stay listed for 30 days, then go.
	later := now.Add(31 * 24 * time.Hour)
	if e = s.NewEnrollmentToken(ctx, "later", later, later.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if tokens, e = s.DeploymentTokens(ctx, later); e != nil || len(tokens) != 1 || tokens[0].ID != deploy.ID {
		t.Fatal("retention", tokens, e)
	}
}

func TestInstallerSettingsAuditChangesOnly(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if v, e := s.InstallerSettings(ctx); e != nil || v != (InstallerSettings{}) {
		t.Fatal("default settings", v, e)
	}
	v := InstallerSettings{ServerURL: "https://rmm.example.com:8443", DeviceURL: "https://rmm.example.com:8444"}
	now := time.Unix(1800000000, 0)
	for i := 0; i < 2; i++ {
		if e = s.SetInstallerSettings(ctx, v, "owner", now); e != nil {
			t.Fatal(e)
		}
	}
	var audits int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='installer_settings_changed' AND actor='owner'").Scan(&audits); e != nil || audits != 1 {
		t.Fatal("audit", audits, e)
	}
	if got, e := s.InstallerSettings(ctx); e != nil || got != v {
		t.Fatal("stored settings", got, e)
	}
}

// The install command's addresses fill empty settings once and
// never replace addresses set on the dashboard.
func TestInitializeInstallerSettings(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	first := InstallerSettings{ServerURL: "https://rmm.lan", DeviceURL: "https://rmm.lan:8444"}
	for i := 0; i < 2; i++ {
		if e = s.InitializeInstallerSettings(ctx, first, now); e != nil {
			t.Fatal(e)
		}
	}
	owner := InstallerSettings{ServerURL: "https://rmm.example.com", DeviceURL: "https://rmm.example.com:8444"}
	if e = s.SetInstallerSettings(ctx, owner, "owner", now); e != nil {
		t.Fatal(e)
	}
	if e = s.InitializeInstallerSettings(ctx, first, now); e != nil {
		t.Fatal(e)
	}
	var audits int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='installer_settings_changed' AND actor='install'").Scan(&audits); e != nil || audits != 1 {
		t.Fatal("audit", audits, e)
	}
	if got, e := s.InstallerSettings(ctx); e != nil || got != owner {
		t.Fatal("dashboard settings replaced", got, e)
	}
}
