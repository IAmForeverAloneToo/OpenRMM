package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func inviteTechnician(t *testing.T, s *Service, name string, access storage.TechnicianAccess) (storage.TechnicianChange, string) {
	t.Helper()
	id, e := NewTechnicianID()
	if e != nil {
		t.Fatal(e)
	}
	c := storage.TechnicianChange{Action: "create", ID: id, Username: name, Enabled: true, Access: access}
	digest, e := s.ReviewTechnician(context.Background(), c, "admin")
	if e != nil {
		t.Fatal(e)
	}
	invitation, e := s.ApplyTechnician(context.Background(), c, "admin", digest)
	if e != nil {
		t.Fatal(e)
	}
	return c, invitation
}
func TestTechnicianInvitationOwnPasswordMFARecoveryAndRevocation(t *testing.T) {
	s, store, _, now := testService(t)
	provision(t, s, *now)
	ctx := context.Background()
	c, invitation := inviteTechnician(t, s, "helper", storage.TechnicianAccess{AllDevices: true})
	if _, e := s.Login(ctx, "helper", testPassword, "123456", "127.0.0.1"); !errors.Is(e, ErrCredentials) {
		t.Fatal("unactivated account accepted")
	}
	setup, e := s.BeginTechnician(ctx, invitation, testPassword, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.BeginTechnician(ctx, invitation, testPassword, "127.0.0.1"); !errors.Is(e, ErrCredentials) {
		t.Fatal("invitation replayed")
	}
	secret, _ := base32Encoding.DecodeString(setup.Secret)
	code := totp(secret, now.Unix()/30, 6)
	if e = s.ConfirmTechnician(ctx, setup.Confirmation, code, "127.0.0.1"); e != nil {
		t.Fatal(e)
	}
	if e = s.ConfirmTechnician(ctx, setup.Confirmation, code, "127.0.0.1"); !errors.Is(e, ErrCredentials) {
		t.Fatal("confirmation replayed")
	}
	if _, e = s.Login(ctx, "helper", testPassword, code, "127.0.0.1"); !errors.Is(e, ErrCredentials) {
		t.Fatal("confirmation TOTP reused")
	}
	v, e := s.Login(ctx, "helper", testPassword, setup.RecoveryCodes[0], "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	session, e := s.Session(ctx, v.Token)
	if e != nil || session.Technician == nil || session.Username != "helper" || session.Actor() != "technician:"+c.ID || session.Can("services") {
		t.Fatal("technician impersonated administrator", e)
	}
	if _, e = s.Login(ctx, "helper", testPassword, setup.RecoveryCodes[0], "127.0.0.1"); !errors.Is(e, ErrCredentials) {
		t.Fatal("recovery replayed")
	}
	*now = now.Add(time.Minute)
	v, e = s.Login(ctx, "helper", testPassword, totp(secret, now.Unix()/30, 6), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := store.Technicians(ctx)
	if e != nil {
		t.Fatal(e)
	}
	c.Action = "save"
	c.Revision = rows[0].Revision
	c.Enabled = false
	digest, e := s.ReviewTechnician(ctx, c, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ApplyTechnician(ctx, c, "admin", digest); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Session(ctx, v.Token); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("disabled session survived", e)
	}
	if _, e = s.Login(ctx, "helper", testPassword, setup.RecoveryCodes[1], "127.0.0.1"); !errors.Is(e, ErrCredentials) {
		t.Fatal("disabled technician logged in")
	}
}

func TestTechnicianInvitationExpiresResetReplacesSecretsAndCipherIsAccountBound(t *testing.T) {
	s, store, _, now := testService(t)
	provision(t, s, *now)
	ctx := context.Background()
	c, invitation := inviteTechnician(t, s, "helper", storage.TechnicianAccess{})
	*now = now.Add(31 * time.Minute)
	if _, e := s.BeginTechnician(ctx, invitation, testPassword, "127.0.0.1"); !errors.Is(e, ErrCredentials) {
		t.Fatal("expired invitation accepted")
	}
	c.Action = "reset"
	c.Revision = 1
	digest, e := s.ReviewTechnician(ctx, c, "admin")
	if e != nil {
		t.Fatal(e)
	}
	invitation, e = s.ApplyTechnician(ctx, c, "admin", digest)
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.BeginTechnician(ctx, invitation, testPassword, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	row, e := store.TechnicianByName(ctx, "helper")
	if e != nil {
		t.Fatal(e)
	}
	row.ID = strings.Repeat("f", 32)
	if _, e = s.decryptTechnician(row); e == nil {
		t.Fatal("MFA ciphertext moved to another identity")
	}
	secret, _ := base32Encoding.DecodeString(result.Secret)
	if e = s.ConfirmTechnician(ctx, result.Confirmation, totp(secret, now.Unix()/30, 6), "127.0.0.1"); e != nil {
		t.Fatal(e)
	}
	login, e := s.Login(ctx, "helper", testPassword, result.RecoveryCodes[0], "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Setup(ctx, "admin", testPassword, true); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Session(ctx, login.Token); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("owner recovery left technician active")
	}
	row, e = store.TechnicianByName(ctx, "helper")
	if e != nil || row.Enabled {
		t.Fatal("owner reset did not disable technician")
	}
}
