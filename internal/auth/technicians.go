package auth

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func NewTechnicianID() (string, error) { b, e := randomBytes(16); return hex.EncodeToString(b), e }
func (s *Service) ReviewTechnician(ctx context.Context, c storage.TechnicianChange, actor string) (string, error) {
	return s.store.ChangeTechnician(ctx, c, actor, "", "", s.now())
}
func (s *Service) ApplyTechnician(ctx context.Context, c storage.TechnicianChange, actor, digest string) (string, error) {
	invitation := ""
	var e error
	if c.Action == "create" || c.Action == "reset" {
		invitation, e = randomToken()
		if e != nil {
			return "", e
		}
	}
	_, e = s.store.ChangeTechnician(ctx, c, actor, digest, tokenHash(invitation), s.now())
	if e != nil {
		return "", e
	}
	return invitation, nil
}
func validInvitation(token string) bool {
	b, e := base64.RawURLEncoding.DecodeString(token)
	return e == nil && len(b) == 32
}
func (s *Service) encryptTechnician(id string, secret []byte) ([]byte, error) {
	nonce, e := randomBytes(s.aead.NonceSize())
	if e != nil {
		return nil, e
	}
	return s.aead.Seal(append([]byte{2}, nonce...), nonce, secret, []byte("openrmm:technician:totp:v1:"+id)), nil
}
func (s *Service) decryptTechnician(t storage.Technician) ([]byte, error) {
	n := s.aead.NonceSize()
	v := t.TOTPCipher
	if len(v) < 1+n+s.aead.Overhead() || v[0] != 2 {
		return nil, errors.New("technician MFA data unavailable")
	}
	secret, e := s.aead.Open(nil, v[1:1+n], v[1+n:], []byte("openrmm:technician:totp:v1:"+t.ID))
	if e != nil || len(secret) != 20 {
		return nil, errors.New("technician MFA data unavailable")
	}
	return secret, nil
}

type TechnicianProvisioning struct {
	Provisioning
	Confirmation string
}

func (s *Service) BeginTechnician(ctx context.Context, invitation, password, peer string) (TechnicianProvisioning, error) {
	if !s.allow(peer, "technician-activation") {
		return TechnicianProvisioning{}, ErrLimited
	}
	if !validInvitation(invitation) {
		return TechnicianProvisioning{}, ErrCredentials
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	default:
		return TechnicianProvisioning{}, ErrLimited
	}
	t, e := s.store.TechnicianInvitation(ctx, tokenHash(invitation), s.now())
	if e != nil {
		return TechnicianProvisioning{}, ErrCredentials
	}
	hash, e := hashPassword(password)
	if e != nil {
		return TechnicianProvisioning{}, e
	}
	secret, e := randomBytes(20)
	if e != nil {
		return TechnicianProvisioning{}, e
	}
	cipher, e := s.encryptTechnician(t.ID, secret)
	if e != nil {
		return TechnicianProvisioning{}, e
	}
	codes, hashes, e := newRecoveryCodes()
	if e != nil {
		return TechnicianProvisioning{}, e
	}
	confirm, e := randomToken()
	if e != nil {
		return TechnicianProvisioning{}, e
	}
	if e = s.store.BeginTechnicianActivation(ctx, t.ID, tokenHash(invitation), tokenHash(confirm), hash, cipher, hashes, s.now()); e != nil {
		return TechnicianProvisioning{}, e
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	uri := "otpauth://totp/" + url.PathEscape("OpenRMM:"+t.Username) + "?secret=" + encoded + "&issuer=OpenRMM&algorithm=SHA1&digits=6&period=30"
	return TechnicianProvisioning{Provisioning: Provisioning{Username: t.Username, Secret: encoded, URI: uri, RecoveryCodes: codes}, Confirmation: confirm}, nil
}
func (s *Service) ConfirmTechnician(ctx context.Context, confirmation, code, peer string) error {
	if !s.allow(peer, "technician-confirmation") {
		return ErrLimited
	}
	if !validInvitation(confirmation) {
		return ErrCredentials
	}
	t, e := s.store.TechnicianInvitation(ctx, tokenHash(confirmation), s.now())
	if e != nil {
		return ErrCredentials
	}
	secret, e := s.decryptTechnician(t)
	if e != nil {
		return ErrCredentials
	}
	step, ok := totpStep(secret, strings.TrimSpace(code), s.now(), t.LastStep)
	if !ok {
		return ErrCredentials
	}
	return s.store.ConfirmTechnicianActivation(ctx, t.ID, tokenHash(confirmation), step, s.now())
}
