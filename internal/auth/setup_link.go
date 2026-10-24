package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// First-administrator setup link (valid 1 hour, single use). The install
// command prints it; the browser creates the
// administrator with it in two steps, like a technician invitation.

// SetupLinkLife is how long a setup link works.
const SetupLinkLife = time.Hour

func linkHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewSetupLink creates a link token; only its hash is stored. It is refused
// once an administrator exists.
func (s *Service) NewSetupLink(ctx context.Context) (string, time.Time, error) {
	raw, e := randomBytes(32)
	if e != nil {
		return "", time.Time{}, e
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expires := s.now().Add(SetupLinkLife)
	if e = s.store.NewSetupLink(ctx, linkHash(token), expires, s.now()); e != nil {
		return "", time.Time{}, e
	}
	return token, expires, nil
}

// failed counts a failed attempt from a peer; past the limit the answer is
// "too many attempts" (the 256-bit link itself cannot be guessed; this slows
// down guessing authenticator codes).
func (s *Service) failed(peer string, e error) error {
	if !s.allow(peer, "setup-link") {
		return ErrLimited
	}
	return e
}

// checkLink checks the link. Past the failure limit every attempt is
// refused before it is evaluated.
func (s *Service) checkLink(ctx context.Context, token, peer string) error {
	if s.limited(peer, "setup-link") {
		return ErrLimited
	}
	if len(token) < 40 || len(token) > 64 {
		return s.failed(peer, storage.ErrSetupLink)
	}
	if e := s.store.CheckSetupLink(ctx, linkHash(token), s.now()); e != nil {
		if errors.Is(e, storage.ErrSetupLink) {
			return s.failed(peer, e)
		}
		return e
	}
	return nil
}

// SetupWithLink creates the administrator (step 1): the provisioning (the
// authenticator key and recovery codes) is shown once. A setup that was
// started but never confirmed is replaced.
func (s *Service) SetupWithLink(ctx context.Context, token, name, password, peer string) (Provisioning, error) {
	if e := s.checkLink(ctx, token, peer); e != nil {
		return Provisioning{}, e
	}
	_, e := s.store.Administrator(ctx)
	unconfirmed := e == nil
	if e != nil && !errors.Is(e, storage.ErrNoAdministrator) {
		return Provisioning{}, e
	}
	// Replacing checks again, in the same transaction, that the earlier
	// setup is still unconfirmed.
	return s.setup(ctx, name, password, unconfirmed, unconfirmed)
}

// ConfirmWithLink confirms the authenticator (step 2) and uses up the link.
func (s *Service) ConfirmWithLink(ctx context.Context, token, code, peer string) error {
	if e := s.checkLink(ctx, token, peer); e != nil {
		return e
	}
	if e := s.Confirm(ctx, code); e != nil {
		if errors.Is(e, ErrCredentials) {
			return s.failed(peer, e)
		}
		return e
	}
	return s.store.UseSetupLink(ctx, linkHash(token), s.now())
}
