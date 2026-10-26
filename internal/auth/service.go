package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

var (
	ErrCredentials = errors.New("sign-in failed; check your credentials and use a fresh authenticator code")
	ErrLimited     = errors.New("too many sign-in attempts; try again later")
)

type Service struct {
	store     *storage.Store
	aead      cipher.AEAD
	csrfKey   []byte
	dummyHash string
	now       func() time.Time
	gate      chan struct{}
	mu        sync.Mutex
	attempts  map[string]attempt
}
type attempt struct {
	count int
	until time.Time
}

type Provisioning struct {
	Username      string   `json:"username"`
	Secret        string   `json:"secret"`
	URI           string   `json:"uri"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type SignedIn struct {
	Token    string
	CSRF     string
	Username string
}

func New(ctx context.Context, store *storage.Store, keyPath string) (*Service, error) {
	admin, err := store.Administrator(ctx)
	hasAdministrator := err == nil
	if err != nil && !errors.Is(err, storage.ErrNoAdministrator) {
		return nil, err
	}
	key, err := loadKey(keyPath, errors.Is(err, storage.ErrNoAdministrator))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("cannot initialize administrator encryption")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("cannot initialize administrator encryption")
	}
	csrfKey, err := hkdf.Key(sha256.New, key, nil, "openrmm:login-csrf:v1", 32)
	if err != nil {
		return nil, errors.New("cannot derive login CSRF key")
	}
	dummy, err := hashPassword("OpenRMM timing-only dummy password")
	if err != nil {
		return nil, err
	}
	service := &Service{store: store, aead: aead, csrfKey: csrfKey, dummyHash: dummy, now: time.Now, gate: make(chan struct{}, 1), attempts: make(map[string]attempt)}
	if hasAdministrator {
		if _, err := service.decrypt(admin.TOTPCipher); err != nil {
			return nil, err
		}
	}
	return service, nil
}

func username(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 3 || len(value) > 64 {
		return "", false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return "", false
	}
	return value, true
}

func (s *Service) encrypt(secret []byte) ([]byte, error) {
	nonce, err := randomBytes(s.aead.NonceSize())
	if err != nil {
		return nil, err
	}
	result := append([]byte{1}, nonce...)
	return s.aead.Seal(result, nonce, secret, []byte("openrmm:administrator:totp:v1")), nil
}

func (s *Service) decrypt(value []byte) ([]byte, error) {
	nonceSize := s.aead.NonceSize()
	if len(value) < 1+nonceSize+s.aead.Overhead() || value[0] != 1 {
		return nil, errors.New("administrator MFA data is invalid")
	}
	secret, err := s.aead.Open(nil, value[1:1+nonceSize], value[1+nonceSize:], []byte("openrmm:administrator:totp:v1"))
	if err != nil || len(secret) != 20 {
		return nil, errors.New("cannot decrypt administrator MFA data; check the encryption key backup")
	}
	return secret, nil
}

// SealSetting encrypts a stored setting (such as the SMTP password) with the
// server's separate encryption key. The purpose is bound to the ciphertext,
// so a value sealed for one setting cannot be opened as another.
func (s *Service) SealSetting(purpose string, plaintext []byte) ([]byte, error) {
	nonce, err := randomBytes(s.aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return s.aead.Seal(append([]byte{1}, nonce...), nonce, plaintext, []byte("openrmm:setting:"+purpose+":v1")), nil
}

// OpenSetting decrypts a value sealed by SealSetting for the same purpose.
func (s *Service) OpenSetting(purpose string, value []byte) ([]byte, error) {
	nonceSize := s.aead.NonceSize()
	if len(value) < 1+nonceSize+s.aead.Overhead() || value[0] != 1 {
		return nil, errors.New("stored setting is invalid")
	}
	plain, err := s.aead.Open(nil, value[1:1+nonceSize], value[1+nonceSize:], []byte("openrmm:setting:"+purpose+":v1"))
	if err != nil {
		return nil, errors.New("cannot decrypt a stored setting; check the encryption key backup")
	}
	return plain, nil
}

func (s *Service) Setup(ctx context.Context, name, password string, reset bool) (Provisioning, error) {
	return s.setup(ctx, name, password, reset, false)
}

func (s *Service) setup(ctx context.Context, name, password string, reset, unconfirmedOnly bool) (Provisioning, error) {
	name, valid := username(name)
	if !valid {
		return Provisioning{}, errors.New("username must be 3 to 64 lowercase letters, numbers, dots, underscores, or hyphens, starting with a letter or number")
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return Provisioning{}, err
	}
	secret, err := randomBytes(20)
	if err != nil {
		return Provisioning{}, err
	}
	encrypted, err := s.encrypt(secret)
	if err != nil {
		return Provisioning{}, err
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return Provisioning{}, err
	}
	store := s.store.SetAdministrator
	if unconfirmedOnly {
		store = func(ctx context.Context, admin storage.Administrator, codes []string, _ bool, now time.Time) error {
			return s.store.ReplaceUnconfirmedAdministrator(ctx, admin, codes, now)
		}
	}
	if err := store(ctx, storage.Administrator{Username: name, PasswordHash: passwordHash, TOTPCipher: encrypted}, hashes, reset, s.now()); err != nil {
		return Provisioning{}, err
	}
	encoded := base32Encoding.EncodeToString(secret)
	query := url.Values{"secret": {encoded}, "issuer": {"OpenRMM"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	uri := (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/OpenRMM:" + name, RawQuery: query.Encode()}).String()
	return Provisioning{Username: name, Secret: encoded, URI: uri, RecoveryCodes: codes}, nil
}

func (s *Service) Confirm(ctx context.Context, code string) error {
	admin, err := s.store.Administrator(ctx)
	if err != nil {
		return err
	}
	if admin.Confirmed {
		return errors.New("administrator MFA is already confirmed")
	}
	secret, err := s.decrypt(admin.TOTPCipher)
	if err != nil {
		return err
	}
	step, valid := totpStep(secret, strings.TrimSpace(code), s.now(), admin.LastStep)
	if !valid {
		return ErrCredentials
	}
	return s.store.ConfirmAdministrator(ctx, admin.Version, step, s.now())
}

// Attempts are limited per client (10 a minute) and per account from that
// client (5 a minute). There is deliberately no limit across all clients or
// per account alone: anyone could use it to lock the administrator out.
// Guessing gains little without one, since every sign-in needs the password
// and a fresh authenticator code, and a failure does not say which was
// wrong; the single sign-in slot (gate) bounds the work an attacker causes.
func limitKeys(peer, name string) ([]string, []int) {
	return []string{"peer:" + peer, "account:" + name + "@" + peer}, []int{10, 5}
}

// limited reports, without counting an attempt, whether a peer or label is
// over its limit.
func (s *Service) limited(peer, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	keys, limits := limitKeys(peer, name)
	for index, key := range keys {
		if v, ok := s.attempts[key]; ok && now.Before(v.until) && v.count >= limits[index] {
			return true
		}
	}
	return false
}

func (s *Service) allow(peer, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, value := range s.attempts {
		if !now.Before(value.until) {
			delete(s.attempts, key)
		}
	}
	keys, limits := limitKeys(peer, name)
	for index, key := range keys {
		if s.attempts[key].count >= limits[index] {
			return false
		}
	}
	// Past this many tracked labels (only an attacker with thousands of
	// addresses gets here) attempts are no longer recorded, rather than
	// refusing everyone; the sign-in slot still bounds the work.
	if len(s.attempts) > 4090 {
		return true
	}
	for _, key := range keys {
		value := s.attempts[key]
		if value.until.IsZero() {
			value.until = now.Add(time.Minute)
		}
		value.count++
		s.attempts[key] = value
	}
	return true
}

// enter takes the single sign-in slot, waiting briefly while another
// password check runs, so a flood of attempts slows sign-in down instead of
// refusing it.
func (s *Service) enter(ctx context.Context) bool {
	t := time.NewTimer(3 * time.Second)
	defer t.Stop()
	select {
	case s.gate <- struct{}{}:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

func (s *Service) Login(ctx context.Context, name, password, factor, peer string) (SignedIn, error) {
	canonical, validName := username(name)
	if !validName {
		canonical = "invalid"
	}
	if !s.allow(peer, canonical) {
		return SignedIn{}, ErrLimited
	}
	if !s.enter(ctx) {
		return SignedIn{}, ErrLimited
	}
	defer func() { <-s.gate }()
	admin, err := s.store.Administrator(ctx)
	if err != nil && !errors.Is(err, storage.ErrNoAdministrator) {
		return SignedIn{}, err
	}
	var technician *storage.Technician
	if validName && (err != nil || admin.Username != canonical) {
		t, lookupErr := s.store.TechnicianByName(ctx, canonical)
		if lookupErr == nil && t.Enabled {
			technician = &t
			admin = storage.Administrator{Username: t.Username, PasswordHash: t.PasswordHash, TOTPCipher: t.TOTPCipher, Confirmed: t.Confirmed, LastStep: t.LastStep, Version: t.Revision}
			err = nil
		}
	}
	hash := s.dummyHash
	known := err == nil && validName && admin.Username == canonical
	if technician != nil && !technician.Confirmed {
		known = false
	}
	if known {
		hash = admin.PasswordHash
	}
	passwordOK := verifyPassword(hash, password)
	fail := func() (SignedIn, error) {
		if err := s.store.AuditLoginFailure(ctx, s.now()); err != nil {
			return SignedIn{}, err
		}
		return SignedIn{}, ErrCredentials
	}
	if !known || !passwordOK || !admin.Confirmed {
		return fail()
	}
	secret, err := s.decrypt(admin.TOTPCipher)
	if technician != nil {
		secret, err = s.decryptTechnician(*technician)
	}
	if err != nil {
		return SignedIn{}, err
	}
	factor = strings.ReplaceAll(strings.TrimSpace(factor), " ", "")
	step, validTOTP := totpStep(secret, factor, s.now(), admin.LastStep)
	recovery := ""
	if !validTOTP {
		recovery = recoveryHash(factor)
		if recovery == "" {
			return fail()
		}
	}
	token, err := randomToken()
	if err != nil {
		return SignedIn{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return SignedIn{}, err
	}
	now := s.now()
	session := storage.Session{TokenHash: tokenHash(token), CSRF: csrf, CreatedAt: now.Unix(), ExpiresAt: now.Add(8 * time.Hour).Unix(), LastSeenAt: now.Unix()}
	if technician != nil {
		err = s.store.CompleteTechnicianLogin(ctx, technician.ID, admin.Version, step, recovery, session, now)
	} else {
		err = s.store.CompleteLogin(ctx, admin.Version, step, recovery, session, now)
	}
	if err != nil {
		if errors.Is(err, storage.ErrAuthentication) {
			return fail()
		}
		return SignedIn{}, err
	}
	return SignedIn{Token: token, CSRF: csrf, Username: admin.Username}, nil
}

func (s *Service) Session(ctx context.Context, token string) (storage.Session, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return storage.Session{}, storage.ErrAuthentication
	}
	return s.store.Session(ctx, tokenHash(token), s.now())
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.Logout(ctx, tokenHash(token), s.now())
}

func (s *Service) LoginCSRF() (string, error) {
	nonce, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	value := make([]byte, 8, 72)
	binary.BigEndian.PutUint64(value, uint64(s.now().Unix()))
	value = append(value, nonce...)
	mac := hmac.New(sha256.New, s.csrfKey)
	_, _ = mac.Write(value)
	return base64.RawURLEncoding.EncodeToString(append(value, mac.Sum(nil)...)), nil
}

func (s *Service) ValidLoginCSRF(cookie, submitted string) bool {
	if len(cookie) > 128 || subtle.ConstantTimeCompare([]byte(cookie), []byte(submitted)) != 1 {
		return false
	}
	value, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || len(value) != 72 {
		return false
	}
	issued := int64(binary.BigEndian.Uint64(value[:8]))
	now := s.now().Unix()
	if issued > now+5 || issued <= now-600 {
		return false
	}
	mac := hmac.New(sha256.New, s.csrfKey)
	_, _ = mac.Write(value[:40])
	return hmac.Equal(mac.Sum(nil), value[40:])
}
