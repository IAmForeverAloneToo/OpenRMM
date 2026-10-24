package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

const testPassword = "Local authentication test passphrase"

func testService(t *testing.T) (*Service, *storage.Store, string, *time.Time) {
	t.Helper()
	root := t.TempDir()
	store, err := storage.Open(context.Background(), filepath.Join(root, "data", "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	keyPath := filepath.Join(root, "secrets", "key.bin")
	service, err := New(context.Background(), store, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1792100010, 0).UTC()
	service.now = func() time.Time { return now }
	return service, store, keyPath, &now
}

func provision(t *testing.T, service *Service, now time.Time) Provisioning {
	t.Helper()
	result, err := service.Setup(context.Background(), "admin", testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32Encoding.DecodeString(result.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Confirm(context.Background(), totp(secret, now.Unix()/30, 6)); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMFAReplaySingleUseRecoveryAndLogout(t *testing.T) {
	service, _, _, now := testService(t)
	result := provision(t, service, *now)
	secret, _ := base32Encoding.DecodeString(result.Secret)
	if _, err := service.Login(context.Background(), "admin", testPassword, totp(secret, now.Unix()/30, 6), "127.0.0.1"); !errors.Is(err, ErrCredentials) {
		t.Fatal("confirmation code replayed as a login")
	}
	*now = now.Add(30 * time.Second)
	code := totp(secret, now.Unix()/30, 6)
	signedIn, err := service.Login(context.Background(), "admin", testPassword, code, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(context.Background(), "admin", testPassword, code, "127.0.0.1"); !errors.Is(err, ErrCredentials) {
		t.Fatal("TOTP replay was not rejected")
	}
	if _, err := service.Session(context.Background(), signedIn.Token); err != nil {
		t.Fatal(err)
	}
	if err := service.Logout(context.Background(), signedIn.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Session(context.Background(), signedIn.Token); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("logged-out session remained valid")
	}
	*now = now.Add(time.Minute)
	if _, err := service.Login(context.Background(), "admin", testPassword, result.RecoveryCodes[0], "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(context.Background(), "admin", testPassword, result.RecoveryCodes[0], "127.0.0.1"); !errors.Is(err, ErrCredentials) {
		t.Fatal("recovery code accepted twice")
	}
}

func TestPendingSetupAndLocalResetInvalidateOldMaterial(t *testing.T) {
	service, store, _, now := testService(t)
	result, err := service.Setup(context.Background(), "admin", testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(context.Background(), "admin", testPassword, result.RecoveryCodes[0], "127.0.0.1"); !errors.Is(err, ErrCredentials) {
		t.Fatal("unconfirmed administrator accepted")
	}
	if _, err := service.Setup(context.Background(), "other", testPassword, false); !errors.Is(err, storage.ErrAlreadyConfigured) {
		t.Fatal("bootstrap replaced an existing administrator")
	}
	secret, _ := base32Encoding.DecodeString(result.Secret)
	if err := service.Confirm(context.Background(), totp(secret, now.Unix()/30, 6)); err != nil {
		t.Fatal(err)
	}
	signedIn, err := service.Login(context.Background(), "admin", testPassword, result.RecoveryCodes[0], "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := service.Setup(context.Background(), "admin", "A replacement local passphrase", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Session(context.Background(), signedIn.Token); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("local reset did not invalidate sessions")
	}
	admin, err := store.Administrator(context.Background())
	if err != nil || admin.Confirmed || admin.Version != 2 {
		t.Fatalf("reset did not require new MFA confirmation: %v", err)
	}
	newSecret, _ := base32Encoding.DecodeString(replacement.Secret)
	if err := service.Confirm(context.Background(), totp(newSecret, now.Unix()/30, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(context.Background(), "admin", "A replacement local passphrase", result.RecoveryCodes[1], "127.0.0.1"); !errors.Is(err, ErrCredentials) {
		t.Fatal("old recovery code survived reset")
	}
}

func TestExpiryCSRFAndLoginThrottling(t *testing.T) {
	service, _, _, now := testService(t)
	result := provision(t, service, *now)
	csrf, err := service.LoginCSRF()
	if err != nil || !service.ValidLoginCSRF(csrf, csrf) {
		t.Fatal("fresh login CSRF rejected")
	}
	if service.ValidLoginCSRF(csrf, csrf+"x") {
		t.Fatal("mismatched login CSRF accepted")
	}
	signedIn, err := service.Login(context.Background(), "admin", testPassword, result.RecoveryCodes[0], "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Minute)
	if _, err := service.Session(context.Background(), signedIn.Token); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("idle session did not expire")
	}
	if service.ValidLoginCSRF(csrf, csrf) {
		t.Fatal("expired login CSRF accepted")
	}
	for index := 0; index < 5; index++ {
		if _, err := service.Login(context.Background(), "admin", "incorrect", "000000", "127.0.0.1"); !errors.Is(err, ErrCredentials) {
			t.Fatal("unexpected failure before throttle threshold")
		}
	}
	if _, err := service.Login(context.Background(), "admin", testPassword, result.RecoveryCodes[1], "127.0.0.1"); !errors.Is(err, ErrLimited) {
		t.Fatal("throttle did not apply to the next attempt")
	}
}

func TestMissingOrWrongKeyAndEncryptedSecret(t *testing.T) {
	service, store, keyPath, now := testService(t)
	result := provision(t, service, *now)
	admin, err := store.Administrator(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := base32Encoding.DecodeString(result.Secret)
	if string(admin.TOTPCipher) == string(secret) || string(admin.TOTPCipher) == result.Secret {
		t.Fatal("MFA secret stored in plaintext")
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), store, keyPath); err == nil {
		t.Fatal("missing established key did not fail closed")
	}
	wrongKey := make([]byte, 32)
	if err := os.WriteFile(keyPath, wrongKey, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), store, keyPath); err == nil {
		t.Fatal("wrong encryption key accepted")
	}
}

func TestActiveSessionStillExpiresAfterEightHours(t *testing.T) {
	service, _, _, now := testService(t)
	result := provision(t, service, *now)
	signedIn, err := service.Login(context.Background(), "admin", testPassword, result.RecoveryCodes[0], "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 47; index++ {
		*now = now.Add(10 * time.Minute)
		if _, err := service.Session(context.Background(), signedIn.Token); err != nil {
			t.Fatal("active session expired early")
		}
	}
	*now = now.Add(10 * time.Minute)
	if _, err := service.Session(context.Background(), signedIn.Token); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("activity extended the absolute session lifetime")
	}
}
