package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTOTPAgainstRFC6238SHA1Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, vector := range []struct {
		seconds int64
		code    string
	}{
		{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
	} {
		if actual := totp(secret, vector.seconds/30, 8); actual != vector.code {
			t.Fatalf("RFC vector failed at %d", vector.seconds)
		}
	}
	now := time.Unix(1234567890, 0)
	step := now.Unix() / 30
	code := totp(secret, step, 6)
	if accepted, ok := totpStep(secret, code, now, step-1); !ok || accepted != step {
		t.Fatal("fresh current code rejected")
	}
	if _, ok := totpStep(secret, code, now, step); ok {
		t.Fatal("same time step accepted twice")
	}
	if _, ok := totpStep(secret, totp(secret, step-2, 6), now, -1); ok {
		t.Fatal("code outside the drift window accepted")
	}
}

func TestPasswordHashingAndBoundedProfiles(t *testing.T) {
	password := "A long local test passphrase"
	first, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("password salts were reused")
	}
	if !verifyPassword(first, password) || verifyPassword(first, "incorrect password") {
		t.Fatal("password verification failed")
	}
	if verifyPassword(strings.Replace(first, "m=19456", "m=999999999", 1), password) {
		t.Fatal("unbounded password profile accepted")
	}
	if _, err := hashPassword("too short"); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := hashPassword(strings.Repeat("x", 257)); err == nil {
		t.Fatal("oversized password accepted")
	}
}

func TestRecoveryCodeNormalizationAndUniqueness(t *testing.T) {
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for index, code := range codes {
		if seen[hashes[index]] || hashes[index] == "" || hashes[index] == code {
			t.Fatal("invalid recovery hash")
		}
		seen[hashes[index]] = true
		if recoveryHash(strings.ToLower(strings.ReplaceAll(code, "-", " "))) != hashes[index] {
			t.Fatal("formatted recovery code not normalized")
		}
	}
	if recoveryHash("a short guess") != "" {
		t.Fatal("malformed recovery code accepted")
	}
}

func TestKeyCreationAndFailClosedRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "key.bin")
	if _, err := loadKey(path, false); err == nil {
		t.Fatal("missing established key was created")
	}
	first, err := loadKey(path, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadKey(path, true)
	if err != nil || string(first) != string(second) {
		t.Fatal("existing key was replaced")
	}
	if err := os.WriteFile(path, []byte("invalid key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(path, true); err == nil {
		t.Fatal("invalid existing key was silently replaced")
	}
}
