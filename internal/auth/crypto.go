// Package auth implements local administrator authentication using standard
// cryptographic primitives and the maintained Go Argon2id implementation.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"

	"golang.org/x/crypto/argon2"
)

const passwordPrefix = "$argon2id$v=19$m=19456,t=2,p=1$"

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, errors.New("secure random generation failed")
	}
	return value, nil
}

func randomToken() (string, error) {
	value, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func validPassword(password string) bool {
	return utf8.ValidString(password) && utf8.RuneCountInString(password) >= 15 && len(password) <= 256
}

func hashPassword(password string) (string, error) {
	if !validPassword(password) {
		return "", errors.New("password must contain at least 15 characters and at most 256 UTF-8 bytes")
	}
	salt, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash), nil
}

func verifyPassword(encoded, password string) bool {
	// Accept only this supported bounded profile. Untrusted/corrupt PHC values
	// cannot ask the process to allocate arbitrary memory or perform extra work.
	if len(encoded) != len(passwordPrefix)+22+1+43 || !strings.HasPrefix(encoded, passwordPrefix) || len(password) > 256 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(encoded, passwordPrefix), "$")
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil || len(salt) != 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil || len(expected) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// totp implements RFC 6238 using the standard HMAC-SHA1 primitive. SHA1 here
// is the interoperable TOTP construction, not password hashing or signatures.
func totp(secret []byte, step int64, digits int) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	number := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", digits, number%modulus)
}

func totpStep(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	current := now.Unix() / 30
	for _, step := range []int64{current, current - 1, current + 1} {
		if step >= 0 && step > lastStep && subtle.ConstantTimeCompare([]byte(totp(secret, step, 6)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func recoveryHash(code string) string {
	value := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
	decoded, err := base32Encoding.DecodeString(value)
	if err != nil || len(decoded) != 20 {
		return ""
	}
	return tokenHash("openrmm-recovery-v1\x00" + value)
}

func newRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for index := range codes {
		value, err := randomBytes(20)
		if err != nil {
			return nil, nil, err
		}
		text := base32Encoding.EncodeToString(value)
		codes[index] = text[:8] + "-" + text[8:16] + "-" + text[16:24] + "-" + text[24:]
		hashes[index] = recoveryHash(codes[index])
	}
	return codes, hashes, nil
}

func readKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(value) != 32 {
		return nil, errors.New("encryption key file must contain exactly 32 bytes")
	}
	return value, nil
}

func loadKey(path string, allowCreation bool) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("an encryption key path is required")
	}
	value, err := readKey(path)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cannot read administrator encryption key")
	}
	if !allowCreation {
		return nil, errors.New("administrator encryption key is missing; restore the separate key backup")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(filepath.Dir(directory), 0700); err != nil {
		return nil, errors.New("cannot create key parent directory")
	}
	if err := privatefs.CreateDirectory(directory); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("cannot create private key directory")
	}
	value, err = randomBytes(32)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		value, err := readKey(path)
		if err != nil {
			return nil, errors.New("administrator encryption key is not ready; retry startup")
		}
		return value, nil
	}
	if err != nil {
		return nil, errors.New("cannot create administrator encryption key")
	}
	_, writeErr := file.Write(value)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return nil, errors.New("cannot persist administrator encryption key")
	}
	return value, nil
}
