package dpapi

import (
	"bytes"
	"testing"
)

func TestProtectRoundTrip(t *testing.T) {
	secret := []byte("http://user:secret@proxy.example:8080")
	sealed, err := Protect(secret, "test")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("protected value contains the plaintext")
	}
	opened, err := Unprotect(sealed, "test")
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatal("round trip failed", err)
	}
	if _, err := Unprotect(sealed, "other"); err == nil {
		t.Fatal("opened with another purpose")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Unprotect(sealed, "test"); err == nil {
		t.Fatal("opened a damaged value")
	}
}
