package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
)

const testPassphrase = "correct horse battery staple"

func TestSealedKeyRoundTripAndTamperRefusal(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	if _, e := sealKey(priv, []byte("too short")); e == nil {
		t.Fatal("short passphrase accepted")
	}
	raw, e := sealKey(priv, []byte(testPassphrase))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), string(priv.Seed())) {
		t.Fatal("seed stored in clear")
	}
	opened, e := openKey(raw, []byte(testPassphrase))
	if e != nil || !opened.Equal(priv) {
		t.Fatal("round trip", e)
	}
	if _, e = openKey(raw, []byte(testPassphrase+"!")); e == nil {
		t.Fatal("wrong passphrase accepted")
	}
	var k sealedKey
	_ = json.Unmarshal(raw, &k)
	_, other, _ := ed25519.GenerateKey(nil)
	swapped, _ := sealKey(other, []byte(testPassphrase))
	var o sealedKey
	_ = json.Unmarshal(swapped, &o)
	k.PublicKey = o.PublicKey // a different public key fails the bound data
	tampered, _ := json.Marshal(k)
	if _, e = openKey(tampered, []byte(testPassphrase)); e == nil {
		t.Fatal("swapped public key accepted")
	}
	k.PublicKey = ""
	_ = json.Unmarshal(raw, &k)
	k.Time = 0
	weak, _ := json.Marshal(k)
	if _, e = openKey(weak, []byte(testPassphrase)); e == nil {
		t.Fatal("out-of-range KDF parameters accepted")
	}
}

func TestSequenceCounterConsumesBeforeSigning(t *testing.T) {
	dir := t.TempDir()
	if _, e := nextSequence(dir, 0); e == nil {
		t.Fatal("missing counter accepted")
	}
	if e := writeCounter(filepath.Join(dir, counterFile), 8, true); e != nil {
		t.Fatal(e)
	}
	if e := writeCounter(filepath.Join(dir, counterFile), 9, true); e == nil {
		t.Fatal("existing counter overwritten on creation")
	}
	for want := int64(9); want <= 11; want++ {
		if got, e := nextSequence(dir, 0); e != nil || got != want {
			t.Fatal("next sequence", got, e)
		}
	}
	if _, e := nextSequence(dir, 11); e == nil {
		t.Fatal("reused sequence accepted")
	}
	if got, e := nextSequence(dir, 20); e != nil || got != 20 {
		t.Fatal("explicit higher sequence", got, e)
	}
	if got, _ := nextSequence(dir, 0); got != 21 {
		t.Fatal("counter did not advance past explicit sequence", got)
	}
	if _, e := os.Stat(filepath.Join(dir, counterFile+".tmp")); !os.IsNotExist(e) {
		t.Fatal("temporary counter left behind")
	}
}

func TestReadPassphrase(t *testing.T) {
	if p, e := readPassphrase(strings.NewReader(testPassphrase + "\r\nignored")); e != nil || string(p) != testPassphrase {
		t.Fatal("line not read", e)
	}
	for _, bad := range []string{"", "\n", strings.Repeat("x", 2000)} {
		if _, e := readPassphrase(strings.NewReader(bad)); e == nil {
			t.Fatal("bad passphrase input accepted", len(bad))
		}
	}
}

// A server release is signed with the sealed key, reuses a
// sequence the counter already handed out, and consumes none.
func TestSignServerRelease(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	if e := storeSealed(dir, priv, []byte(testPassphrase), 39); e != nil {
		t.Fatal(e)
	}
	pass := func() ([]byte, error) { return []byte(testPassphrase), nil }
	key := filepath.Join(dir, sealedKeyFile)
	id := "sha256:" + strings.Repeat("a", 64)
	notes := filepath.Join(dir, "notes.txt")
	os.WriteFile(notes, []byte("What changed."), 0600)
	out := filepath.Join(dir, "release.json")
	if e := signServer(key, "1.2.0", 40, "ghcr.io/example/openrmm-server", id, "", notes, out, 90, pass); e == nil {
		t.Fatal("unused sequence accepted")
	}
	if e := signServer(key, "1.2.0", 39, "ghcr.io/example/openrmm-server:1.2.0", id, "", notes, out, 90, pass); e == nil {
		t.Fatal("tagged image accepted")
	}
	if e := signServer(key, "1.2.0", 39, "ghcr.io/example/openrmm-server", id, "", notes, out, 90, pass); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(out)
	var r serverupdate.Release
	if json.Unmarshal(raw, &r) != nil || !serverupdate.Verify(r, []string{hex.EncodeToString(priv.Public().(ed25519.PublicKey))}) || r.Manifest.Notes != "What changed." {
		t.Fatal(string(raw))
	}
	if last, e := lastSequence(dir); e != nil || last != 39 {
		t.Fatal("counter changed", last, e)
	}
}
