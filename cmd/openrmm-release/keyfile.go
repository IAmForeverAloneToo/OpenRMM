package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// The signing key is stored encrypted (S11): Argon2id derives an AES-256-GCM
// key from the publisher's passphrase. The file names its public key, which is
// also bound as additional data, so a swapped or edited file fails to open.
const (
	sealedKeyFile = "signing-key.json"
	publicKeyFile = "public.txt"
	counterFile   = "sequence.json"
	keyAAD        = "openrmm signing key v1|"
	minPassphrase = 15
)

var errKey = errors.New("signing key unavailable")

type sealedKey struct {
	Format     int    `json:"format"`
	KDF        string `json:"kdf"`
	Time       uint32 `json:"time"`
	MemoryKiB  uint32 `json:"memory_kib"`
	Threads    uint8  `json:"threads"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	PublicKey  string `json:"public_key"`
}

func deriveAEAD(passphrase, salt []byte, time, memory uint32, threads uint8) (cipher.AEAD, error) {
	block, e := aes.NewCipher(argon2.IDKey(passphrase, salt, time, memory, threads, 32))
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}

func sealKey(priv ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	if utf8.RuneCount(passphrase) < minPassphrase {
		return nil, errKey
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	k := sealedKey{Format: 1, KDF: "argon2id", Time: 3, MemoryKiB: 64 * 1024, Threads: 4, Salt: base64.StdEncoding.EncodeToString(salt), PublicKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey))}
	aead, e := deriveAEAD(passphrase, salt, k.Time, k.MemoryKiB, k.Threads)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	k.Nonce = base64.StdEncoding.EncodeToString(nonce)
	k.Ciphertext = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, priv.Seed(), []byte(keyAAD+k.PublicKey)))
	return json.MarshalIndent(k, "", "  ")
}

func openKey(raw, passphrase []byte) (ed25519.PrivateKey, error) {
	var k sealedKey
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if len(raw) > 4096 || d.Decode(&k) != nil || k.Format != 1 || k.KDF != "argon2id" || k.Time < 1 || k.Time > 10 || k.MemoryKiB < 8*1024 || k.MemoryKiB > 1024*1024 || k.Threads < 1 || k.Threads > 16 {
		return nil, errKey
	}
	salt, e1 := base64.StdEncoding.DecodeString(k.Salt)
	nonce, e2 := base64.StdEncoding.DecodeString(k.Nonce)
	sealed, e3 := base64.StdEncoding.DecodeString(k.Ciphertext)
	public, e4 := hex.DecodeString(k.PublicKey)
	if errors.Join(e1, e2, e3, e4) != nil || len(salt) < 16 || len(public) != ed25519.PublicKeySize {
		return nil, errKey
	}
	aead, e := deriveAEAD(passphrase, salt, k.Time, k.MemoryKiB, k.Threads)
	if e != nil || len(nonce) != aead.NonceSize() {
		return nil, errKey
	}
	seed, e := aead.Open(nil, nonce, sealed, []byte(keyAAD+k.PublicKey))
	if e != nil || len(seed) != ed25519.SeedSize {
		return nil, errKey
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(public)) {
		return nil, errKey
	}
	return priv, nil
}

// readPassphrase takes one line from r (the release script pipes it in after a
// no-echo prompt). It is never echoed, logged or written anywhere.
func readPassphrase(r io.Reader) ([]byte, error) {
	line, e := bufio.NewReaderSize(io.LimitReader(r, 1025), 1025).ReadString('\n')
	if e != nil && !errors.Is(e, io.EOF) || len(line) > 1024 {
		return nil, errKey
	}
	p := []byte(strings.TrimRight(line, "\r\n"))
	if len(p) == 0 || !utf8.Valid(p) {
		return nil, errKey
	}
	return p, nil
}

type sequenceCounter struct {
	Format int   `json:"format"`
	Last   int64 `json:"last_sequence"`
}

// nextSequence consumes the next release sequence from the counter stored with
// the key, before anything is signed, so a sequence is never reused for
// different bytes even if signing is interrupted. An explicit sequence must be
// higher than the last one consumed.
// lastSequence reads the counter without changing it.
func lastSequence(dir string) (int64, error) {
	raw, e := os.ReadFile(filepath.Join(dir, counterFile))
	if e != nil {
		return 0, errKey
	}
	var c sequenceCounter
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if len(raw) > 256 || d.Decode(&c) != nil || c.Format != 1 || c.Last < 0 {
		return 0, errKey
	}
	return c.Last, nil
}

func nextSequence(dir string, explicit int64) (int64, error) {
	path := filepath.Join(dir, counterFile)
	raw, e := os.ReadFile(path)
	if e != nil {
		return 0, errKey
	}
	var c sequenceCounter
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if len(raw) > 256 || d.Decode(&c) != nil || c.Format != 1 || c.Last < 0 {
		return 0, errKey
	}
	next := c.Last + 1
	if explicit != 0 {
		if explicit <= c.Last {
			return 0, errKey
		}
		next = explicit
	}
	return next, writeCounter(path, next, false)
}

func writeCounter(path string, last int64, create bool) error {
	data, _ := json.Marshal(sequenceCounter{Format: 1, Last: last})
	if create {
		return writeNew(path, data)
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if e := writeNew(tmp, data); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}

// writeNew creates a file exclusively and syncs it before returning.
func writeNew(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	return e
}
