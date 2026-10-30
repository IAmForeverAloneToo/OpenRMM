// Package devicekey keeps an agent's device private key: in the TPM where
// the machine has one (it cannot be copied off the machine), otherwise as a
// software key encrypted with DPAPI for the SYSTEM account. Outside Windows
// (development and tests) a software key is kept in plain form.
package devicekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// Ref is what the agent's state file records about its key.
type Ref struct {
	// Kind is "tpm", "dpapi" or (outside Windows) "plain".
	Kind string `json:"kind"`
	// Name is a TPM key's name in the Platform Crypto Provider.
	Name string `json:"name,omitempty"`
	// Blob is the PKCS #8 key, encrypted with DPAPI for "dpapi".
	Blob string `json:"blob,omitempty"`
}

// Key is a device key. Its signatures are ASN.1 ECDSA P-256, as TLS and
// X.509 expect from a crypto.Signer.
type Key interface {
	crypto.Signer
	Ref() Ref
	// Delete removes a TPM key from the machine; other kinds live only in
	// the state file.
	Delete() error
}

const purpose = "device-key:v1"

// New creates a key, in the TPM when tpm is set and one is usable.
func New(tpm bool) (Key, error) {
	if tpm {
		if k, err := newTPM(); err == nil {
			return k, nil
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("cannot generate device key")
	}
	return Protect(k)
}

// Protect keeps an existing software key protected (a key moved from an
// older, unprotected state file).
func Protect(k *ecdsa.PrivateKey) (Key, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, errors.New("cannot encode device key")
	}
	kind, blob, err := seal(der)
	if err != nil {
		return nil, err
	}
	return softwareKey{k, Ref{Kind: kind, Blob: base64.StdEncoding.EncodeToString(blob)}}, nil
}

// Unprotected wraps a key read from an older state file that kept it in
// plain form; it is never saved as a Ref.
func Unprotected(k *ecdsa.PrivateKey) Key { return softwareKey{k, Ref{Kind: "plain"}} }

// Same reports whether two refs name the same key.
func Same(a, b Ref) bool { return a.Kind == b.Kind && a.Name == b.Name && a.Blob == b.Blob }

// Open loads the key a state file refers to.
func Open(r Ref) (Key, error) {
	switch r.Kind {
	case "tpm":
		return openTPM(r.Name)
	case "dpapi", "plain":
		blob, err := base64.StdEncoding.DecodeString(r.Blob)
		if err != nil {
			return nil, errors.New("invalid saved device key")
		}
		der, err := unseal(r.Kind, blob)
		if err != nil {
			return nil, err
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		k, ok := parsed.(*ecdsa.PrivateKey)
		if err != nil || !ok || k.Curve != elliptic.P256() {
			return nil, errors.New("invalid saved device key")
		}
		return softwareKey{k, r}, nil
	}
	return nil, errors.New("unknown saved device key kind")
}

type softwareKey struct {
	*ecdsa.PrivateKey
	ref Ref
}

func (k softwareKey) Ref() Ref      { return k.ref }
func (k softwareKey) Delete() error { return nil }

// check signs and verifies once, so a key that misbehaves is never used.
func check(k crypto.Signer) error {
	digest := sha256.Sum256([]byte("openrmm device key check"))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if err != nil || !ok || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("device key self-check failed")
	}
	return nil
}
