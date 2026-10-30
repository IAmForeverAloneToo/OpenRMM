package devicekey

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func roundTrip(t *testing.T, k Key) {
	t.Helper()
	if err := check(k); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(k.Ref())
	if err != nil {
		t.Fatal(err)
	}
	if !opened.Public().(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Fatal("reopened key differs")
	}
	// The key works for X.509 requests and TLS (crypto.Signer).
	if _, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, opened); err != nil {
		t.Fatal(err)
	}
}

func TestSoftwareKey(t *testing.T) {
	k, err := New(false)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, k)
	r := k.Ref()
	if r.Kind == "dpapi" {
		der, _ := x509.MarshalPKCS8PrivateKey(k.(softwareKey).PrivateKey)
		if strings.Contains(r.Blob, base64.StdEncoding.EncodeToString(der)[:40]) {
			t.Fatal("protected key stored in plain form")
		}
	}
	for _, bad := range []Ref{{Kind: "tpm", Name: "other"}, {Kind: r.Kind, Blob: "!"}, {Kind: r.Kind, Blob: base64.StdEncoding.EncodeToString([]byte("junk"))}, {Kind: "unknown"}} {
		if _, err := Open(bad); err == nil {
			t.Error("opened", bad)
		}
	}
}

// The TPM test creates and deletes a key in the current account's TPM key
// store, so it runs only when asked: OPENRMM_TEST_TPM=1.
func TestTPMKey(t *testing.T) {
	if os.Getenv("OPENRMM_TEST_TPM") != "1" {
		t.Skip("set OPENRMM_TEST_TPM=1 to test with this machine's TPM")
	}
	k, err := newTPM()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Delete()
	if k.Ref().Kind != "tpm" {
		t.Fatal("not a TPM key")
	}
	roundTrip(t, k)
	name := k.Ref()
	if err := k.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(name); err == nil {
		t.Fatal("deleted key still opens")
	}
}
