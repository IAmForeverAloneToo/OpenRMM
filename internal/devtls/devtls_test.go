package devtls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratedCertificatesAndNoOverwrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "tls")
	if err := Generate(directory); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(directory, "server.pem"), filepath.Join(directory, "server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("missing CA PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA {
		t.Fatalf("invalid CA: %v", err)
	}
	if len(ca.SubjectKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
		t.Fatal("leaf must identify its issuing CA for strict TLS verification")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Fatalf("certificate invalid for %s: %v", name, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "192.168.1.2"}); err == nil {
		t.Fatal("development certificate trusted a LAN address")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost", CurrentTime: time.Now().Add(8 * 24 * time.Hour)}); err == nil {
		t.Fatal("expired server certificate accepted")
	}
	if err := Generate(directory); err == nil {
		t.Fatal("existing credentials overwritten")
	}
	unchanged, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
	if err != nil || string(unchanged) != string(caPEM) {
		t.Fatal("failed regeneration changed existing CA")
	}
}
