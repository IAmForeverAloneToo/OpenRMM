package deviceidentity

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/url"
	"testing"
	"time"
)

func TestIssuerIgnoresCSRIdentityAndPrivileges(t *testing.T) {
	now := time.Now()
	issuer, err := NewAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	claimed, _ := url.Parse("urn:openrmm:device:ffffffffffffffffffffffffffffffff")
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "administrator"}, DNSNames: []string{"arbitrary.example"}, URIs: []*url.URL{claimed}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef0123456789abcdef"
	issued, err := issuer.Issue(id, csr, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(issued)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := DeviceID(cert)
	if err != nil || actual != id || cert.Subject.CommonName != id || len(cert.DNSNames) != 0 || cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("issuer honored untrusted CSR identity or privileges")
	}
	if len(cert.AuthorityKeyId) == 0 {
		t.Fatal("missing issuer linkage")
	}
	if _, err := ParseCSR("invalid request"); err == nil {
		t.Fatal("invalid CSR accepted")
	}
}
