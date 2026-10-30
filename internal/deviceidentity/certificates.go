// Package deviceidentity uses standard-library X.509 and ECDSA implementations.
package deviceidentity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func Fingerprint(raw []byte) string      { value := sha256.Sum256(raw); return hex.EncodeToString(value[:]) }
func NewKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
func KeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("cannot encode private key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}
func ParseKey(value []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(value)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("invalid private key")
	}
	return key, nil
}
func ParseCertificate(value string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
func CertificatePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func serial() (*big.Int, error) {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.New("cannot create certificate serial")
	}
	return value.Add(value, big.NewInt(1)), nil
}
func CSR(key crypto.Signer) (string, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", errors.New("cannot create device certificate request")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
func ParseCSR(value string) (*x509.CertificateRequest, error) {
	if len(value) > 4096 {
		return nil, errors.New("invalid certificate request")
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("invalid certificate request signature")
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("device request requires an ECDSA P-256 key")
	}
	return csr, nil
}
func DeviceID(cert *x509.Certificate) (string, error) {
	if cert == nil || cert.IsCA || len(cert.URIs) != 1 {
		return "", errors.New("invalid device certificate identity")
	}
	uri := cert.URIs[0].String()
	id := strings.TrimPrefix(uri, "urn:openrmm:device:")
	if uri != "urn:openrmm:device:"+id || !protocol.ValidID(id) {
		return "", errors.New("invalid device certificate identity")
	}
	return id, nil
}

type Authority struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
}

func NewAuthority(now time.Time) (*Authority, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	identifier, err := serial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: identifier, Subject: pkix.Name{CommonName: "OpenRMM device identity CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, errors.New("cannot create device identity CA")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{Certificate: cert, Key: key}, nil
}
func (a *Authority) Issue(id string, csr *x509.CertificateRequest, now time.Time, lifetime time.Duration) (string, error) {
	if !protocol.ValidID(id) || lifetime <= 0 || !now.Before(a.Certificate.NotAfter) {
		return "", errors.New("device certificate issuance is unavailable")
	}
	identifier, err := serial()
	if err != nil {
		return "", err
	}
	uri, _ := url.Parse("urn:openrmm:device:" + id)
	expires := now.Add(lifetime)
	if expires.After(a.Certificate.NotAfter) {
		expires = a.Certificate.NotAfter
	}
	template := &x509.Certificate{SerialNumber: identifier, Subject: pkix.Name{CommonName: id}, NotBefore: now.Add(-time.Minute), NotAfter: expires, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	// Deliberately ignore all CSR subject, SAN, extension, and privilege requests.
	der, err := x509.CreateCertificate(rand.Reader, template, a.Certificate, csr.PublicKey, a.Key)
	if err != nil {
		return "", errors.New("cannot issue device certificate")
	}
	return CertificatePEM(der), nil
}
