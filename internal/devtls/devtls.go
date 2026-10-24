// Package devtls creates disposable, local-only development certificates.
// It does not install trust or provide the future enrollment certificate authority.
package devtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
)

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// Generate refuses to reuse an existing output directory. The CA private key is
// discarded: these certificates support local HTTPS, not agent enrollment.
func Generate(output string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.New("cannot generate development CA key")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.New("cannot generate development server key")
	}
	caSerial, err := serial()
	if err != nil {
		return errors.New("cannot generate development CA serial")
	}
	serverSerial, err := serial()
	if err != nil {
		return errors.New("cannot generate development server serial")
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: caSerial,
		Subject:      pkix.Name{CommonName: "OpenRMM local development CA"},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: 0, MaxPathLenZero: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return errors.New("cannot create development CA certificate")
	}
	// Parse the generated certificate so the leaf inherits the CA's generated
	// subject key identifier as its authority key identifier. Strict RFC 5280
	// clients require that linkage; the original template has no generated ID.
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		return errors.New("cannot read generated development CA certificate")
	}
	leaf := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "OpenRMM local development server"},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(7 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return errors.New("cannot create development server certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return errors.New("cannot encode development private key")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return errors.New("cannot create development certificate parent directory")
	}
	if err := privatefs.CreateDirectory(output); err != nil {
		return errors.New("cannot create certificate directory; choose a new path because existing directories are never overwritten")
	}
	files := []struct {
		name string
		kind string
		data []byte
		mode os.FileMode
	}{
		{"ca.pem", "CERTIFICATE", caDER, 0644},
		{"server.pem", "CERTIFICATE", leafDER, 0644},
		{"server-key.pem", "PRIVATE KEY", keyDER, 0600},
	}
	created := make([]string, 0, len(files))
	for _, item := range files {
		path := filepath.Join(output, item.name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, item.mode)
		if err == nil {
			created = append(created, path)
			err = pem.Encode(file, &pem.Block{Type: item.kind, Bytes: item.data})
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			for _, createdPath := range created {
				_ = os.Remove(createdPath)
			}
			_ = os.Remove(output)
			return errors.New("cannot write development certificates")
		}
	}
	return nil
}
