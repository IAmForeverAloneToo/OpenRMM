// Package lancert gives a server without a public domain name its HTTPS
// certificate (LAN and lab installs): the server keeps its own
// certificate authority (10 years, in the secrets volume), issues the
// server certificate for the given host names and addresses, and renews it
// automatically. Agent installers carry the CA, so agents keep trusting the
// server across renewals.
package lancert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
)

const (
	caLife      = 10 * 365 * 24 * time.Hour
	serverLife  = 180 * 24 * time.Hour
	renewBefore = 30 * 24 * time.Hour
)

var dnsName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ValidHost accepts a lower-case DNS name or an IP address.
func ValidHost(h string) bool {
	if a, e := netip.ParseAddr(h); e == nil {
		return a.Zone() == "" && !a.IsUnspecified()
	}
	return len(h) <= 253 && dnsName.MatchString(h)
}

// Manager keeps the CA and the server certificate in Dir.
type Manager struct {
	Dir   string
	Hosts []string
	Now   func() time.Time

	mu   sync.Mutex
	cert *tls.Certificate
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// CAFile is the CA certificate agents trust.
func (m *Manager) CAFile() string { return filepath.Join(m.Dir, "ca.pem") }

// GetCertificate serves the current server certificate.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cert == nil {
		return nil, errors.New("the server certificate is not available")
	}
	return m.cert, nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func writePEM(path, kind string, der []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if e := os.WriteFile(tmp, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), mode); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}

func readPEM(path, kind string) ([]byte, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != kind {
		return nil, fmt.Errorf("%s is not a %s", filepath.Base(path), kind)
	}
	return b.Bytes, nil
}

// authority loads the CA or, when there is no CA certificate, creates it. A
// CA certificate without its key is an error: replacing it would break every
// enrolled agent. A key without a certificate (a crash while creating the
// CA) was never handed to agents and is replaced.
func (m *Manager) authority() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath, keyPath := m.CAFile(), filepath.Join(m.Dir, "ca-key.pem")
	certDER, e1 := readPEM(certPath, "CERTIFICATE")
	keyDER, e2 := readPEM(keyPath, "EC PRIVATE KEY")
	if e1 == nil && e2 == nil {
		cert, e := x509.ParseCertificate(certDER)
		if e != nil {
			return nil, nil, e
		}
		key, e := x509.ParseECPrivateKey(keyDER)
		if e != nil {
			return nil, nil, e
		}
		return cert, key, nil
	}
	if !errors.Is(e1, os.ErrNotExist) {
		return nil, nil, errors.New("the server CA is incomplete; restore ca.pem and ca-key.pem from a backup (agents trust this CA)")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	sn, e := serial()
	if e != nil {
		return nil, nil, e
	}
	now := m.now()
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "OpenRMM server CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(caLife),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		return nil, nil, e
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	if e = writePEM(keyPath, "EC PRIVATE KEY", kder, 0600); e != nil {
		return nil, nil, e
	}
	if e = writePEM(certPath, "CERTIFICATE", der, 0644); e != nil {
		return nil, nil, e
	}
	cert, e := x509.ParseCertificate(der)
	return cert, key, e
}

// covers reports whether a certificate names exactly the configured hosts.
func (m *Manager) covers(c *x509.Certificate) bool {
	var have []string
	have = append(have, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		have = append(have, ip.String())
	}
	want := slices.Clone(m.Hosts)
	slices.Sort(have)
	slices.Sort(want)
	return slices.Equal(have, want)
}

// Ensure loads the server certificate, issuing a new one when it is missing,
// due for renewal, or for other hosts.
func (m *Manager) Ensure() error {
	if len(m.Hosts) == 0 {
		return errors.New("no host names or addresses for the server certificate")
	}
	for _, h := range m.Hosts {
		if !ValidHost(h) {
			return fmt.Errorf("invalid host %q", h)
		}
	}
	if e := os.MkdirAll(filepath.Dir(m.Dir), 0700); e != nil {
		return e
	}
	// The CA key is private to the server.
	if e := privatefs.CreateDirectory(m.Dir); e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	certPath, keyPath := filepath.Join(m.Dir, "server.pem"), filepath.Join(m.Dir, "server-key.pem")
	if c, e := tls.LoadX509KeyPair(certPath, keyPath); e == nil && c.Leaf != nil && m.covers(c.Leaf) && m.now().Add(renewBefore).Before(c.Leaf.NotAfter) {
		ca, _, e := m.authority()
		if e == nil && c.Leaf.CheckSignatureFrom(ca) == nil {
			c.Certificate = append(c.Certificate, ca.Raw)
			m.mu.Lock()
			m.cert = &c
			m.mu.Unlock()
			return nil
		}
	}
	ca, caKey, e := m.authority()
	if e != nil {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	sn, e := serial()
	if e != nil {
		return e
	}
	now := m.now()
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "OpenRMM server"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(serverLife),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range m.Hosts {
		if a, e := netip.ParseAddr(h); e == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(a.AsSlice()))
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if e != nil {
		return e
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	if e = writePEM(keyPath, "EC PRIVATE KEY", kder, 0600); e != nil {
		return e
	}
	if e = writePEM(certPath, "CERTIFICATE", der, 0644); e != nil {
		return e
	}
	leaf, _ := x509.ParseCertificate(der)
	m.mu.Lock()
	m.cert = &tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: leaf}
	m.mu.Unlock()
	return nil
}

// Run renews the server certificate when due, checking once a day.
func (m *Manager) Run(ctx context.Context, logf func(string, ...any)) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if e := m.Ensure(); e != nil {
				logf("the server certificate could not be renewed", "error", e.Error())
			}
		}
	}
}

// ParseHosts splits a comma-separated list of host names and addresses;
// addresses are written in canonical form, as certificates report them.
func ParseHosts(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		h = Canonical(h)
		if h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// Canonical lower-cases a host name and writes an IP address canonically.
func Canonical(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if a, e := netip.ParseAddr(h); e == nil {
		return a.Unmap().String()
	}
	return h
}
