// Package acmecert obtains and renews the dashboard's HTTPS certificate from
// an ACME certificate authority such as Let's Encrypt. It answers the
// TLS-ALPN-01 challenge on the dashboard listener itself (port 443; port 80
// stays closed), keeps the account key, certificate and key
// in a cache folder in the data volume, and renews 30 days before expiry.
//
// It is a small manager on golang.org/x/crypto/acme rather than autocert,
// which would add golang.org/x/net and x/text.
package acmecert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// LetsEncrypt is the production directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// ALPN is the protocol of TLS-ALPN-01 challenge connections.
const ALPN = acme.ALPNProto

// renewBefore: a certificate is renewed when less than this is left.
const renewBefore = 30 * 24 * time.Hour

var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidDomain accepts a lower-case DNS name with at least one dot (no
// wildcard, no IP address).
func ValidDomain(d string) bool { return len(d) <= 253 && domainPattern.MatchString(d) }

// Manager obtains and serves the certificate for one domain.
type Manager struct {
	Domain    string
	Email     string
	Directory string
	// Cache is a private folder (created if missing).
	Cache string
	// Client is used instead of a new one (tests); HTTP settings come from
	// the default client otherwise.
	Client *acme.Client
	Now    func() time.Time

	mu         sync.Mutex
	cert       *tls.Certificate
	challenges map[string]*tls.Certificate
	status     Status
}

// Status is shown to the owner.
type Status struct {
	Domain    string `json:"domain"`
	NotAfter  int64  `json:"not_after,omitempty"`
	LastError string `json:"last_error,omitempty"`
	LastTry   int64  `json:"last_try,omitempty"`
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Status reports the certificate and the last error.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Domain = m.Domain
	if m.cert != nil && m.cert.Leaf != nil {
		s.NotAfter = m.cert.Leaf.NotAfter.Unix()
	}
	return s
}

// GetCertificate serves challenge certificates to ACME validation
// connections and the current certificate to everyone else.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == ALPN {
		if c := m.challenges[name]; c != nil {
			return c, nil
		}
		return nil, errors.New("no ACME challenge for this name")
	}
	if m.cert == nil {
		return nil, errors.New("the HTTPS certificate is not available yet")
	}
	return m.cert, nil
}

// TLSConfig is the dashboard listener's configuration: TLS 1.3, except that
// ACME validation connections may use TLS 1.2.
func (m *Manager) TLSConfig() *tls.Config {
	normal := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: m.GetCertificate}
	challenge := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.GetCertificate, NextProtos: []string{ALPN}}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{ALPN},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == ALPN {
				return challenge, nil
			}
			return normal, nil
		},
	}
}

func readPEM(path, kind string) (*pem.Block, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != kind {
		return nil, fmt.Errorf("%s is not a %s", filepath.Base(path), kind)
	}
	return b, nil
}

func writePEM(path string, blocks ...*pem.Block) error {
	var out []byte
	for _, b := range blocks {
		out = append(out, pem.EncodeToMemory(b)...)
	}
	tmp := path + ".tmp"
	if e := os.WriteFile(tmp, out, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}

// accountKey loads the account key or creates one.
func (m *Manager) accountKey() (crypto.Signer, error) {
	path := filepath.Join(m.Cache, "account-key.pem")
	if b, e := readPEM(path, "EC PRIVATE KEY"); e == nil {
		return x509.ParseECPrivateKey(b.Bytes)
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	der, _ := x509.MarshalECPrivateKey(key)
	return key, writePEM(path, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// loadCached reads a cached certificate for the domain.
func (m *Manager) loadCached() *tls.Certificate {
	c, e := tls.LoadX509KeyPair(filepath.Join(m.Cache, "certificate.pem"), filepath.Join(m.Cache, "key.pem"))
	if e != nil || c.Leaf == nil || c.Leaf.VerifyHostname(m.Domain) != nil {
		return nil
	}
	return &c
}

// due reports whether the certificate needs obtaining or renewing.
func (m *Manager) due() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cert == nil || m.cert.Leaf == nil || m.now().Add(renewBefore).After(m.cert.Leaf.NotAfter)
}

// Run keeps the certificate current until ctx ends: it loads a cached one,
// obtains or renews when due (retrying failures with growing pauses, as the
// CA limits failed attempts), and checks again twice a day.
func (m *Manager) Run(ctx context.Context, logf func(string, ...any)) {
	if e := os.MkdirAll(m.Cache, 0700); e != nil {
		m.fail(e)
		logf("the ACME cache folder cannot be created", "error", e.Error())
		return
	}
	if c := m.loadCached(); c != nil {
		m.mu.Lock()
		m.cert = c
		m.mu.Unlock()
	}
	retry := time.Minute
	for ctx.Err() == nil {
		wait := 12 * time.Hour
		if m.due() {
			if e := m.Obtain(ctx); e != nil {
				logf("the HTTPS certificate could not be obtained; retrying", "domain", m.Domain, "error", e.Error(), "retry_in", retry.String())
				wait, retry = retry, min(retry*4, 6*time.Hour)
			} else {
				logf("HTTPS certificate obtained", "domain", m.Domain, "not_after", m.Status().NotAfter)
				retry = time.Minute
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func (m *Manager) fail(e error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.LastError, m.status.LastTry = e.Error(), m.now().Unix()
}

// Obtain gets a new certificate for the domain now.
func (m *Manager) Obtain(ctx context.Context) error {
	e := m.obtain(ctx)
	if e != nil {
		m.fail(e)
		return e
	}
	m.mu.Lock()
	m.status.LastError, m.status.LastTry = "", m.now().Unix()
	m.mu.Unlock()
	return nil
}

func (m *Manager) obtain(ctx context.Context) error {
	if !ValidDomain(m.Domain) {
		return errors.New("invalid domain name")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	client := m.Client
	if client == nil {
		key, e := m.accountKey()
		if e != nil {
			return fmt.Errorf("account key: %w", e)
		}
		dir := m.Directory
		if dir == "" {
			dir = LetsEncrypt
		}
		client = &acme.Client{Key: key, DirectoryURL: dir, UserAgent: "openrmm"}
	}
	account := &acme.Account{}
	if m.Email != "" {
		account.Contact = []string{"mailto:" + m.Email}
	}
	if _, e := client.Register(ctx, account, acme.AcceptTOS); e != nil && !errors.Is(e, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("register: %w", e)
	}
	order, e := client.AuthorizeOrder(ctx, acme.DomainIDs(m.Domain))
	if e != nil {
		return fmt.Errorf("order: %w", e)
	}
	defer func() {
		m.mu.Lock()
		delete(m.challenges, m.Domain)
		m.mu.Unlock()
	}()
	for _, u := range order.AuthzURLs {
		z, e := client.GetAuthorization(ctx, u)
		if e != nil {
			return fmt.Errorf("authorization: %w", e)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "tls-alpn-01" {
				chal = c
			}
		}
		if chal == nil {
			return errors.New("the CA offers no tls-alpn-01 challenge")
		}
		cert, e := client.TLSALPN01ChallengeCert(chal.Token, m.Domain)
		if e != nil {
			return fmt.Errorf("challenge certificate: %w", e)
		}
		m.mu.Lock()
		if m.challenges == nil {
			m.challenges = map[string]*tls.Certificate{}
		}
		m.challenges[m.Domain] = &cert
		m.mu.Unlock()
		if _, e = client.Accept(ctx, chal); e != nil {
			return fmt.Errorf("accept challenge: %w", e)
		}
		if _, e = client.WaitAuthorization(ctx, z.URI); e != nil {
			return fmt.Errorf("validation (is port 443 of %s reachable from the internet?): %w", m.Domain, e)
		}
	}
	if order, e = client.WaitOrder(ctx, order.URI); e != nil {
		return fmt.Errorf("order: %w", e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: m.Domain}, DNSNames: []string{m.Domain}}, key)
	if e != nil {
		return e
	}
	chain, _, e := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if e != nil {
		return fmt.Errorf("certificate: %w", e)
	}
	if len(chain) == 0 {
		return errors.New("the CA returned no certificate")
	}
	leaf, e := x509.ParseCertificate(chain[0])
	if e != nil || leaf.VerifyHostname(m.Domain) != nil || !leaf.NotAfter.After(m.now()) {
		return errors.New("the CA returned a certificate for another name or already expired")
	}
	blocks := make([]*pem.Block, 0, len(chain))
	for _, der := range chain {
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if e = writePEM(filepath.Join(m.Cache, "key.pem"), &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); e != nil {
		return e
	}
	if e = writePEM(filepath.Join(m.Cache, "certificate.pem"), blocks...); e != nil {
		return e
	}
	m.mu.Lock()
	m.cert = &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}
	m.mu.Unlock()
	return nil
}
