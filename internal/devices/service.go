// Package devices owns enrollment, certificate identity, and credential lifecycle.
package devices

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/terminal"
)

var ErrLimited = errors.New("too many enrollment attempts")

type attempt struct {
	count int
	until time.Time
}
type Service struct {
	Desktop  *desktop.Hub
	Terminal *terminal.Hub
	store    *storage.Store
	issuer   *deviceidentity.Authority
	now      func() time.Time
	lifetime time.Duration
	mu       sync.Mutex
	attempts map[string]attempt
	reports  map[string]reportBudget // feature reports per device (reportAllowed)
	// Immutable after startup; zero uses the 120-second default.
	OfflineAfter time.Duration
	// Immutable after startup: the PEM file of the CA that
	// issued the server's TLS certificate, written into downloaded installers
	// (empty: agents use the operating system's trusted roots), and the port
	// of the device listener, used to suggest the device address.
	InstallerCA string
	DevicePort  int
}

func New(ctx context.Context, store *storage.Store, path string) (*Service, error) {
	bound, err := store.DeviceAuthority(ctx)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	var contents []byte
	if errors.Is(err, os.ErrNotExist) && bound == "" {
		issuer, err := deviceidentity.NewAuthority(time.Now())
		if err != nil {
			return nil, errors.New("cannot generate device authority")
		}
		key, err := deviceidentity.KeyPEM(issuer.Key)
		if err != nil {
			return nil, err
		}
		contents = append([]byte(deviceidentity.CertificatePEM(issuer.Certificate.Raw)), key...)
		directory := filepath.Dir(path)
		if err := os.MkdirAll(filepath.Dir(directory), 0700); err != nil {
			return nil, errors.New("cannot create device authority parent")
		}
		if err := privatefs.CreateDirectory(directory); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errors.New("cannot create private device authority directory")
		}
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, errors.New("cannot exclusively create device authority; retry startup")
		}
		_, writeErr := out.Write(contents)
		syncErr := out.Sync()
		closeErr := out.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			_ = os.Remove(path)
			return nil, errors.New("cannot persist device authority")
		}
	} else if err != nil {
		return nil, errors.New("device authority is missing or unreadable; restore the matching separate CA backup")
	} else {
		contents, err = io.ReadAll(io.LimitReader(file, 32769))
		_ = file.Close()
		if err != nil || len(contents) > 32768 {
			return nil, errors.New("cannot read device authority")
		}
	}
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid device authority backup")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid device authority certificate")
	}
	key, err := deviceidentity.ParseKey(rest)
	if err != nil {
		return nil, errors.New("invalid device authority key")
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil || !time.Now().Before(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
		return nil, errors.New("device authority key/certificate mismatch or expired CA")
	}
	if err := store.BindDeviceAuthority(ctx, deviceidentity.Fingerprint(cert.Raw)); err != nil {
		return nil, err
	}
	return &Service{Terminal: terminal.NewHub(store.CheckTerminalAuthorization, store.AuditDesktop), Desktop: desktop.NewHub(store.CheckDesktopAuthorization, store.AuditDesktop), store: store, issuer: &deviceidentity.Authority{Certificate: cert, Key: key}, now: time.Now, lifetime: 30 * 24 * time.Hour, attempts: make(map[string]attempt)}, nil
}
func (s *Service) Roots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(s.issuer.Certificate)
	return roots
}
func (s *Service) credential(id, cert string) protocol.Credential {
	return protocol.Credential{DeviceID: id, Certificate: cert, DeviceCA: deviceidentity.CertificatePEM(s.issuer.Certificate.Raw)}
}

// SingleTokenLifetime is how long a single-device token stays valid; long
// enough to carry a downloaded installer to the machine.
const SingleTokenLifetime = 24 * time.Hour

// TokenRequest describes a new enrollment token. MaxDevices and
// Lifetime apply to reusable deployment tokens only.
type TokenRequest struct {
	Actor      string
	Label      string
	Reusable   bool
	MaxDevices int
	Lifetime   time.Duration
}

func (s *Service) CreateToken(ctx context.Context, r TokenRequest) (string, storage.EnrollmentToken, error) {
	value, id := make([]byte, 32), make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", storage.EnrollmentToken{}, errors.New("cannot generate enrollment token")
	}
	if _, err := rand.Read(id); err != nil {
		return "", storage.EnrollmentToken{}, errors.New("cannot generate enrollment token")
	}
	token := base64.RawURLEncoding.EncodeToString(value)
	now := s.now()
	t := storage.EnrollmentToken{ID: hex.EncodeToString(id), Label: r.Label, Reusable: r.Reusable, MaxDevices: 1, Actor: r.Actor, CreatedAt: now.Unix(), ExpiresAt: now.Add(SingleTokenLifetime).Unix()}
	if r.Reusable {
		if r.Lifetime < time.Hour || r.Lifetime > 366*24*time.Hour {
			return "", storage.EnrollmentToken{}, storage.ErrEnrollmentToken
		}
		t.MaxDevices, t.ExpiresAt = r.MaxDevices, now.Add(r.Lifetime).Unix()
	}
	if err := s.store.AddEnrollmentToken(ctx, deviceidentity.Fingerprint([]byte(token)), t, now); err != nil {
		return "", storage.EnrollmentToken{}, err
	}
	return token, t, nil
}

// NewToken creates a single-device token.
func (s *Service) NewToken(ctx context.Context) (string, time.Time, error) {
	token, t, err := s.CreateToken(ctx, TokenRequest{Actor: "administrator"})
	return token, time.Unix(t.ExpiresAt, 0), err
}
func (s *Service) allow(peer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, value := range s.attempts {
		if !now.Before(value.until) {
			delete(s.attempts, key)
		}
	}
	// Per client only: a limit across all clients would let anyone block
	// enrollment. Past this many tracked clients attempts are no longer
	// recorded rather than refused.
	if s.attempts["peer:"+peer].count >= 20 {
		return false
	}
	if len(s.attempts) > 4090 {
		return true
	}
	for _, key := range []string{"peer:" + peer} {
		value := s.attempts[key]
		if value.until.IsZero() {
			value.until = now.Add(time.Minute)
		}
		value.count++
		s.attempts[key] = value
	}
	return true
}

// ErrReportsLimited: a device sends feature reports faster than any agent
// does. One device must not be able to overflow the fleet's alert and health
// sample queues, which would reset alert evaluation for every device.
var ErrReportsLimited = errors.New("too many feature reports")

// An agent sends about 12 reports a minute and one of each kind at start;
// a device may burst to reportBurst, then one report a second.
const (
	reportBurst = 30
	reportRate  = time.Second
)

type reportBudget struct {
	tokens float64
	at     time.Time
}

func (s *Service) reportAllowed(device string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.reports == nil {
		s.reports = map[string]reportBudget{}
	}
	if len(s.reports) > 4096 {
		for k, v := range s.reports {
			if now.Sub(v.at) >= reportBurst*reportRate {
				delete(s.reports, k)
			}
		}
	}
	b, ok := s.reports[device]
	if !ok {
		b = reportBudget{tokens: reportBurst, at: now}
	}
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(reportBurst, b.tokens+float64(d)/float64(reportRate))
	}
	b.at = now
	if b.tokens < 1 {
		s.reports[device] = b
		return false
	}
	b.tokens--
	s.reports[device] = b
	return true
}

func (s *Service) Enroll(ctx context.Context, input protocol.Enrollment, peer string) (protocol.Credential, error) {
	if !s.allow(peer) {
		return protocol.Credential{}, ErrLimited
	}
	fail := func() (protocol.Credential, error) {
		if err := s.store.AuditEnrollmentFailure(ctx, s.now()); err != nil {
			return protocol.Credential{}, err
		}
		return protocol.Credential{}, storage.ErrAuthentication
	}
	if len(input.Token) != 43 || !protocol.ValidMetadata(input.Hostname, input.OS, input.Architecture) {
		return fail()
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(input.Token)
	if err != nil || len(decoded) != 32 {
		return fail()
	}
	csr, err := deviceidentity.ParseCSR(input.CSR)
	if err != nil {
		return fail()
	}
	// Sign a certificate only for a usable token; the token is consumed
	// atomically with the enrollment below.
	if usable, err := s.store.EnrollmentTokenUsable(ctx, deviceidentity.Fingerprint([]byte(input.Token)), s.now()); err != nil {
		return protocol.Credential{}, err
	} else if !usable {
		return fail()
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return protocol.Credential{}, errors.New("cannot generate device identity")
	}
	id := hex.EncodeToString(idBytes)
	cert, err := s.issuer.Issue(id, csr, s.now(), s.lifetime)
	if err != nil {
		return protocol.Credential{}, err
	}
	parsed, err := deviceidentity.ParseCertificate(cert)
	if err != nil {
		return protocol.Credential{}, errors.New("cannot read issued device certificate")
	}
	device := storage.Device{ID: id, Hostname: input.Hostname, OS: input.OS, Architecture: input.Architecture, Certificate: cert, Fingerprint: deviceidentity.Fingerprint(parsed.Raw)}
	if err := s.store.EnrollDevice(ctx, deviceidentity.Fingerprint([]byte(input.Token)), device, s.now()); err != nil {
		if errors.Is(err, storage.ErrAuthentication) {
			return fail()
		}
		return protocol.Credential{}, err
	}
	return s.credential(id, cert), nil
}
func (s *Service) Authenticate(ctx context.Context, state *tls.ConnectionState) (storage.Device, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return storage.Device{}, storage.ErrAuthentication
	}
	cert := state.PeerCertificates[0]
	now := s.now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return storage.Device{}, storage.ErrAuthentication
	}
	id, err := deviceidentity.DeviceID(cert)
	if err != nil {
		return storage.Device{}, storage.ErrAuthentication
	}
	return s.store.ActiveDevice(ctx, id, deviceidentity.Fingerprint(cert.Raw), now)
}
func (s *Service) Renew(ctx context.Context, state *tls.ConnectionState, input protocol.Renewal) (protocol.Credential, error) {
	d, err := s.Authenticate(ctx, state)
	if err != nil {
		return protocol.Credential{}, err
	}
	csr, err := deviceidentity.ParseCSR(input.CSR)
	if err != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, state.PeerCertificates[0].RawSubjectPublicKeyInfo) {
		return protocol.Credential{}, storage.ErrAuthentication
	}
	now := s.now()
	presented := state.PeerCertificates[0]
	// Early checks and lost-response retries return the persisted current cert.
	current, err := deviceidentity.ParseCertificate(d.Certificate)
	if err != nil {
		return protocol.Credential{}, errors.New("invalid persisted device certificate")
	}
	if deviceidentity.Fingerprint(presented.Raw) != d.Fingerprint || current.NotAfter.Sub(now) > 7*24*time.Hour {
		return s.credential(d.ID, d.Certificate), nil
	}
	cert, err := s.issuer.Issue(d.ID, csr, now, s.lifetime)
	if err != nil {
		return protocol.Credential{}, err
	}
	parsed, err := deviceidentity.ParseCertificate(cert)
	if err != nil {
		return protocol.Credential{}, err
	}
	stored, err := s.store.RenewDevice(ctx, d.ID, deviceidentity.Fingerprint(presented.Raw), deviceidentity.Fingerprint(parsed.Raw), cert, now)
	if err != nil {
		return protocol.Credential{}, err
	}
	return s.credential(d.ID, stored), nil
}
